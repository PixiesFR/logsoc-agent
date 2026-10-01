#pragma once
// action_recommender_process.hpp — T13.3': privilege-separated action
// recommender (escalation pipeline).
//
// Architecture (per logsoc-privsep-architecture.html + T13.3'
// inversion de modèle decided 2026-06-17 by the user):
//
//   [root parent agent] --1 socketpair(AF_UNIX, SOCK_SEQPACKET)-->
//        [logsoc child: setuid(logsoc) + setgid(logsoc) + no caps]
//
// The CHILD is the analyst. It runs pattern matching (severity scoring
// + sigma rules) on incoming events received via IPC. If a critical
// pattern is detected, the child sends a structured **recommendation**
// (NOT a command) back to the parent.
//
// The PARENT is the validator. It receives the recommendation,
// authenticates the peer via the kernel (no userland trust), applies
// 3 safety barriers, and only THEN calls t28::execute() with its own
// root capabilities.
//
// Why inversion: the original diagram put the action executor in a
// child, but action executors need CAP_KILL / CAP_NET_ADMIN /
// CAP_SYS_ADMIN, which defeats privilege separation. With inversion,
// the child is a pure analyst (no caps), and the parent keeps root
// for execution. The child CANNOT trigger an action on its own —
// every recommendation passes through 3 parent-side barriers.
//
// 3 barriers (parent side, ActionValidator):
//   1. Is the triggering rule in the pre-approved rule set signed by
//      the backend? (Rule allowlist, populated at config load from
//      /etc/logsoc-agent/rules_allowlist.json.)
//   2. Is the target PID outside the system exclusion list?
//      (PID 1, kernel threads, the agent's own PID, the parent's PID,
//      any PID in /etc/logsoc-agent/pid_exclusions.)
//   3. Is the action type allowed for this rule? (kill_pid allowed
//      for "yara_critical_binary" but not for "sigma_suspicious_comm".)
//
// If any barrier fails: log + ignore. Never partial-execute.
//
// IPC protocol (1 channel, request-reply pattern like WalWriter —
// see skill log-soc-ai-fork-ipc lesson #8):
//   Header (5 bytes): [1B type][4B LE uint32 length]
//   Payload: [length bytes, max 4 KB]
//
// Types parent → child:
//   0x10  PUSH_EVENT      payload = serialized event JSON (the
//                          parent forwards ship-ready events to the
//                          child for pattern matching)
//   0x11  GET_STATS       payload = empty
//   0x12  STOP            payload = empty (graceful shutdown)
//
// Types child → parent:
//   0x80  ACK             payload = empty (ack to PUSH_EVENT)
//   0x81  RECOMMENDATION  payload = serialized ActionRecommendation
//                          (action_type, target_pid, rule_id, severity)
//   0x82  STATS_RESP      payload = uint64 events_seen + uint64
//                          recommendations_sent
//   0x83  STOP_OK         payload = empty
//   0x8F  ERROR           payload = int32 LE errno
//
// Hardening (lessons from log-soc-ai-fork-ipc skill):
//   - SOCK_CLOEXEC
//   - SO_RCVTIMEO + SO_SNDTIMEO 1s (1 channel, no contention)
//   - NOT O_NONBLOCK (Linux UB with SO_RCVTIMEO)
//   - MSG_NOSIGNAL on send
//   - getpwnam/getgrnam + setgroups(0) + setgid + setuid (lesson #5)
//   - Most-vexing-parse fix with double-parens in child_entry (lesson #1)
//   - fflush(stderr) in child after every log (lesson #6)
//   - EPIPE catcher in send_frame (lesson #7)
//   - waitpid(WNOHANG) check at start of ensure_child_locked (lesson #4)
//   - EAGAIN idle loop handling (lesson #10)

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace action_recommender {

// Protocol limits — must match WalWriterProcess conventions.
constexpr uint32_t MSG_HEADER_SIZE = 5;
constexpr uint32_t MSG_MAX_PAYLOAD = 4 * 1024;

// ActionRecommendation is the structured payload the child sends to
// the parent when pattern matching detects a critical event. The
// parent validates before executing. JSON serialization is done by
// the parent in agent.cpp using nlohmann::json (already a dep).
struct ActionRecommendation {
    std::string action_type;   // "kill_pid" | "block_ip" | "quarantine_file"
    int         target_pid = 0;
    std::string target_path;  // for quarantine_file
    std::string rule_id;      // sigma/yara rule that triggered
    int         severity = 0; // 0..100 (from severity::score)
    std::string reason;       // human-readable explanation
};

struct Config {
    std::string wal_user  = "logsoc";
    std::string wal_group = "logsoc";
    int         severity_threshold = 90;  // only recommend if score >= this
    int         stats_interval_sec  = 30; // for the GET_STATS response
};

class ActionRecommenderProcess {
public:
    explicit ActionRecommenderProcess(Config cfg);
    ~ActionRecommenderProcess();

    ActionRecommenderProcess(const ActionRecommenderProcess&)            = delete;
    ActionRecommenderProcess& operator=(const ActionRecommenderProcess&) = delete;

    // Fork + setuid child. Idempotent.
    bool start();

    // Forward an event to the child for pattern matching. Returns
    // true if the event was queued and acked by the child. Returns
    // false if the child is dead or the IPC failed.
    //
    // The event is a JSON string (the same one that gets shipped to
    // the backend). The child parses it with nlohmann::json, extracts
    // features for severity::score, and runs the sigma matcher.
    bool push_event(const std::string& event_json);

    // Drain the recommendation queue (child → parent). Returns false
    // if empty. The ActionValidator in agent.cpp calls this on a
    // dedicated thread and applies the 3 safety barriers before
    // calling t28::execute().
    bool pop_recommendation(ActionRecommendation& out);
    size_t recommendation_queue_depth() const;

    // Stats (cached from the child's last GET_STATS response).
    uint64_t events_seen()           const { return events_seen_.load(); }
    uint64_t recommendations_sent() const { return recommendations_sent_.load(); }

    void stop();
    bool is_alive() const { return child_pid_ > 0; }

private:
    // ----- IPC primitives (parameterized by fd, like FimScanner) -----
    bool send_frame(int fd, uint8_t type, const void* payload, uint32_t len);
    bool recv_frame(int fd, uint8_t* out_type, std::vector<uint8_t>& out_payload);
    bool send_simple(int fd, uint8_t type);
    bool send_u64(int fd, uint8_t type, uint64_t v);

    // ----- Fork / setuid plumbing -----
    bool ensure_child_locked();
    static void child_entry(int fd, Config cfg);
    void        child_main(int fd, const Config& cfg);

    // ----- LE byte-order helpers -----
    static void     append_u32_le(std::vector<uint8_t>& buf, uint32_t v);
    static void     append_u64_le(std::vector<uint8_t>& buf, uint64_t v);
    static uint32_t read_u32_le(const uint8_t* p);
    static uint64_t read_u64_le(const uint8_t* p);

    // ----- ActionRecommendation wire serialization -----
    static void append_recommendation(std::vector<uint8_t>& buf,
                                       const ActionRecommendation& rec);
    static bool read_recommendation(const uint8_t* p, size_t len, size_t* off,
                                     ActionRecommendation& out);

    Config cfg_;
    mutable std::mutex mu_;
    int  parent_fd_ = -1;
    pid_t child_pid_ = -1;
    int   restarts_  = 0;
    std::atomic<bool> stop_requested_{false};

    // Cached stats (refreshed by GET_STATS).
    std::atomic<uint64_t> events_seen_{0};
    std::atomic<uint64_t> recommendations_sent_{0};

    // Inbound recommendation queue (child → parent). Bounded.
    std::vector<ActionRecommendation> inbound_recs_;
    mutable std::mutex inbound_mtx_;
    static constexpr size_t INBOUND_QUEUE_CAP = 256;
};

}  // namespace action_recommender
