#pragma once
// fim_scanner_process.hpp — T13.2b: privilege-separated FIM scanner.
//
// Architecture (per logsoc-privsep-architecture.html):
//   [root parent agent] --2 socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)-->
//        [logsoc child: setuid(logsoc) + setgid(logsoc) + CAP_DAC_READ_SEARCH]
//
// Two channels (Option 1 of T13.2b, see ~/.hermes/tickets/
// T13.2-fim-scanner-privilege-separation.md):
//   - Channel 1 (event): child → parent PUBLISH_EXTERNAL (FimEvents),
//                         parent → child STOP_EVENT.
//   - Channel 2 (command): parent → child POLL_NOW/GET_STATS/STOP_CMD,
//                           child → parent POLL_NOW_OK/STATS_RESP/STOP_CMD_OK.
//
// Why 2 channels: T13.1 (WalWriter) was a single-channel request-replier
// (parent writes request, child writes reply, no concurrency). For T13.2
// the child must publish events continuously AND answer occasional
// commands, so 1 channel races between dispatcher_loop and poll_now.
// 2 channels = 1 writer per direction per channel = no race possible.
//
// Why not move FimCollector too (T13.2c): that would be a 5-6h refactor
// of the eBPF→FimCollector hot path. KISS first: just the FimPoller
// scanner, which is a periodic SHA-256 poller that doesn't touch
// /proc/<pid>/fd/* and so is safe in logsoc.
//
// IPC protocol (5-byte header, same as WalWriterProcess):
//   [1B type][4B LE uint32 length], payload ≤ 4096 bytes
//
// Channel 1 (event) — child → parent:
//   0x83  PUBLISH_EXTERNAL   payload = serialized FimEvent
// Channel 1 — parent → child:
//   0x13  STOP_EVENT         payload = empty (graceful event-channel close)
//
// Channel 2 (command) — parent → child:
//   0x10  POLL_NOW           payload = empty
//   0x11  GET_STATS          payload = empty
//   0x12  STOP_CMD           payload = empty
// Channel 2 — child → parent:
//   0x80  POLL_NOW_OK        payload = uint32 (changes detected)
//   0x81  STATS_RESP         payload = uint64 polls + uint64 changes
//   0x82  STOP_CMD_OK        payload = empty
//   0x8F  ERROR              payload = int32 LE errno
//
// Hardening (lessons from T13.1 — see ~/.hermes/skills/log-soc-ai-fork-ipc):
//   - SOCK_CLOEXEC
//   - SO_RCVTIMEO + SO_SNDTIMEO on parent fds (1s, no contention now)
//   - NOT O_NONBLOCK (Linux UB combined with SO_RCVTIMEO)
//   - MSG_NOSIGNAL on send
//   - getpwnam/getgrnam + setgroups(0) + setgid + setuid (lesson #5)
//   - Most-vexing-parse fix with double-parens in child_entry (lesson #1)
//   - fflush(stderr) in child after every log (lesson #6)
//   - EPIPE catcher in send_frame (lesson #7)
//   - waitpid(WNOHANG) check at start of ensure_child_locked (lesson #4)
//
// Capabilities: the systemd service runs User=root and the parent's
// bounding set includes CAP_DAC_READ_SEARCH (added in T13.2c). The
// child inherits it across fork+setuid. If the service file doesn't
// have it, the child loses it on setuid and watch_paths won't open.

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "agent/fim_collector.hpp"  // FimEvent (full definition, for the queue)

namespace fim_scanner {

// Protocol limits — must match WalWriterProcess conventions.
constexpr uint32_t MSG_HEADER_SIZE  = 5;
constexpr uint32_t MSG_MAX_PAYLOAD  = 4 * 1024;

// Auto-restart cap (defensive — if the child keeps dying, give up).
constexpr int MAX_CHILD_RESTARTS   = 10;

// Inbound event queue (PUBLISH_EXTERNAL frames from the child). Bounded;
// oldest is dropped on overflow (FIFO drop policy, same as FimCollector's
// ship queue).
constexpr size_t INBOUND_QUEUE_CAP = 1024;

struct Config {
    std::string              wal_user         = "logsoc";   // target uid
    std::string              wal_group        = "logsoc";   // target gid
    std::vector<std::string> watch_paths;
    int                      poll_interval_sec = 5;
};

class FimScannerProcess {
public:
    explicit FimScannerProcess(Config cfg);
    ~FimScannerProcess();

    FimScannerProcess(const FimScannerProcess&)            = delete;
    FimScannerProcess& operator=(const FimScannerProcess&) = delete;

    // Fork + setuid child. Idempotent: returns true if a child is already
    // alive. Returns false only on hard failure (socketpair, fork, setuid).
    bool start();

    // Force a poll right now (synchronous, blocks ~200ms worst case).
    // Returns the count of changes detected by the child's last poll.
    // The PUBLISH_EXTERNAL events for those changes arrive asynchronously
    // via pop_event(); this count is just a synchronous "did anything
    // change?" probe for callers that need it (admin trigger, tests).
    int poll_now();

    // Stats (cached from the child's last GET_STATS response).
    uint64_t polls_total()   const { return polls_total_.load(); }
    uint64_t changes_total() const { return changes_total_.load(); }

    // Drain the inbound event queue (called by the shipper thread in
    // agent.cpp, before FimCollector::pop_ship_event). Returns false
    // if the queue is empty.
    bool   pop_event(logsoc::agent::fim::FimEvent& out);
    size_t event_queue_depth() const;

    // Stop the child gracefully. Idempotent. Safe from any thread.
    void stop();

    bool is_alive() const { return child_pid_ > 0; }

private:
    // ----- IPC primitives (parameterized by fd — works for both channels) -----
    bool send_frame(int fd, uint8_t type, const void* payload, uint32_t len);
    bool recv_frame(int fd, uint8_t* out_type, std::vector<uint8_t>& out_payload);
    bool send_simple(int fd, uint8_t type);
    bool send_u32(int fd, uint8_t type, uint32_t v);
    bool send_u64(int fd, uint8_t type, uint64_t v);

    // ----- Fork / setuid plumbing -----
    bool ensure_child_locked();
    static void child_entry(int event_fd, int cmd_fd, Config cfg);
    void        child_main(int event_fd, int cmd_fd, const Config& cfg);

    // ----- Parent dispatcher (reads event channel) -----
    void dispatcher_loop();
    std::thread dispatcher_;

    // ----- LE byte-order helpers (same as WalWriterProcess) -----
    static void   append_u32_le(std::vector<uint8_t>& buf, uint32_t v);
    static void   append_u64_le(std::vector<uint8_t>& buf, uint64_t v);
    static uint32_t read_u32_le(const uint8_t* p);
    static uint64_t read_u64_le(const uint8_t* p);

    // ----- FimEvent wire serialization (used by child to publish events) -----
    static void append_fim_event(std::vector<uint8_t>& buf,
                                 const logsoc::agent::fim::FimEvent& ev);
    static bool read_fim_event(const uint8_t* p, size_t len, size_t* off,
                               logsoc::agent::fim::FimEvent& out);

    Config cfg_;
    mutable std::mutex mu_;             // protects fork state + child pids + fds
    int  parent_event_fd_ = -1;          // parent's read end of event channel
    int  parent_cmd_fd_   = -1;          // parent's read/write end of cmd channel
    pid_t child_pid_      = -1;
    int   restarts_       = 0;
    std::atomic<bool> stop_requested_{false};

    // Cached stats (refreshed by GET_STATS calls).
    std::atomic<uint64_t> polls_total_{0};
    std::atomic<uint64_t> changes_total_{0};

    // Inbound event queue (parent dispatcher_loop writes, shipper thread
    // reads via pop_event).
    std::vector<logsoc::agent::fim::FimEvent> inbound_events_;
    mutable std::mutex inbound_mtx_;
};

}  // namespace fim_scanner
