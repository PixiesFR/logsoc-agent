#pragma once
// wal_writer_process.hpp — T13 (audit Nova 2026-06-16): privilege-separated
// FallbackWAL writer.
//
// Architecture (SCOPE A strict — FallbackWAL only):
//   [root parent agent] --socketpair(AF_UNIX, SOCK_SEQPACKET| SOCK_CLOEXEC)-->
//        [logsoc child: setuid(logsoc) + setgid(logsoc) + noclose 0/1/2]
//
// IPC protocol (SOCK_SEQPACKET = connection-oriented, message-bounded,
// preserves message boundaries; no stream reassembly required):
//   Header (5 bytes):
//     [1B type][4B length LE uint32]
//   Payload:
//     [length bytes, MUST be <= MSG_MAX_PAYLOAD]
//   Auto-truncation by kernel: if a sender writes more than the receiver's
//   buffer, the kernel returns -1 / EMSGSIZE and we treat the message as
//   dropped. Sender MUST validate length <= MSG_MAX_PAYLOAD before send.
//
// Message types (parent -> child):
//   0x01  PUSH          payload = serialized FallbackEvent (raw event bytes)
//   0x02  POP_BATCH     payload = uint32 LE N (max events to drain)
//   0x03  MARK_SENT     payload = uint64 LE event_id_hash
//   0x04  STOP          payload = empty (graceful shutdown)
//   0x05  COUNT         payload = empty (request count of pending events)
//   0x06  DRAIN         payload = empty (returns ALL pending events for buffer drain)
//
// Message types (child -> parent):
//   0x80  PUSH_OK        payload = empty
//   0x81  POP_BATCH_RESP payload = uint32 LE N + N x serialized FallbackEvent
//   0x82  MARK_SENT_OK   payload = empty
//   0x83  COUNT_RESP     payload = uint64 LE count
//   0x84  STOP_OK        payload = empty
//   0x85  DRAIN_RESP     payload = uint32 LE N + N x serialized FallbackEvent
//   0x8F  ERROR          payload = int32 LE errno
//
// Hardening:
//   - SOCK_CLOEXEC: child can't accidentally leak fds via execve (defense in depth).
//   - O_NONBLOCK: parent side non-blocking (backpressure / non-fatal EAGAIN).
//                 child side blocking in the event loop (simpler, owns no fds
//                 besides the socketpair fd and its WAL files).
//   - SO_PASSCRED not used (anonymous socketpair, SO_PEERCRED would be redundant).
//   - 4 KB hard cap on payload (MSG_MAX_PAYLOAD). Anything larger is rejected
//     at the sender (caller is responsible — a typical raw event is 1-2 KB).
//   - Auto-restart: if the child dies (SIGKILL, OOM, assert), the parent
//     re-forks on the next call. Bounded retries to avoid fork-bombing.
//   - Drop-in API: push/pop_batch/mark_sent/count/cleanup_old_segments
//     match FallbackWAL signatures 1:1, so agent.cpp call sites need only
//     a type swap (FallbackWAL& -> WalWriterProcess&).
//
// Out of scope for T13 4.8.1 (deferred):
//   - Migrating other filesystem writes (agent.identity, config.json reload)
//   - Named socket /run/logsoc/agent.sock + SO_PEERCRED (socketpair is
//     sufficient when parent and child are the same process tree)
//   - Heartbeat / network in the child (TLS already encrypts the channel
//     and the parent already runs as root with CAP_BPF)

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "fallback_wal.hpp"

namespace wal_writer {

// Protocol limits. MUST stay below SOCK_SEQPACKET kernel max (typically
// ~256 KB on Linux, but a typical event is <2 KB, so 4 KB is plenty and
// bounds memory under load).
constexpr uint32_t MSG_HEADER_SIZE    = 5;     // 1B type + 4B length
constexpr uint32_t MSG_MAX_PAYLOAD    = 4 * 1024;  // 4 KB hard cap
constexpr uint32_t MSG_MAX_FRAME      = MSG_HEADER_SIZE + MSG_MAX_PAYLOAD;  // 4101 B

// Re-fork policy if the child dies.
constexpr int  MAX_CHILD_RESTARTS    = 10;    // Bounded to avoid fork bomb
constexpr int  CHILD_RESTART_BACKOFF_MS = 200;

// Backpressure (parent send): if the socketpair kernel buffer is full,
// the parent retries up to N times with a small sleep before giving up
// and pushing the event to in-memory overflow (which is the existing
// FallbackWAL behavior we are replacing — degrade gracefully).
constexpr int  PARENT_SEND_RETRIES   = 3;
constexpr int  PARENT_SEND_BACKOFF_US = 1000;  // 1 ms

struct Config {
    std::string wal_user  = "logsoc";  // UID/GID name to drop to
    std::string wal_group = "logsoc";
    std::string data_dir;              // /var/lib/logsoc-agent — child writes here
    std::vector<uint8_t> aes_key;      // 32 B AES-256-GCM (forwarded to child)
    std::string agent_id;              // for filename salt
};

class WalWriterProcess {
public:
    explicit WalWriterProcess(Config cfg);
    ~WalWriterProcess();

    WalWriterProcess(const WalWriterProcess&) = delete;
    WalWriterProcess& operator=(const WalWriterProcess&) = delete;

    // Fork + setuid child. Returns false on hard failure (cannot fork
    // or cannot drop privileges). After start(), the child holds the
    // FallbackWAL and the parent talks to it over the socketpair.
    bool start();

    // --- Drop-in FallbackWAL-compatible API ---------------------------
    bool   push(const std::string& raw_event);
    std::vector<fallback_wal::FallbackEvent> pop_batch(size_t n);
    void   mark_sent(uint64_t event_id_hash);
    size_t count();
    // Cleanup is fire-and-forget; child runs it lazily. We still return
    // synchronously after a round-trip so the call site can log it.
    void   cleanup_old_segments(size_t max_age_sec);
    // Drain is needed for buffer-drain-at-shutdown (see agent.cpp:4922).
    std::vector<fallback_wal::FallbackEvent> drain_all();

    // Polite shutdown. Sends STOP, joins the child thread, waits for
    // the process to exit. Safe to call multiple times. After stop(),
    // push/pop_batch return false / empty and the process is reusable
    // only via start() again.
    void stop();

    // True if the child is alive and we have a valid fd.
    bool is_alive() const { return child_pid_ > 0; }

private:
    // --- IPC primitives (parent side) ---------------------------------
    // send_frame: blocking-with-retries, validates length <= MSG_MAX_PAYLOAD,
    // returns true on success.
    bool send_frame(uint8_t type, const void* payload, uint32_t len);
    // recv_frame: blocking, fills out_type/out_payload, validates length.
    // Returns false on EOF (child dead) or protocol error.
    bool recv_frame(uint8_t* out_type, std::vector<uint8_t>& out_payload);
    // Convenience wrappers.
    bool send_simple(uint8_t type);
    bool send_u32(uint8_t type, uint32_t v);
    bool send_u64(uint8_t type, uint64_t v);

    // --- Re-fork helper (parent side, mutex held by caller) ------------
    bool ensure_child_locked();

    // --- Child entry point (static, forks then runs child_main) --------
    static void child_entry(int fd, Config cfg);
    // --- Child main loop (owns the FallbackWAL) ------------------------
    void child_main(int fd, const Config& cfg);

    // --- Serialization helpers (shared, in cpp) -----------------------
    // Append uint32/uint64 LE to a buffer.
    static void append_u32_le(std::vector<uint8_t>& buf, uint32_t v);
    static void append_u64_le(std::vector<uint8_t>& buf, uint64_t v);
    // Read uint32/uint64 LE from a buffer (assumes enough bytes).
    static uint32_t read_u32_le(const uint8_t* p);
    static uint64_t read_u64_le(const uint8_t* p);

    Config cfg_;
    mutable std::mutex mu_;
    int    parent_fd_ = -1;          // parent end of the socketpair
    pid_t  child_pid_ = -1;          // 0 in the child, > 0 in the parent
    int    restarts_  = 0;           // how many times we've re-forked
    std::atomic<bool> stop_requested_{false};

    // The child owns a FallbackWAL. The parent only ever talks to the
    // child over the socketpair. (No shared state = no locking concerns.)
};

}  // namespace wal_writer
