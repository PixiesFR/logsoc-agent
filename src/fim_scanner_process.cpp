// fim_scanner_process.cpp — T13.2b: privilege-separated FIM scanner.
// See fim_scanner_process.hpp for the architecture and protocol.
//
// This implementation copies the IPC scaffolding from
// wal_writer_process.cpp (proven in T13.1) and parameterizes it by fd
// so the same send/recv helpers work for both channels (event + cmd).

#include "fim_scanner_process.hpp"
#include "logsoc_user_cache.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <thread>
#include <iostream>

#include "debug.hpp"
#include "agent/fim_collector.hpp"  // FimEvent full definition
#include "agent/fim_poller.hpp"     // FimPoller + EventCallback ctor (commit e1ce2dd)

namespace fim_scanner {

// =====================================================================
// Construction / destruction
// =====================================================================

FimScannerProcess::FimScannerProcess(Config cfg) : cfg_(std::move(cfg)) {}

FimScannerProcess::~FimScannerProcess() {
    stop();
    if (dispatcher_.joinable()) dispatcher_.join();
}

// =====================================================================
// LE byte-order helpers (identical to WalWriterProcess)
// =====================================================================

void FimScannerProcess::append_u32_le(std::vector<uint8_t>& buf, uint32_t v) {
    size_t n = buf.size();
    buf.resize(n + 4);
    buf[n+0] = static_cast<uint8_t>(v & 0xff);
    buf[n+1] = static_cast<uint8_t>((v >> 8) & 0xff);
    buf[n+2] = static_cast<uint8_t>((v >> 16) & 0xff);
    buf[n+3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void FimScannerProcess::append_u64_le(std::vector<uint8_t>& buf, uint64_t v) {
    size_t n = buf.size();
    buf.resize(n + 8);
    for (int i = 0; i < 8; ++i) {
        buf[n+i] = static_cast<uint8_t>((v >> (8*i)) & 0xff);
    }
}

uint32_t FimScannerProcess::read_u32_le(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t FimScannerProcess::read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8*i);
    }
    return v;
}

// =====================================================================
// FimEvent wire serialization
// =====================================================================
//
// Wire format (little-endian, no padding):
//   [u32 abs_path_len][abs_path bytes]
//   [u32 basename_len][basename bytes]
//   [u32 pid]
//   [u64 ktime_ns]
//   [u32 op_len][op bytes]
//   [u32 mitre_count]
//   [for each: u32 mitre_len + mitre bytes]
//   [u32 resolution_len][resolution bytes]
//   [i64 enqueued_at_ns_since_epoch]
//
// Max ~4 KB for a typical event (path < 256B, basename < 256B, op < 16B,
// mitre array < 256B, resolution < 32B). Verified during T13.2a.

void FimScannerProcess::append_fim_event(std::vector<uint8_t>& buf,
                                          const logsoc::agent::fim::FimEvent& ev) {
    auto put_str = [&](const std::string& s) {
        append_u32_le(buf, static_cast<uint32_t>(s.size()));
        buf.insert(buf.end(), s.begin(), s.end());
    };
    put_str(ev.abs_path);
    put_str(ev.basename);
    append_u32_le(buf, ev.pid);
    append_u64_le(buf, ev.ktime_ns);
    put_str(std::string(ev.operation));
    append_u32_le(buf, static_cast<uint32_t>(ev.mitre.size()));
    for (const auto& m : ev.mitre) put_str(m);
    put_str(ev.resolution);
    int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        ev.enqueued_at.time_since_epoch()).count();
    uint64_t le_ns = 0;
    for (int i = 0; i < 8; ++i) {
        ((uint8_t*)&le_ns)[i] = static_cast<uint8_t>((ns >> (8*i)) & 0xff);
    }
    append_u64_le(buf, le_ns);
}

bool FimScannerProcess::read_fim_event(const uint8_t* p, size_t len, size_t* off,
                                        logsoc::agent::fim::FimEvent& out) {
    auto get_str = [&](std::string& s) -> bool {
        if (*off + 4 > len) return false;
        uint32_t l = read_u32_le(p + *off); *off += 4;
        if (*off + l > len) return false;
        s.assign(reinterpret_cast<const char*>(p + *off), l); *off += l;
        return true;
    };
    if (!get_str(out.abs_path))  return false;
    if (!get_str(out.basename))  return false;
    if (*off + 12 > len) return false;
    out.pid      = read_u32_le(p + *off); *off += 4;
    out.ktime_ns = read_u64_le(p + *off); *off += 8;
    std::string op;
    if (!get_str(op)) return false;
    std::strncpy(out.operation, op.c_str(), sizeof(out.operation) - 1);
    out.operation[sizeof(out.operation) - 1] = '\0';
    if (*off + 4 > len) return false;
    uint32_t mc = read_u32_le(p + *off); *off += 4;
    for (uint32_t i = 0; i < mc; ++i) {
        std::string m;
        if (!get_str(m)) return false;
        out.mitre.push_back(std::move(m));
    }
    if (!get_str(out.resolution)) return false;
    if (*off + 8 > len) return false;
    uint64_t le_ns = read_u64_le(p + *off); *off += 8;
    int64_t ns = 0;
    for (int i = 0; i < 8; ++i) {
        ((uint8_t*)&ns)[i] = static_cast<uint8_t>((le_ns >> (8*i)) & 0xff);
    }
    out.enqueued_at = std::chrono::system_clock::time_point(
        std::chrono::nanoseconds(ns));
    return true;
}

// =====================================================================
// IPC primitives (parameterized by fd — same logic as WalWriterProcess)
// =====================================================================

bool FimScannerProcess::send_frame(int fd, uint8_t type, const void* payload, uint32_t len) {
    if (len > MSG_MAX_PAYLOAD) {
        std::fprintf(stderr, "[fim_scanner] send_frame: payload %u > MSG_MAX_PAYLOAD %u\n",
                     len, MSG_MAX_PAYLOAD);
        return false;
    }
    uint8_t header[MSG_HEADER_SIZE];
    header[0] = type;
    header[1] = static_cast<uint8_t>(len & 0xff);
    header[2] = static_cast<uint8_t>((len >> 8) & 0xff);
    header[3] = static_cast<uint8_t>((len >> 16) & 0xff);
    header[4] = static_cast<uint8_t>((len >> 24) & 0xff);

    ssize_t n = ::send(fd, header, MSG_HEADER_SIZE, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EINTR) return send_frame(fd, type, payload, len);
        if (errno == EPIPE) {
            // Lesson #7: child closed the channel. Caller decides
            // whether to re-fork or give up. Returning false lets
            // poll_now() report 0 and pop_event() report empty.
            return false;
        }
        std::fprintf(stderr, "[fim_scanner] send(header) failed: %s\n",
                     std::strerror(errno));
        return false;
    }
    if (n != MSG_HEADER_SIZE) {
        std::fprintf(stderr, "[fim_scanner] send(header) short write: %zd\n", n);
        return false;
    }
    if (len > 0) {
        ssize_t n2 = ::send(fd, payload, len, MSG_NOSIGNAL);
        if (n2 < 0) {
            if (errno == EINTR) return send_frame(fd, type, payload, len);
            if (errno == EPIPE) return false;
            std::fprintf(stderr, "[fim_scanner] send(payload) failed: %s\n",
                         std::strerror(errno));
            return false;
        }
        if (n2 != static_cast<ssize_t>(len)) {
            std::fprintf(stderr, "[fim_scanner] send(payload) short write: %zd\n", n2);
            return false;
        }
    }
    return true;
}

// Returns true on a complete frame, false on EOF or unrecoverable error.
// Timeout (EAGAIN/EWOULDBLOCK from SO_RCVTIMEO) is treated as **transient**
// and returns false BUT errno is set to EAGAIN so the caller can retry.
// The original behavior (EOF returns false) is preserved; callers that
// want to distinguish can check errno.
bool FimScannerProcess::recv_frame(int fd, uint8_t* out_type, std::vector<uint8_t>& out_payload) {
    uint8_t header[MSG_HEADER_SIZE];
    ssize_t n = ::recv(fd, header, MSG_HEADER_SIZE, 0);
    if (n == 0) return false;  // EOF — peer closed
    if (n < 0) {
        if (errno == EINTR) return recv_frame(fd, out_type, out_payload);
        // EAGAIN/EWOULDBLOCK from SO_RCVTIMEO is expected in idle loops.
        // The caller's loop will retry on the next iteration.
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            errno = EAGAIN;  // normalize
            return false;
        }
        std::fprintf(stderr, "[fim_scanner] recv(header) failed: %s\n",
                     std::strerror(errno));
        return false;
    }
    if (n != MSG_HEADER_SIZE) {
        std::fprintf(stderr, "[fim_scanner] recv(header) short read: %zd\n", n);
        return false;
    }
    *out_type = header[0];
    uint32_t length = read_u32_le(header + 1);
    if (length > MSG_MAX_PAYLOAD) {
        std::fprintf(stderr, "[fim_scanner] recv: length %u > MSG_MAX_PAYLOAD %u\n",
                     length, MSG_MAX_PAYLOAD);
        // Drain the oversized payload to keep the stream sane, then
        // bail. Caller will see false and treat it as a child error.
        std::vector<uint8_t> junk(MSG_MAX_PAYLOAD);
        size_t remaining = length;
        while (remaining > 0) {
            size_t want = remaining > junk.size() ? junk.size() : remaining;
            ssize_t m = ::recv(fd, junk.data(), want, 0);
            if (m <= 0) break;
            remaining -= static_cast<size_t>(m);
        }
        return false;
    }
    out_payload.assign(length, 0);
    if (length > 0) {
        ssize_t n2 = ::recv(fd, out_payload.data(), length, 0);
        if (n2 == 0) return false;
        if (n2 < 0) {
            if (errno == EINTR) return recv_frame(fd, out_type, out_payload);
            std::fprintf(stderr, "[fim_scanner] recv(payload) failed: %s\n",
                         std::strerror(errno));
            return false;
        }
        if (n2 != static_cast<ssize_t>(length)) {
            std::fprintf(stderr, "[fim_scanner] recv(payload) short read: %zd\n", n2);
            return false;
        }
    }
    return true;
}

bool FimScannerProcess::send_simple(int fd, uint8_t type) {
    return send_frame(fd, type, nullptr, 0);
}

bool FimScannerProcess::send_u32(int fd, uint8_t type, uint32_t v) {
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>(v & 0xff);
    buf[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    buf[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    buf[3] = static_cast<uint8_t>((v >> 24) & 0xff);
    return send_frame(fd, type, buf, 4);
}

bool FimScannerProcess::send_u64(int fd, uint8_t type, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>((v >> (8*i)) & 0xff);
    return send_frame(fd, type, buf, 8);
}

// =====================================================================
// Fork / setuid — same pattern as WalWriterProcess, with 2 socketpairs
// =====================================================================

bool FimScannerProcess::start() {
    std::lock_guard<std::mutex> lk(mu_);
    return ensure_child_locked();
}

bool FimScannerProcess::ensure_child_locked() {
    // Fast path: child still alive? (T13.1 lesson #4.)
    if (child_pid_ > 0) {
        int status = 0;
        pid_t r = ::waitpid(child_pid_, &status, WNOHANG);
        if (r == 0) return true;  // child still running
        if (r == child_pid_) {
            std::fprintf(stderr, "[fim_scanner] child pid=%d exited (status=%d), re-forking\n",
                         static_cast<int>(child_pid_), WEXITSTATUS(status));
            child_pid_ = -1;
            if (parent_event_fd_ >= 0) { ::close(parent_event_fd_); parent_event_fd_ = -1; }
            if (parent_cmd_fd_   >= 0) { ::close(parent_cmd_fd_);   parent_cmd_fd_   = -1; }
            if (++restarts_ > MAX_CHILD_RESTARTS) {
                std::fprintf(stderr, "[fim_scanner] child restarted %d times, giving up\n",
                             MAX_CHILD_RESTARTS);
                return false;
            }
        }
    }

    // Create both socketpairs. AF_UNIX, SOCK_SEQPACKET, SOCK_CLOEXEC.
    int sv_ev[2] = {-1, -1};
    int sv_cmd[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv_ev) != 0) {
        std::fprintf(stderr, "[fim_scanner] socketpair(event) failed: %s\n",
                     std::strerror(errno));
        return false;
    }
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv_cmd) != 0) {
        std::fprintf(stderr, "[fim_scanner] socketpair(cmd) failed: %s\n",
                     std::strerror(errno));
        ::close(sv_ev[0]); ::close(sv_ev[1]);
        return false;
    }

    // SO_RCVTIMEO + SO_SNDTIMEO 1s on both parent fds. The dispatcher
    // uses the event fd; poll_now() uses the cmd fd. They are
    // DIFFERENT fds, so no race possible. 1s is generous.
    struct timeval to = { 1, 0 };
    if (::setsockopt(sv_ev[0],  SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to)) != 0 ||
        ::setsockopt(sv_ev[0],  SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to)) != 0 ||
        ::setsockopt(sv_cmd[0], SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to)) != 0 ||
        ::setsockopt(sv_cmd[0], SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to)) != 0) {
        std::fprintf(stderr, "[fim_scanner] setsockopt failed: %s\n",
                     std::strerror(errno));
        ::close(sv_ev[0]); ::close(sv_ev[1]);
        ::close(sv_cmd[0]); ::close(sv_cmd[1]);
        return false;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        std::fprintf(stderr, "[fim_scanner] fork() failed: %s\n",
                     std::strerror(errno));
        ::close(sv_ev[0]); ::close(sv_ev[1]);
        ::close(sv_cmd[0]); ::close(sv_cmd[1]);
        return false;
    }

    if (pid == 0) {
        // ----- CHILD -----
        ::close(sv_ev[0]);
        ::close(sv_cmd[0]);
        child_entry(sv_ev[1], sv_cmd[1], cfg_);
        // child_entry should _exit(0), this is defensive
        ::_exit(0);
    }

    // ----- PARENT -----
    ::close(sv_ev[1]);
    ::close(sv_cmd[1]);
    parent_event_fd_ = sv_ev[0];
    parent_cmd_fd_   = sv_cmd[0];
    child_pid_       = pid;
    restarts_        = 0;

    // Start the dispatcher thread that reads the event channel.
    if (dispatcher_.joinable()) dispatcher_.join();
    dispatcher_ = std::thread(&FimScannerProcess::dispatcher_loop, this);

    std::fprintf(stderr, "[fim_scanner] child started, pid=%d "
                 "(will drop to %s:%s, 2 channels)\n",
                 static_cast<int>(child_pid_),
                 cfg_.wal_user.c_str(), cfg_.wal_group.c_str());
    return true;
}

void FimScannerProcess::child_entry(int event_fd, int cmd_fd, Config cfg) {
    // Drop privileges to logsoc:logsoc. Order is strict (lesson #5).
    // T13.5 noise fix (2026-06-17): use cached getpwnam_r via
    // logsoc::resolve_user_group. The previous direct getpwnam()
    // opened the abstract socket /run/systemd/userdb/... on every
    // fork, generating ~6 AppArmor DENIED/sec.
    auto ug = logsoc::resolve_user_group(cfg.wal_user, cfg.wal_group);
    if (!ug.valid) {
        std::fprintf(stderr, "[fim_scanner/child] getpwnam(%s) failed\n",
                     cfg.wal_user.c_str());
        ::_exit(1);
    }
    if (::setgroups(0, nullptr) != 0 ||
        ::setgid(ug.gid) != 0 ||
        ::setuid(ug.uid) != 0) {
        std::fprintf(stderr, "[fim_scanner/child] setuid/setgid failed: %s\n",
                     std::strerror(errno));
        ::_exit(1);
    }

    // Double-parens defeat MVP (lesson #1).
    FimScannerProcess instance((Config(cfg)));
    instance.child_main(event_fd, cmd_fd, cfg);
    // child_main should not return; defensive
    std::fflush(stderr);
    ::_exit(0);
}

void FimScannerProcess::child_main(int event_fd, int cmd_fd, const Config& cfg) {
    // Set short timeouts on both fds in the child. The cmd channel
    // uses 1s; the event channel uses 5s (child can block longer
    // writing events — the parent dispatcher can keep up).
    struct timeval cmd_to   = { 1, 0 };
    struct timeval event_to = { 5, 0 };
    ::setsockopt(cmd_fd,   SOL_SOCKET, SO_RCVTIMEO, &cmd_to,   sizeof(cmd_to));
    ::setsockopt(cmd_fd,   SOL_SOCKET, SO_SNDTIMEO, &cmd_to,   sizeof(cmd_to));
    ::setsockopt(event_fd, SOL_SOCKET, SO_SNDTIMEO, &event_to, sizeof(event_to));
    // event_fd RCVTIMEO is unused (the child never reads on the event
    // channel — it's a one-way publisher), but set it for hygiene.
    ::setsockopt(event_fd, SOL_SOCKET, SO_RCVTIMEO, &event_to, sizeof(event_to));

    std::fprintf(stderr, "[fim_scanner/child] uid=%d gid=%d watch_paths=%zu "
                 "poll_interval=%ds\n",
                 static_cast<int>(::geteuid()),
                 static_cast<int>(::getegid()),
                 cfg.watch_paths.size(),
                 cfg.poll_interval_sec);
    std::fflush(stderr);

    // ----- Construct the FimPoller in callback mode -----
    // The callback is invoked synchronously on the poller's thread for
    // each detected change. It must be non-blocking. If send() returns
    // EAGAIN or short write, we drop the event (logged at WARN).
    // This is acceptable: the next 5s poll cycle will catch a missed
    // change (and the FimPoller always re-checks).
    auto forward_to_parent = [this, event_fd](const logsoc::agent::fim::FimEvent& ev) {
        std::vector<uint8_t> payload;
        append_fim_event(payload, ev);
        if (!send_frame(event_fd, 0x83, payload.data(),
                        static_cast<uint32_t>(payload.size()))) {
            std::fprintf(stderr, "[fim_scanner/child] send PUBLISH_EXTERNAL failed\n");
            std::fflush(stderr);
        }
    };

    logsoc::agent::fim::FimPoller::Config poller_cfg;
    poller_cfg.poll_interval = std::chrono::seconds(cfg.poll_interval_sec);
    poller_cfg.watch_paths   = cfg.watch_paths;

    logsoc::agent::fim::FimPoller poller(poller_cfg, forward_to_parent);
    std::fprintf(stderr, "[fim_scanner/child] FimPoller ready\n");
    std::fflush(stderr);

    // ----- Command loop -----
    // Read frames on cmd_fd. The cmd channel is exclusive to commands
    // (no PUBLISH_EXTERNAL here), so the dispatcher race from T13.2a
    // does not exist.
    //
    // recv_frame() returns false on EOF (peer closed) OR on EAGAIN
    // (SO_RCVTIMEO expired, no data). We MUST distinguish them:
    //   - EOF (errno != EAGAIN) → parent is gone, exit cleanly.
    //   - EAGAIN → idle tick, just retry.
    while (!stop_requested_.load()) {
        uint8_t type;
        std::vector<uint8_t> payload;
        if (!recv_frame(cmd_fd, &type, payload)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Idle: no command in the last 1s. Continue.
                continue;
            }
            // EOF or hard error. Parent is gone.
            std::fprintf(stderr, "[fim_scanner/child] cmd channel closed (errno=%d %s), exiting\n",
                         errno, std::strerror(errno));
            std::fflush(stderr);
            break;
        }
        switch (type) {
            case 0x10: {  // POLL_NOW
                int changes = poller.poll_now();
                uint32_t v = (changes > 0) ? static_cast<uint32_t>(changes) : 0u;
                if (!send_u32(cmd_fd, 0x80, v)) {
                    std::fprintf(stderr, "[fim_scanner/child] POLL_NOW_OK send failed\n");
                    std::fflush(stderr);
                }
                break;
            }
            case 0x11: {  // GET_STATS
                std::vector<uint8_t> body;
                append_u64_le(body, poller.polls_total());
                append_u64_le(body, poller.changes_total());
                if (!send_frame(cmd_fd, 0x81, body.data(),
                                static_cast<uint32_t>(body.size()))) {
                    std::fprintf(stderr, "[fim_scanner/child] STATS_RESP send failed\n");
                    std::fflush(stderr);
                }
                break;
            }
            case 0x12: {  // STOP_CMD
                if (!send_simple(cmd_fd, 0x82)) {
                    std::fprintf(stderr, "[fim_scanner/child] STOP_CMD_OK send failed\n");
                }
                stop_requested_.store(true);
                break;
            }
            case 0x13: {  // STOP_EVENT (shouldn't come on cmd channel)
                std::fprintf(stderr, "[fim_scanner/child] unexpected STOP_EVENT on cmd channel\n");
                std::fflush(stderr);
                break;
            }
            default: {
                std::fprintf(stderr, "[fim_scanner/child] unknown cmd type=0x%02x\n",
                             static_cast<unsigned>(type));
                std::fflush(stderr);
                std::vector<uint8_t> err(4);
                int32_t e = EINVAL;
                err[0] = static_cast<uint8_t>(e & 0xff);
                err[1] = static_cast<uint8_t>((e >> 8) & 0xff);
                err[2] = static_cast<uint8_t>((e >> 16) & 0xff);
                err[3] = static_cast<uint8_t>((e >> 24) & 0xff);
                (void)send_frame(cmd_fd, 0x8F, err.data(), 4);
                break;
            }
        }
    }

    // Drop the poller explicitly (joins its thread, then destructor).
    // FimPoller's destructor is called when this scope exits.
    std::fprintf(stderr, "[fim_scanner/child] cmd loop exited, closing fds\n");
    std::fflush(stderr);
    ::close(cmd_fd);
    ::close(event_fd);
}

// =====================================================================
// Drop-in FimPoller-compatible API (parent side)
// =====================================================================

void FimScannerProcess::dispatcher_loop() {
    std::fprintf(stderr, "[fim_scanner/dispatcher] started, event_fd=%d\n",
                 parent_event_fd_);
    std::fflush(stderr);
    while (!stop_requested_.load()) {
        int fd;
        {
            std::lock_guard<std::mutex> lk(mu_);
            fd = parent_event_fd_;
        }
        if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        uint8_t type;
        std::vector<uint8_t> payload;
        if (!recv_frame(fd, &type, payload)) {
            // Child closed the channel or died. Sleep briefly and
            // re-check stop_requested; the parent may have called
            // stop() and we'll exit cleanly.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        if (type == 0x83 && !payload.empty()) {
            // PUBLISH_EXTERNAL: deserialize FimEvent
            logsoc::agent::fim::FimEvent ev;
            size_t off = 0;
            if (read_fim_event(payload.data(), payload.size(), &off, ev)) {
                std::lock_guard<std::mutex> lk(inbound_mtx_);
                if (inbound_events_.size() >= INBOUND_QUEUE_CAP) {
                    // FIFO drop: pop oldest, push newest
                    inbound_events_.erase(inbound_events_.begin());
                }
                inbound_events_.push_back(std::move(ev));
            } else {
                std::fprintf(stderr, "[fim_scanner/dispatcher] FimEvent deserialization failed\n");
                std::fflush(stderr);
            }
        } else {
            // Unknown type on the event channel. Log and continue.
            std::fprintf(stderr, "[fim_scanner/dispatcher] unexpected type=0x%02x len=%zu\n",
                         static_cast<unsigned>(type), payload.size());
            std::fflush(stderr);
        }
    }
    std::fprintf(stderr, "[fim_scanner/dispatcher] exiting\n");
    std::fflush(stderr);
}

int FimScannerProcess::poll_now() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!ensure_child_locked()) return 0;
    if (parent_cmd_fd_ < 0) return 0;
    if (!send_simple(parent_cmd_fd_, 0x10)) return 0;
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(parent_cmd_fd_, &type, payload)) return 0;
    if (type != 0x80 || payload.size() < 4) return 0;
    return static_cast<int>(read_u32_le(payload.data()));
}

bool FimScannerProcess::pop_event(logsoc::agent::fim::FimEvent& out) {
    std::lock_guard<std::mutex> lk(inbound_mtx_);
    if (inbound_events_.empty()) return false;
    out = std::move(inbound_events_.front());
    inbound_events_.erase(inbound_events_.begin());
    return true;
}

size_t FimScannerProcess::event_queue_depth() const {
    std::lock_guard<std::mutex> lk(inbound_mtx_);
    return inbound_events_.size();
}

void FimScannerProcess::stop() {
    pid_t pid_to_kill = -1;
    int   ev_fd_to_close = -1;
    int   cmd_fd_to_close = -1;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (child_pid_ <= 0 && parent_event_fd_ < 0 && parent_cmd_fd_ < 0) return;
        stop_requested_.store(true);
        pid_to_kill    = child_pid_;
        ev_fd_to_close = parent_event_fd_;
        cmd_fd_to_close = parent_cmd_fd_;
        // Mark as dead so future calls to ensure_child_locked start fresh
        child_pid_      = -1;
        parent_event_fd_ = -1;
        parent_cmd_fd_   = -1;
    }

    // Send graceful shutdown on cmd channel (best effort).
    if (cmd_fd_to_close >= 0) {
        (void)send_simple(cmd_fd_to_close, 0x12);  // STOP_CMD
    }

    if (pid_to_kill > 0) {
        int status = 0;
        for (int i = 0; i < 20; ++i) {
            pid_t r = ::waitpid(pid_to_kill, &status, WNOHANG);
            if (r == pid_to_kill) {
                std::fprintf(stderr, "[fim_scanner] child stopped gracefully\n");
                goto done;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::fprintf(stderr, "[fim_scanner] child did not exit after 2s, SIGTERM\n");
        ::kill(pid_to_kill, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            pid_t r = ::waitpid(pid_to_kill, &status, WNOHANG);
            if (r == pid_to_kill) goto done;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::fprintf(stderr, "[fim_scanner] SIGTERM+2s timeout, SIGKILL\n");
        ::kill(pid_to_kill, SIGKILL);
        ::waitpid(pid_to_kill, &status, 0);
    }
done:
    if (ev_fd_to_close   >= 0) ::close(ev_fd_to_close);
    if (cmd_fd_to_close  >= 0) ::close(cmd_fd_to_close);
}

}  // namespace fim_scanner
