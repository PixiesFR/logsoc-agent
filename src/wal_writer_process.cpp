// wal_writer_process.cpp — T13 (audit Nova 2026-06-16):
// privilege-separated FallbackWAL writer (see wal_writer_process.hpp for
// architecture and protocol details).
//
// Drop-in for fallback_wal::FallbackWAL. The parent process holds an
// instance of WalWriterProcess and uses it exactly like FallbackWAL. All
// filesystem writes happen in the child after setuid(logsoc) — the parent
// (running as root for eBPF / network) never touches /var/lib/logsoc-agent.
//
// Build deps: <sys/socket.h>, <sys/types.h>, <sys/wait.h>, <unistd.h>,
// <signal.h>, <fcntl.h>, <errno.h>, <pwd.h>, <grp.h>, <cstring>.

#include "wal_writer_process.hpp"
#include "logsoc_user_cache.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <thread>

#include "debug.hpp"
#include "fallback_wal.hpp"

namespace wal_writer {

// =====================================================================
// Construction / destruction
// =====================================================================

WalWriterProcess::WalWriterProcess(Config cfg) : cfg_(std::move(cfg)) {}

WalWriterProcess::~WalWriterProcess() {
    stop();
}

// =====================================================================
// IPC serialization helpers
// =====================================================================

void WalWriterProcess::append_u32_le(std::vector<uint8_t>& buf, uint32_t v) {
    size_t n = buf.size();
    buf.resize(n + 4);
    buf[n+0] = static_cast<uint8_t>(v & 0xff);
    buf[n+1] = static_cast<uint8_t>((v >> 8) & 0xff);
    buf[n+2] = static_cast<uint8_t>((v >> 16) & 0xff);
    buf[n+3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void WalWriterProcess::append_u64_le(std::vector<uint8_t>& buf, uint64_t v) {
    size_t n = buf.size();
    buf.resize(n + 8);
    for (int i = 0; i < 8; ++i) {
        buf[n+i] = static_cast<uint8_t>((v >> (8*i)) & 0xff);
    }
}

uint32_t WalWriterProcess::read_u32_le(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t WalWriterProcess::read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8*i);
    }
    return v;
}

// =====================================================================
// Socketpair / fork / setuid
// =====================================================================

bool WalWriterProcess::start() {
    std::lock_guard<std::mutex> lk(mu_);
    if (child_pid_ > 0) {
        // Already running.
        return true;
    }
    return ensure_child_locked();
}

bool WalWriterProcess::ensure_child_locked() {
    // Fast path: if the child is still alive, reuse it. We poll the
    // child_pid_ — if it's > 0 AND waitpid(WNOHANG) returns 0, the
    // child is alive and we can use the existing socketpair. If the
    // child has exited (waitpid returns the pid), we need to fork a
    // new one.
    if (child_pid_ > 0) {
        int status = 0;
        pid_t r = ::waitpid(child_pid_, &status, WNOHANG);
        if (r == 0) {
            // Child still running, socketpair still valid.
            return true;
        }
        if (r == child_pid_) {
            // Child has exited. Reap it and fall through to re-fork.
            LOG_WARN("[wal_writer] child pid=" << child_pid_
                     << " has exited (status=" << WEXITSTATUS(status)
                     << "), re-forking");
            child_pid_ = -1;
            if (parent_fd_ >= 0) {
                ::close(parent_fd_);
                parent_fd_ = -1;
            }
        }
        // r < 0 (ECHILD) means the child was already reaped (e.g. by
        // a signal handler). Fall through to re-fork.
    }

    // 1. Create the socketpair. SOCK_SEQPACKET preserves message
    //    boundaries (no stream reassembly); SOCK_CLOEXEC prevents fd
    //    leaks across execve. Protocol 0 = default (no need for a
    //    specific protocol family inside AF_UNIX).
    int sv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) {
        LOG_ERROR("[wal_writer] socketpair() failed: " << std::strerror(errno));
        return false;
    }

    // 2. The parent fd uses socket timeouts (SO_RCVTIMEO + SO_SNDTIMEO)
    //    for backpressure and liveness, NOT O_NONBLOCK. Reason: on
    //    Linux, O_NONBLOCK + SO_RCVTIMEO is undefined behavior —
    //    O_NONBLOCK wins and SO_RCVTIMEO is ignored. We want blocking
    //    recv/send that fails after a timeout, so the parent can detect
    //    a wedged child and re-fork on the next call.
    //    (See socket(7): "O_NONBLOCK ... If SO_RCVTIMEO and SO_SNDTIMEO
    //    are also set ... this is currently undefined.")
    //    Receive timeout: 5 seconds. Send timeout: 5 seconds.
    struct timeval rcvto = { 5, 0 };
    if (::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto)) != 0) {
        LOG_ERROR("[wal_writer] setsockopt(SO_RCVTIMEO) failed: "
                  << std::strerror(errno));
        ::close(sv[0]); ::close(sv[1]);
        return false;
    }
    struct timeval sndto = { 5, 0 };
    if (::setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &sndto, sizeof(sndto)) != 0) {
        LOG_ERROR("[wal_writer] setsockopt(SO_SNDTIMEO) failed: "
                  << std::strerror(errno));
        ::close(sv[0]); ::close(sv[1]);
        return false;
    }

    // 3. Fork. CRITICAL: fork() must happen before any pthread is
    //    created in the parent (agent.cpp main loop spawns threads
    //    after WalWriterProcess::start(), so we are safe here). If
    //    you move this call later, install pthread_atfork() first.
    pid_t pid = ::fork();
    if (pid < 0) {
        LOG_ERROR("[wal_writer] fork() failed: " << std::strerror(errno));
        ::close(sv[0]); ::close(sv[1]);
        return false;
    }

    if (pid == 0) {
        // ----- CHILD -----
        // Close the parent end. The child only ever talks on sv[1].
        ::close(sv[0]);
        // Reset signal handlers to defaults (in case the parent had
        // custom SIGCHLD / SIGTERM handlers that would interfere).
        // We don't touch SIGKILL/SIGSTOP (uncatchable anyway).
        // Note: pthread_sigmask is irrelevant pre-pthread creation,
        // and we are the only thread here, so it's fine.
        // The actual work is in child_entry (static, calls child_main).
        child_entry(sv[1], cfg_);
        // child_entry should not return; if it does, exit cleanly.
        ::_exit(0);
    }

    // ----- PARENT -----
    // Close the child end. Parent only ever talks on sv[0].
    ::close(sv[1]);
    parent_fd_ = sv[0];
    child_pid_ = pid;
    restarts_  = 0;  // fresh start, reset counter
    LOG_INFO("[wal_writer] child started, pid=" << child_pid_
             << " (will drop to " << cfg_.wal_user << ":" << cfg_.wal_group << ")");
    return true;
}

// =====================================================================
// Child entry point
// =====================================================================

void WalWriterProcess::child_entry(int fd, Config cfg) {
    // Resolve UID/GID BEFORE doing anything else, so we can fail fast
    // and exit without half-initializing.
    // T13.5 noise fix (2026-06-17): use cached getpwnam_r via
    // logsoc::resolve_user_group. The previous direct getpwnam()
    // opened the abstract socket /run/systemd/userdb/... on every
    // fork, generating ~6 AppArmor DENIED/sec. The cache hits on
    // every fork after the first one.
    auto ug = logsoc::resolve_user_group(cfg.wal_user, cfg.wal_group);
    if (!ug.valid) {
        std::fprintf(stderr, "[wal_writer/child] getpwnam(%s) failed\n",
                     cfg.wal_user.c_str());
        ::_exit(1);
    }
    uid_t target_uid = ug.uid;
    gid_t target_gid = ug.gid;

    // Drop supplementary groups first (defense in depth: even if the
    // parent had groups like adm, systemd-journal, we strip them all
    // before the setgid/setuid).
    if (::setgroups(0, nullptr) != 0) {
        std::fprintf(stderr, "[wal_writer/child] setgroups(0) failed: %s\n",
                     std::strerror(errno));
        ::_exit(1);
    }
    // Drop GID, then UID. setuid must be last (it can only lower euid).
    if (::setgid(target_gid) != 0) {
        std::fprintf(stderr, "[wal_writer/child] setgid(%u) failed: %s\n",
                     (unsigned)target_gid, std::strerror(errno));
        ::_exit(1);
    }
    if (::setuid(target_uid) != 0) {
        std::fprintf(stderr, "[wal_writer/child] setuid(%u) failed: %s\n",
                     (unsigned)target_uid, std::strerror(errno));
        ::_exit(1);
    }

    // From here on, the process is unprivileged. We construct a
    // WalWriterProcess instance just to call child_main (the IPC loop).
    // The parent's instance is in the parent process — this is a
    // separate object in the child's address space. NOTE: do NOT move
    // `cfg` into the instance before passing it to child_main, or the
    // reference child_main receives will be empty.
    WalWriterProcess instance((Config(cfg)));  // double-parens to defeat MVP
    instance.child_main(fd, cfg);
    // child_main returns only on STOP / EOF. Exit cleanly.
    ::_exit(0);
}

// =====================================================================
// Child IPC loop
// =====================================================================

void WalWriterProcess::child_main(int fd, const Config& cfg) {
    // Construct the real FallbackWAL. We are now logsoc:logsoc, so
    // file ownership will be correct automatically.
    try {
        fallback_wal::FallbackWAL fwal(cfg.data_dir, cfg.aes_key, cfg.agent_id);
        LOG_INFO("[wal_writer/child] uid=" << ::geteuid()
                 << " gid=" << ::getegid()
                 << " FallbackWAL ready ("
                 << fwal.count() << " events on disk)");

        // Receive loop. SOCK_SEQPACKET: one recvmsg = one message, the
        // kernel never delivers a partial frame and never merges frames.
        std::vector<uint8_t> header(MSG_HEADER_SIZE);
        std::vector<uint8_t> payload(MSG_MAX_PAYLOAD);

        while (!stop_requested_.load()) {
            // 1) Read 5-byte header.
            ssize_t got = ::recv(fd, header.data(), header.size(), 0);
            if (got == 0) {
                // Parent closed its end: clean shutdown.
                LOG_INFO("[wal_writer/child] parent closed socket, exiting");
                break;
            }
            if (got < 0) {
                if (errno == EINTR) continue;
                LOG_ERROR("[wal_writer/child] recv(header) failed: "
                          << std::strerror(errno) << " (errno=" << errno << ")");
                break;
            }
            if (got != MSG_HEADER_SIZE) {
                LOG_ERROR("[wal_writer/child] short header read: "
                          << got << " bytes");
                break;
            }
            uint8_t  type    = header[0];
            uint32_t length  = read_u32_le(header.data() + 1);

            if (length > MSG_MAX_PAYLOAD) {
                // We must drain the oversized message to keep the
                // stream in sync. SOCK_SEQPACKET + MSG_TRUNC: pass
                // MSG_TRUNC so the kernel reports the actual size but
                // does NOT keep the bytes; we still need to read and
                // discard. Use a dummy buffer of MSG_MAX_PAYLOAD.
                LOG_ERROR("[wal_writer/child] oversized message type=0x"
                          << std::hex << (int)type << std::dec
                          << " length=" << length
                          << " > MSG_MAX_PAYLOAD=" << MSG_MAX_PAYLOAD
                          << " — dropping");
                size_t remaining = length;
                std::vector<uint8_t> junk(MSG_MAX_PAYLOAD);
                while (remaining > 0) {
                    size_t want = remaining > junk.size() ? junk.size() : remaining;
                    ssize_t n = ::recv(fd, junk.data(), want, MSG_TRUNC);
                    if (n <= 0) break;
                    if (static_cast<size_t>(n) > want) {
                        // Truncated; skip the rest.
                        remaining = 0;
                    } else {
                        remaining -= static_cast<size_t>(n);
                    }
                }
                // Reply with ERROR.
                std::vector<uint8_t> err(4);
                append_u32_le(err, EMSGSIZE);
                uint8_t  h[MSG_HEADER_SIZE] = {0x8F, 0,0,0,0};
                uint32_t L = 4;
                h[1] = (uint8_t)(L & 0xff);
                h[2] = (uint8_t)((L>>8) & 0xff);
                h[3] = (uint8_t)((L>>16) & 0xff);
                h[4] = (uint8_t)((L>>24) & 0xff);
                ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                ::send(fd, err.data(), 4, MSG_NOSIGNAL);
                continue;
            }

            // 2) Read payload. For SOCK_SEQPACKET, we can use a single
            //    recv even for a 0-byte payload (recv returns 0 but
            //    it's the payload length, not EOF — EOF only happens
            //    when the whole connection is closed).
            if (length > 0) {
                ssize_t got2 = ::recv(fd, payload.data(), length, 0);
                if (got2 <= 0) {
                    LOG_ERROR("[wal_writer/child] recv(payload) failed/EOF: "
                              << std::strerror(errno));
                    break;
                }
                if (got2 != static_cast<ssize_t>(length)) {
                    // SOCK_SEQPACKET should never short-read, but be defensive.
                    LOG_ERROR("[wal_writer/child] short payload read: "
                              << got2 << " / " << length);
                    break;
                }
            }

            // 3) Dispatch.
            try {
                switch (type) {
                    case 0x01: {  // PUSH
                        std::string ev(reinterpret_cast<const char*>(payload.data()),
                                       length);
                        bool ok = fwal.push(std::move(ev));
                        if (ok) {
                            uint8_t h[MSG_HEADER_SIZE] = {0x80, 0,0,0,0};
                            ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        } else {
                            uint8_t h[MSG_HEADER_SIZE] = {0x8F, 0,0,0,0};
                            std::vector<uint8_t> err(4);
                            append_u32_le(err, EIO);
                            uint32_t L = 4;
                            h[1] = (uint8_t)(L & 0xff); h[2] = (uint8_t)((L>>8) & 0xff);
                            h[3] = (uint8_t)((L>>16) & 0xff); h[4] = (uint8_t)((L>>24) & 0xff);
                            ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                            ::send(fd, err.data(), 4, MSG_NOSIGNAL);
                        }
                        break;
                    }
                    case 0x02: {  // POP_BATCH
                        if (length != 4) break;
                        uint32_t n = read_u32_le(payload.data());
                        auto events = fwal.pop_batch(n);
                        std::vector<uint8_t> body;
                        append_u32_le(body, static_cast<uint32_t>(events.size()));
                        for (const auto& e : events) {
                            // FallbackEvent layout for wire:
                            //   uint64 event_id_hash
                            //   uint32 raw_event length
                            //   raw_event bytes
                            append_u64_le(body, e.event_id_hash);
                            append_u32_le(body, static_cast<uint32_t>(e.raw_event.size()));
                            body.insert(body.end(),
                                        e.raw_event.begin(),
                                        e.raw_event.end());
                        }
                        uint8_t h[MSG_HEADER_SIZE] = {0x81, 0,0,0,0};
                        uint32_t L = static_cast<uint32_t>(body.size());
                        h[1] = (uint8_t)(L & 0xff); h[2] = (uint8_t)((L>>8) & 0xff);
                        h[3] = (uint8_t)((L>>16) & 0xff); h[4] = (uint8_t)((L>>24) & 0xff);
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        if (!body.empty()) {
                            ::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
                        }
                        break;
                    }
                    case 0x03: {  // MARK_SENT
                        if (length != 8) break;
                        uint64_t h64 = read_u64_le(payload.data());
                        fwal.mark_sent(h64);
                        uint8_t h[MSG_HEADER_SIZE] = {0x82, 0,0,0,0};
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        break;
                    }
                    case 0x04: {  // STOP
                        uint8_t h[MSG_HEADER_SIZE] = {0x84, 0,0,0,0};
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        stop_requested_.store(true);
                        break;
                    }
                    case 0x05: {  // COUNT
                        uint64_t cnt = fwal.count();
                        std::vector<uint8_t> body;
                        append_u64_le(body, cnt);
                        uint8_t h[MSG_HEADER_SIZE] = {0x83, 0,0,0,0};
                        uint32_t L = static_cast<uint32_t>(body.size());
                        h[1] = (uint8_t)(L & 0xff); h[2] = (uint8_t)((L>>8) & 0xff);
                        h[3] = (uint8_t)((L>>16) & 0xff); h[4] = (uint8_t)((L>>24) & 0xff);
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        ::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
                        break;
                    }
                    case 0x06: {  // DRAIN
                        auto events = fwal.pop_batch(fwal.count());
                        std::vector<uint8_t> body;
                        append_u32_le(body, static_cast<uint32_t>(events.size()));
                        for (const auto& e : events) {
                            append_u64_le(body, e.event_id_hash);
                            append_u32_le(body, static_cast<uint32_t>(e.raw_event.size()));
                            body.insert(body.end(),
                                        e.raw_event.begin(),
                                        e.raw_event.end());
                        }
                        uint8_t h[MSG_HEADER_SIZE] = {0x85, 0,0,0,0};
                        uint32_t L = static_cast<uint32_t>(body.size());
                        h[1] = (uint8_t)(L & 0xff); h[2] = (uint8_t)((L>>8) & 0xff);
                        h[3] = (uint8_t)((L>>16) & 0xff); h[4] = (uint8_t)((L>>24) & 0xff);
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        if (!body.empty()) {
                            ::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
                        }
                        break;
                    }
                    case 0x07: {  // CLEANUP_OLD (max_age_sec as u32)
                        if (length != 4) break;
                        uint32_t age = read_u32_le(payload.data());
                        fwal.cleanup_old_segments(age);
                        uint8_t h[MSG_HEADER_SIZE] = {0x87, 0,0,0,0};
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        break;
                    }
                    default: {
                        LOG_WARN("[wal_writer/child] unknown msg type=0x"
                                 << std::hex << (int)type << std::dec
                                 << " (silently ignored — header only)");
                        // Drain payload if any (we already read it above
                        // in the length > 0 branch).
                        // Reply with ERROR to keep protocol symmetric.
                        std::vector<uint8_t> err(4);
                        append_u32_le(err, EINVAL);
                        uint8_t h[MSG_HEADER_SIZE] = {0x8F, 0,0,0,0};
                        uint32_t L = 4;
                        h[1] = (uint8_t)(L & 0xff); h[2] = (uint8_t)((L>>8) & 0xff);
                        h[3] = (uint8_t)((L>>16) & 0xff); h[4] = (uint8_t)((L>>24) & 0xff);
                        ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                        ::send(fd, err.data(), 4, MSG_NOSIGNAL);
                        break;
                    }
                }
            } catch (const std::exception& e) {
                LOG_ERROR("[wal_writer/child] dispatch exception: " << e.what());
                // Try to send ERROR.
                std::vector<uint8_t> err(4);
                append_u32_le(err, EIO);
                uint8_t h[MSG_HEADER_SIZE] = {0x8F, 0,0,0,0};
                uint32_t L = 4;
                h[1] = (uint8_t)(L & 0xff); h[2] = (uint8_t)((L>>8) & 0xff);
                h[3] = (uint8_t)((L>>16) & 0xff); h[4] = (uint8_t)((L>>24) & 0xff);
                ::send(fd, h, MSG_HEADER_SIZE, MSG_NOSIGNAL);
                ::send(fd, err.data(), 4, MSG_NOSIGNAL);
            }

            if (stop_requested_.load()) break;
        }  // while

        // Close the socket on the child side so the parent sees EOF.
        ::close(fd);
        LOG_INFO("[wal_writer/child] clean shutdown, exiting uid="
                 << ::geteuid());
    } catch (const std::exception& e) {
        LOG_ERROR("[wal_writer/child] fatal: " << e.what());
        ::_exit(1);
    }
}

// =====================================================================
// Parent-side IPC primitives
// =====================================================================

bool WalWriterProcess::send_frame(uint8_t type, const void* payload, uint32_t len) {
    if (len > MSG_MAX_PAYLOAD) {
        LOG_ERROR("[wal_writer] send_frame: payload " << len
                  << " > MSG_MAX_PAYLOAD " << MSG_MAX_PAYLOAD);
        return false;
    }
    uint8_t header[MSG_HEADER_SIZE];
    header[0] = type;
    header[1] = static_cast<uint8_t>(len & 0xff);
    header[2] = static_cast<uint8_t>((len >> 8) & 0xff);
    header[3] = static_cast<uint8_t>((len >> 16) & 0xff);
    header[4] = static_cast<uint8_t>((len >> 24) & 0xff);

    // The parent fd has O_NONBLOCK + SO_SNDTIMEO (5s). If the kernel
    // buffer is full and the child is too slow to drain, send will
    // return EAGAIN/ETIMEDOUT after 5s — we treat that as a hard fail
    // (the caller may re-fork the child on the next call).
    ssize_t n = ::send(parent_fd_, header, MSG_HEADER_SIZE, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EINTR) return send_frame(type, payload, len);
        if (errno == EPIPE) {
            LOG_WARN("[wal_writer] EPIPE on send (child dead?)");
            return false;
        }
        LOG_ERROR("[wal_writer] send(header) failed: " << std::strerror(errno));
        return false;
    }
    if (n != MSG_HEADER_SIZE) {
        LOG_ERROR("[wal_writer] send(header) short write: " << n);
        return false;
    }
    if (len > 0) {
        ssize_t n2 = ::send(parent_fd_, payload, len, MSG_NOSIGNAL);
        if (n2 < 0) {
            if (errno == EINTR) return send_frame(type, payload, len);
            if (errno == EPIPE) return false;
            LOG_ERROR("[wal_writer] send(payload) failed: " << std::strerror(errno));
            return false;
        }
        if (n2 != static_cast<ssize_t>(len)) {
            LOG_ERROR("[wal_writer] send(payload) short write: " << n2);
            return false;
        }
    }
    return true;
}

bool WalWriterProcess::recv_frame(uint8_t* out_type, std::vector<uint8_t>& out_payload) {
    // The parent fd has SO_RCVTIMEO (5s). recv blocks until a message
    // arrives or the timeout fires. EAGAIN/EWOULDBLOCK cannot happen
    // here (the timeout converts to ETIMEDOUT). We still tolerate EINTR.
    uint8_t header[MSG_HEADER_SIZE];
    ssize_t n = ::recv(parent_fd_, header, MSG_HEADER_SIZE, 0);
    if (n == 0) return false;  // EOF — child closed
    if (n < 0) {
        if (errno == EINTR) return recv_frame(out_type, out_payload);
        // ETIMEDOUT (EAGAIN/EWOULDBLOCK with SO_RCVTIMEO), ECONNRESET, etc.
        LOG_ERROR("[wal_writer] recv(header) failed: " << std::strerror(errno));
        return false;
    }
    if (n != MSG_HEADER_SIZE) {
        LOG_ERROR("[wal_writer] recv(header) short read: " << n);
        return false;
    }
    *out_type = header[0];
    uint32_t length = read_u32_le(header + 1);
    if (length > MSG_MAX_PAYLOAD) {
        LOG_ERROR("[wal_writer] recv: length " << length
                  << " > MSG_MAX_PAYLOAD " << MSG_MAX_PAYLOAD
                  << " (child misbehaved?)");
        return false;
    }
    out_payload.assign(length, 0);
    if (length > 0) {
        ssize_t n2 = ::recv(parent_fd_, out_payload.data(), length, 0);
        if (n2 == 0) return false;  // EOF mid-frame
        if (n2 < 0) {
            if (errno == EINTR) return recv_frame(out_type, out_payload);
            LOG_ERROR("[wal_writer] recv(payload) failed: "
                      << std::strerror(errno));
            return false;
        }
        if (n2 != static_cast<ssize_t>(length)) {
            LOG_ERROR("[wal_writer] recv(payload) short read: " << n2);
            return false;
        }
    }
    return true;
}

bool WalWriterProcess::send_simple(uint8_t type) {
    return send_frame(type, nullptr, 0);
}

bool WalWriterProcess::send_u32(uint8_t type, uint32_t v) {
    uint8_t buf[4];
    buf[0] = (uint8_t)(v & 0xff);
    buf[1] = (uint8_t)((v >> 8) & 0xff);
    buf[2] = (uint8_t)((v >> 16) & 0xff);
    buf[3] = (uint8_t)((v >> 24) & 0xff);
    return send_frame(type, buf, 4);
}

bool WalWriterProcess::send_u64(uint8_t type, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) {
        buf[i] = (uint8_t)((v >> (8*i)) & 0xff);
    }
    return send_frame(type, buf, 8);
}

// =====================================================================
// Drop-in FallbackWAL-compatible API (parent side)
// =====================================================================

bool WalWriterProcess::push(const std::string& raw_event) {
    if (raw_event.size() > MSG_MAX_PAYLOAD) {
        LOG_ERROR("[wal_writer] push: event size " << raw_event.size()
                  << " > MSG_MAX_PAYLOAD " << MSG_MAX_PAYLOAD
                  << " — silently dropped (callers should chunk or trim)");
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    if (!ensure_child_locked()) return false;
    if (!send_frame(0x01, raw_event.data(), static_cast<uint32_t>(raw_event.size()))) {
        return false;
    }
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(&type, payload)) return false;
    if (type == 0x80) return true;          // PUSH_OK
    if (type == 0x8F) {                    // ERROR
        int32_t err = payload.size() >= 4 ? static_cast<int32_t>(read_u32_le(payload.data())) : EIO;
        LOG_ERROR("[wal_writer] push: child returned error: " << std::strerror(err));
        return false;
    }
    LOG_ERROR("[wal_writer] push: unexpected reply type=0x"
              << std::hex << (int)type << std::dec);
    return false;
}

std::vector<fallback_wal::FallbackEvent> WalWriterProcess::pop_batch(size_t n) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<fallback_wal::FallbackEvent> out;
    if (!ensure_child_locked()) return out;
    if (n > 0xFFFFFFFFu) n = 0xFFFFFFFFu;
    if (!send_u32(0x02, static_cast<uint32_t>(n))) return out;
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(&type, payload)) return out;
    if (type != 0x81) {
        LOG_ERROR("[wal_writer] pop_batch: unexpected reply type=0x"
                  << std::hex << (int)type << std::dec);
        return out;
    }
    if (payload.size() < 4) return out;
    uint32_t count = read_u32_le(payload.data());
    size_t off = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (off + 12 > payload.size()) break;
        uint64_t h = read_u64_le(payload.data() + off); off += 8;
        uint32_t ln = read_u32_le(payload.data() + off); off += 4;
        if (off + ln > payload.size()) break;
        fallback_wal::FallbackEvent ev;
        ev.event_id_hash = h;
        ev.raw_event.assign(reinterpret_cast<const char*>(payload.data() + off), ln);
        off += ln;
        out.push_back(std::move(ev));
    }
    return out;
}

void WalWriterProcess::mark_sent(uint64_t event_id_hash) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!ensure_child_locked()) return;
    if (!send_u64(0x03, event_id_hash)) return;
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(&type, payload)) return;
    if (type != 0x82) {
        LOG_ERROR("[wal_writer] mark_sent: unexpected reply type=0x"
                  << std::hex << (int)type << std::dec);
    }
}

size_t WalWriterProcess::count() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!ensure_child_locked()) return 0;
    if (!send_simple(0x05)) return 0;
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(&type, payload)) return 0;
    if (type != 0x83 || payload.size() < 8) return 0;
    return static_cast<size_t>(read_u64_le(payload.data()));
}

void WalWriterProcess::cleanup_old_segments(size_t max_age_sec) {
    if (max_age_sec > 0xFFFFFFFFu) max_age_sec = 0xFFFFFFFFu;
    std::lock_guard<std::mutex> lk(mu_);
    if (!ensure_child_locked()) return;
    if (!send_u32(0x07, static_cast<uint32_t>(max_age_sec))) return;
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(&type, payload)) return;
    if (type != 0x87) {
        LOG_ERROR("[wal_writer] cleanup: unexpected reply type=0x"
                  << std::hex << (int)type << std::dec);
    }
}

std::vector<fallback_wal::FallbackEvent> WalWriterProcess::drain_all() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<fallback_wal::FallbackEvent> out;
    if (!ensure_child_locked()) return out;
    if (!send_simple(0x06)) return out;
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(&type, payload)) return out;
    if (type != 0x85) {
        LOG_ERROR("[wal_writer] drain_all: unexpected reply type=0x"
                  << std::hex << (int)type << std::dec);
        return out;
    }
    if (payload.size() < 4) return out;
    uint32_t count = read_u32_le(payload.data());
    size_t off = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (off + 12 > payload.size()) break;
        uint64_t h = read_u64_le(payload.data() + off); off += 8;
        uint32_t ln = read_u32_le(payload.data() + off); off += 4;
        if (off + ln > payload.size()) break;
        fallback_wal::FallbackEvent ev;
        ev.event_id_hash = h;
        ev.raw_event.assign(reinterpret_cast<const char*>(payload.data() + off), ln);
        off += ln;
        out.push_back(std::move(ev));
    }
    return out;
}

// =====================================================================
// Shutdown
// =====================================================================

void WalWriterProcess::stop() {
    std::lock_guard<std::mutex> lk(mu_);
    if (child_pid_ <= 0 || parent_fd_ < 0) return;
    // Best-effort STOP. If the child is wedged, we SIGTERM after 2s
    // and SIGKILL after another 2s.
    stop_requested_.store(true);
    (void)send_simple(0x04);
    // Wait for the child to exit gracefully (max 2s).
    int status = 0;
    for (int i = 0; i < 20; ++i) {
        pid_t r = ::waitpid(child_pid_, &status, WNOHANG);
        if (r == child_pid_) {
            child_pid_ = -1;
            ::close(parent_fd_);
            parent_fd_ = -1;
            LOG_INFO("[wal_writer] child stopped gracefully");
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Graceful failed, escalate.
    LOG_WARN("[wal_writer] child did not exit after 2s, sending SIGTERM");
    ::kill(child_pid_, SIGTERM);
    for (int i = 0; i < 20; ++i) {
        pid_t r = ::waitpid(child_pid_, &status, WNOHANG);
        if (r == child_pid_) {
            child_pid_ = -1;
            ::close(parent_fd_);
            parent_fd_ = -1;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    LOG_WARN("[wal_writer] child did not exit after SIGTERM+2s, sending SIGKILL");
    ::kill(child_pid_, SIGKILL);
    ::waitpid(child_pid_, &status, 0);
    child_pid_ = -1;
    ::close(parent_fd_);
    parent_fd_ = -1;
}

}  // namespace wal_writer
