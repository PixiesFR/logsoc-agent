// action_recommender_process.cpp — T13.3': privilege-separated action
// recommender child. See action_recommender_process.hpp for the
// architecture and protocol.
//
// This implementation copies the IPC scaffolding from
// fim_scanner_process.cpp (T13.2b) and wal_writer_process.cpp (T13.1),
// adapted for a 1-channel request-reply pattern.

#include "action_recommender_process.hpp"
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

#include "debug.hpp"
#include "agent/severity_scorer.hpp"  // severity::score + score_to_severity
#include "agent/sigma_engine.hpp"     // sigma::match (TODO: confirm signature)

// nlohmann::json is used by the parent to construct events and by the
// child to parse them. It's already a project dep (used everywhere).
// In the project, the include is "json.hpp" (not <nlohmann/json.hpp>).
#include "json.hpp"

namespace action_recommender {

// =====================================================================
// Construction / destruction
// =====================================================================

ActionRecommenderProcess::ActionRecommenderProcess(Config cfg) : cfg_(std::move(cfg)) {}

ActionRecommenderProcess::~ActionRecommenderProcess() {
    stop();
}

// =====================================================================
// LE byte-order helpers
// =====================================================================

void ActionRecommenderProcess::append_u32_le(std::vector<uint8_t>& buf, uint32_t v) {
    size_t n = buf.size();
    buf.resize(n + 4);
    buf[n+0] = static_cast<uint8_t>(v & 0xff);
    buf[n+1] = static_cast<uint8_t>((v >> 8) & 0xff);
    buf[n+2] = static_cast<uint8_t>((v >> 16) & 0xff);
    buf[n+3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void ActionRecommenderProcess::append_u64_le(std::vector<uint8_t>& buf, uint64_t v) {
    size_t n = buf.size();
    buf.resize(n + 8);
    for (int i = 0; i < 8; ++i) {
        buf[n+i] = static_cast<uint8_t>((v >> (8*i)) & 0xff);
    }
}

uint32_t ActionRecommenderProcess::read_u32_le(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ActionRecommenderProcess::read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8*i);
    }
    return v;
}

// =====================================================================
// ActionRecommendation wire serialization
// =====================================================================
//
// Wire format (little-endian):
//   [u32 action_type_len][action_type bytes]
//   [i32 target_pid]
//   [u32 target_path_len][target_path bytes]
//   [u32 rule_id_len][rule_id bytes]
//   [i32 severity]
//   [u32 reason_len][reason bytes]
//
// Max ~4 KB for a typical recommendation (action_type < 16B,
// rule_id < 64B, reason < 256B).

void ActionRecommenderProcess::append_recommendation(std::vector<uint8_t>& buf,
                                                      const ActionRecommendation& rec) {
    auto put_str = [&](const std::string& s) {
        append_u32_le(buf, static_cast<uint32_t>(s.size()));
        buf.insert(buf.end(), s.begin(), s.end());
    };
    put_str(rec.action_type);
    append_u32_le(buf, static_cast<uint32_t>(rec.target_pid));
    put_str(rec.target_path);
    put_str(rec.rule_id);
    append_u32_le(buf, static_cast<uint32_t>(rec.severity));
    put_str(rec.reason);
}

bool ActionRecommenderProcess::read_recommendation(const uint8_t* p, size_t len, size_t* off,
                                                    ActionRecommendation& out) {
    auto get_str = [&](std::string& s) -> bool {
        if (*off + 4 > len) return false;
        uint32_t l = read_u32_le(p + *off); *off += 4;
        if (*off + l > len) return false;
        s.assign(reinterpret_cast<const char*>(p + *off), l); *off += l;
        return true;
    };
    if (!get_str(out.action_type)) return false;
    if (*off + 4 > len) return false;
    out.target_pid = static_cast<int32_t>(read_u32_le(p + *off)); *off += 4;
    if (!get_str(out.target_path)) return false;
    if (!get_str(out.rule_id)) return false;
    if (*off + 4 > len) return false;
    out.severity = static_cast<int32_t>(read_u32_le(p + *off)); *off += 4;
    if (!get_str(out.reason)) return false;
    return true;
}

// =====================================================================
// IPC primitives
// =====================================================================

bool ActionRecommenderProcess::send_frame(int fd, uint8_t type, const void* payload, uint32_t len) {
    if (len > MSG_MAX_PAYLOAD) {
        std::fprintf(stderr, "[action_recommender] send_frame: payload %u > MSG_MAX_PAYLOAD %u\n",
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
        if (errno == EPIPE) return false;  // child closed
        std::fprintf(stderr, "[action_recommender] send(header) failed: %s\n",
                     std::strerror(errno));
        return false;
    }
    if (n != MSG_HEADER_SIZE) {
        std::fprintf(stderr, "[action_recommender] send(header) short: %zd\n", n);
        return false;
    }
    if (len > 0) {
        ssize_t n2 = ::send(fd, payload, len, MSG_NOSIGNAL);
        if (n2 < 0) {
            if (errno == EINTR) return send_frame(fd, type, payload, len);
            if (errno == EPIPE) return false;
            std::fprintf(stderr, "[action_recommender] send(payload) failed: %s\n",
                         std::strerror(errno));
            return false;
        }
        if (n2 != static_cast<ssize_t>(len)) {
            std::fprintf(stderr, "[action_recommender] send(payload) short: %zd\n", n2);
            return false;
        }
    }
    return true;
}

bool ActionRecommenderProcess::recv_frame(int fd, uint8_t* out_type, std::vector<uint8_t>& out_payload) {
    uint8_t header[MSG_HEADER_SIZE];
    ssize_t n = ::recv(fd, header, MSG_HEADER_SIZE, 0);
    if (n == 0) return false;  // EOF
    if (n < 0) {
        if (errno == EINTR) return recv_frame(fd, out_type, out_payload);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            errno = EAGAIN;  // normalize, caller distinguishes
            return false;
        }
        std::fprintf(stderr, "[action_recommender] recv(header) failed: %s\n",
                     std::strerror(errno));
        return false;
    }
    if (n != MSG_HEADER_SIZE) {
        std::fprintf(stderr, "[action_recommender] recv(header) short: %zd\n", n);
        return false;
    }
    *out_type = header[0];
    uint32_t length = read_u32_le(header + 1);
    if (length > MSG_MAX_PAYLOAD) {
        std::fprintf(stderr, "[action_recommender] recv: length %u > MSG_MAX_PAYLOAD %u\n",
                     length, MSG_MAX_PAYLOAD);
        // Drain the oversized payload
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
            std::fprintf(stderr, "[action_recommender] recv(payload) failed: %s\n",
                         std::strerror(errno));
            return false;
        }
        if (n2 != static_cast<ssize_t>(length)) {
            std::fprintf(stderr, "[action_recommender] recv(payload) short: %zd\n", n2);
            return false;
        }
    }
    return true;
}

bool ActionRecommenderProcess::send_simple(int fd, uint8_t type) {
    return send_frame(fd, type, nullptr, 0);
}

bool ActionRecommenderProcess::send_u64(int fd, uint8_t type, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>((v >> (8*i)) & 0xff);
    return send_frame(fd, type, buf, 8);
}

// =====================================================================
// Fork / setuid
// =====================================================================

bool ActionRecommenderProcess::start() {
    std::lock_guard<std::mutex> lk(mu_);
    return ensure_child_locked();
}

bool ActionRecommenderProcess::ensure_child_locked() {
    // Fast path: child still alive?
    if (child_pid_ > 0) {
        int status = 0;
        pid_t r = ::waitpid(child_pid_, &status, WNOHANG);
        if (r == 0) return true;
        if (r == child_pid_) {
            std::fprintf(stderr, "[action_recommender] child pid=%d exited (status=%d), re-forking\n",
                         static_cast<int>(child_pid_), WEXITSTATUS(status));
            child_pid_ = -1;
            if (parent_fd_ >= 0) { ::close(parent_fd_); parent_fd_ = -1; }
        }
    }

    int sv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) {
        std::fprintf(stderr, "[action_recommender] socketpair() failed: %s\n",
                     std::strerror(errno));
        return false;
    }

    // SO_RCVTIMEO + SO_SNDTIMEO 1s. 1 channel, no contention, 1s is fine.
    struct timeval to = { 1, 0 };
    if (::setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to)) != 0 ||
        ::setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to)) != 0) {
        std::fprintf(stderr, "[action_recommender] setsockopt failed: %s\n",
                     std::strerror(errno));
        ::close(sv[0]); ::close(sv[1]);
        return false;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        std::fprintf(stderr, "[action_recommender] fork() failed: %s\n",
                     std::strerror(errno));
        ::close(sv[0]); ::close(sv[1]);
        return false;
    }

    if (pid == 0) {
        // ----- CHILD -----
        ::close(sv[0]);
        child_entry(sv[1], cfg_);
        ::_exit(0);
    }

    // ----- PARENT -----
    ::close(sv[1]);
    parent_fd_ = sv[0];
    child_pid_ = pid;
    restarts_  = 0;
    std::fprintf(stderr, "[action_recommender] child started, pid=%d "
                 "(will drop to %s:%s)\n",
                 static_cast<int>(child_pid_),
                 cfg_.wal_user.c_str(), cfg_.wal_group.c_str());
    return true;
}

void ActionRecommenderProcess::child_entry(int fd, Config cfg) {
    // Drop privileges. Order is strict (lesson #5).
    // T13.5 noise fix (2026-06-17): use cached getpwnam_r via
    // logsoc::resolve_user_group.
    auto ug = logsoc::resolve_user_group(cfg.wal_user, cfg.wal_group);
    if (!ug.valid) {
        std::fprintf(stderr, "[action_recommender/child] getpwnam(%s) failed\n",
                     cfg.wal_user.c_str());
        ::_exit(1);
    }
    if (::setgroups(0, nullptr) != 0 ||
        ::setgid(ug.gid) != 0 ||
        ::setuid(ug.uid) != 0) {
        std::fprintf(stderr, "[action_recommender/child] setuid/setgid failed: %s\n",
                     std::strerror(errno));
        ::_exit(1);
    }

    // Double-parens defeat MVP (lesson #1).
    ActionRecommenderProcess instance((Config(cfg)));
    instance.child_main(fd, cfg);
    std::fflush(stderr);
    ::_exit(0);
}

void ActionRecommenderProcess::child_main(int fd, const Config& cfg) {
    std::fprintf(stderr, "[action_recommender/child] uid=%d gid=%d "
                 "severity_threshold=%d\n",
                 static_cast<int>(::geteuid()),
                 static_cast<int>(::getegid()),
                 cfg.severity_threshold);
    std::fflush(stderr);

    // IPC loop. 1 channel, request-reply.
    uint64_t local_events_seen = 0;
    uint64_t local_recommendations_sent = 0;

    while (!stop_requested_.load()) {
        uint8_t type;
        std::vector<uint8_t> payload;
        if (!recv_frame(fd, &type, payload)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;  // idle tick
            // EOF or hard error
            std::fprintf(stderr, "[action_recommender/child] channel closed (errno=%d), exiting\n",
                         errno);
            std::fflush(stderr);
            break;
        }
        try {
            switch (type) {
                case 0x10: {  // PUSH_EVENT
                    local_events_seen++;
                    // Parse JSON event
                    std::string event_json(payload.begin(), payload.end());
                    nlohmann::json ev;
                    try {
                        ev = nlohmann::json::parse(event_json);
                    } catch (const std::exception& e) {
                        std::fprintf(stderr, "[action_recommender/child] JSON parse failed: %s\n",
                                     e.what());
                        std::fflush(stderr);
                        (void)send_simple(fd, 0x80);  // ACK even on parse error
                        break;
                    }

                    // Extract features for severity::score
                    logsoc::agent::severity::ScoreFeatures sf;
                    sf.event_type   = ev.value("event_type", 0u);
                    sf.comm         = ev.value("comm", std::string());
                    sf.path         = ev.value("path", std::string());
                    sf.uid          = ev.value("uid", 0u);
                    sf.dst_port     = ev.value("dst_port", 0u);
                    sf.mitre_count  = ev.value("mitre_count", 0u);
                    int score = logsoc::agent::severity::score(sf);
                    const char* sev = logsoc::agent::severity::score_to_severity(score);

                    if (score >= cfg.severity_threshold) {
                        // Critical! Build recommendation.
                        ActionRecommendation rec;
                        rec.action_type = "kill_pid";
                        rec.target_pid  = ev.value("pid", 0);
                        rec.target_path = ev.value("path", std::string());
                        rec.rule_id     = ev.value("rule_id", std::string("severity_threshold"));
                        rec.severity    = score;
                        rec.reason      = std::string("severity=") + sev +
                                          " rule=" + rec.rule_id;

                        std::vector<uint8_t> rec_buf;
                        append_recommendation(rec_buf, rec);
                        if (send_frame(fd, 0x81, rec_buf.data(),
                                        static_cast<uint32_t>(rec_buf.size()))) {
                            local_recommendations_sent++;
                            std::fprintf(stderr, "[action_recommender/child] RECOMMENDATION sent: "
                                         "action=%s pid=%d severity=%d reason=%s\n",
                                         rec.action_type.c_str(), rec.target_pid,
                                         rec.severity, rec.reason.c_str());
                            std::fflush(stderr);
                        }
                    }

                    (void)send_simple(fd, 0x80);  // ACK
                    break;
                }
                case 0x11: {  // GET_STATS
                    std::vector<uint8_t> body;
                    append_u64_le(body, local_events_seen);
                    append_u64_le(body, local_recommendations_sent);
                    if (!send_frame(fd, 0x82, body.data(),
                                     static_cast<uint32_t>(body.size()))) {
                        std::fprintf(stderr, "[action_recommender/child] STATS_RESP send failed\n");
                        std::fflush(stderr);
                    }
                    break;
                }
                case 0x12: {  // STOP
                    (void)send_simple(fd, 0x83);  // STOP_OK
                    stop_requested_.store(true);
                    break;
                }
                default: {
                    std::fprintf(stderr, "[action_recommender/child] unknown type=0x%02x\n",
                                 static_cast<unsigned>(type));
                    std::fflush(stderr);
                    std::vector<uint8_t> err(4);
                    int32_t e = EINVAL;
                    err[0] = static_cast<uint8_t>(e & 0xff);
                    err[1] = static_cast<uint8_t>((e >> 8) & 0xff);
                    err[2] = static_cast<uint8_t>((e >> 16) & 0xff);
                    err[3] = static_cast<uint8_t>((e >> 24) & 0xff);
                    (void)send_frame(fd, 0x8F, err.data(), 4);
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[action_recommender/child] dispatch exception: %s\n", e.what());
            std::fflush(stderr);
        }
    }

    std::fprintf(stderr, "[action_recommender/child] loop exited, closing fd\n");
    std::fflush(stderr);
    ::close(fd);
}

// =====================================================================
// Drop-in API (parent side)
// =====================================================================

bool ActionRecommenderProcess::push_event(const std::string& event_json) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!ensure_child_locked()) return false;
    if (parent_fd_ < 0) return false;
    if (event_json.size() > MSG_MAX_PAYLOAD) {
        std::fprintf(stderr, "[action_recommender] push_event: json %zu > MSG_MAX_PAYLOAD %u\n",
                     event_json.size(), MSG_MAX_PAYLOAD);
        return false;
    }
    if (!send_frame(parent_fd_, 0x10, event_json.data(),
                     static_cast<uint32_t>(event_json.size()))) {
        return false;
    }
    uint8_t type;
    std::vector<uint8_t> payload;
    if (!recv_frame(parent_fd_, &type, payload)) {
        if (errno == EAGAIN) return false;
        return false;
    }
    return type == 0x80;  // ACK
}

bool ActionRecommenderProcess::pop_recommendation(ActionRecommendation& out) {
    std::lock_guard<std::mutex> lk(inbound_mtx_);
    if (inbound_recs_.empty()) return false;
    out = std::move(inbound_recs_.front());
    inbound_recs_.erase(inbound_recs_.begin());
    return true;
}

size_t ActionRecommenderProcess::recommendation_queue_depth() const {
    std::lock_guard<std::mutex> lk(inbound_mtx_);
    return inbound_recs_.size();
}

void ActionRecommenderProcess::stop() {
    pid_t pid_to_kill = -1;
    int   fd_to_close = -1;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (child_pid_ <= 0 && parent_fd_ < 0) return;
        stop_requested_.store(true);
        pid_to_kill  = child_pid_;
        fd_to_close  = parent_fd_;
        child_pid_   = -1;
        parent_fd_   = -1;
    }

    if (fd_to_close >= 0) {
        (void)send_simple(fd_to_close, 0x12);  // STOP
    }

    if (pid_to_kill > 0) {
        int status = 0;
        for (int i = 0; i < 20; ++i) {
            pid_t r = ::waitpid(pid_to_kill, &status, WNOHANG);
            if (r == pid_to_kill) goto done;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::fprintf(stderr, "[action_recommender] child did not exit after 2s, SIGTERM\n");
        ::kill(pid_to_kill, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            pid_t r = ::waitpid(pid_to_kill, &status, WNOHANG);
            if (r == pid_to_kill) goto done;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::fprintf(stderr, "[action_recommender] SIGTERM+2s timeout, SIGKILL\n");
        ::kill(pid_to_kill, SIGKILL);
        ::waitpid(pid_to_kill, &status, 0);
    }
done:
    if (fd_to_close >= 0) ::close(fd_to_close);
}

}  // namespace action_recommender
