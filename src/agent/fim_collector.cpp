// fim_collector.cpp — T4.8.5 — FIM event orchestrator (impl)
#include "fim_collector.hpp"

#include <algorithm>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

using namespace std::chrono_literals;

namespace logsoc::agent::fim {

// v4.8.0 (T4.8 hotfix): fallback path resolver. When the write_fd kprobe
// does not fire (kernel optimization, missing kprobe, etc.) we still
// need to ship something useful. Try to resolve the basename via the
// process's CWD symlink: /proc/<pid>/cwd/<basename>. If the file exists
// there, return that absolute path. Returns empty string if not found.
//
// This is best-effort and never blocks: readlinkat on a missing file
// returns ENOENT immediately, not a hang.
// M-10 audit fix: reject basename containing path traversal characters.
// A basename with "/" could escape the /proc/<pid>/cwd/ prefix via "../",
// and null bytes can truncate the path silently.
static bool is_basename_safe(const std::string& basename) {
    if (basename.empty()) return false;
    if (basename.find('/') != std::string::npos) return false;
    if (basename.find("..") != std::string::npos) return false;
    if (basename.find('\0') != std::string::npos) return false;
    return true;
}

static std::string resolve_via_cwd(uint32_t pid, const std::string& basename) {
    // M-10: reject basenames that could cause path traversal
    if (!is_basename_safe(basename)) return "";
    char linkpath[64];
    std::snprintf(linkpath, sizeof(linkpath), "/proc/%u/cwd/%s",
                  pid, basename.c_str());
    // Quick stat: does the file exist at this path?
    struct stat st;
    if (::stat(linkpath, &st) != 0) return "";  // ENOENT/EACCES/etc.
    if (!S_ISREG(st.st_mode)) return "";        // not a regular file
    return std::string(linkpath);
}

FimCollector::FimCollector(const Config& cfg, fd::FdResolver& resolver)
    : cfg_(cfg), resolver_(resolver) {
    if (cfg_.enable_watchdog) {
        watchdog_ = std::thread(&FimCollector::watchdog_loop, this);
    }
}

FimCollector::~FimCollector() {
    stop_.store(true);
    ship_cv_.notify_all();
    if (watchdog_.joinable()) watchdog_.join();
}

std::string FimCollector::merge_key(uint32_t pid, const std::string& basename) {
    // Cheap hash key for the pending map. Avoids std::pair hashing.
    return std::to_string(pid) + ":" + basename;
}

bool FimCollector::try_acquire_token(uint32_t pid) {
    std::lock_guard<std::mutex> lock(rate_mtx_);
    auto& b = buckets_[pid];
    if (b.last_refill.time_since_epoch().count() == 0) {
        // First time we see this pid: start with a full bucket.
        b.tokens = (double)cfg_.rate_limit_per_pid_per_sec;
        b.last_refill = std::chrono::steady_clock::now();
    }
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - b.last_refill).count();
    b.tokens = std::min((double)cfg_.rate_limit_per_pid_per_sec,
                        b.tokens + elapsed * cfg_.rate_limit_per_pid_per_sec);
    b.last_refill = now;
    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    return false;
}

bool FimCollector::pop_ship_event(FimEvent& out, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(ship_mtx_);
    if (!ship_cv_.wait_for(lock, timeout, [this] { return !ship_queue_.empty() || stop_.load(); })) {
        return false;
    }
    if (stop_.load() && ship_queue_.empty()) return false;
    out = std::move(ship_queue_.front());
    ship_queue_.pop_front();
    return true;
}

void FimCollector::publish_external(FimEvent ev) {
    // Tag the resolution so the UI can tell this came from the poller fallback
    if (ev.resolution.empty()) ev.resolution = "poller_fallback";
    // Make sure path field is set
    if (ev.abs_path.empty() && !ev.basename.empty()) ev.abs_path = ev.basename;
    // Enqueue into the ship queue (the FimShipper thread will pop and ship).
    // Bypass rate limit and merge window — this is a fallback path.
    {
        std::lock_guard<std::mutex> lock(ship_mtx_);
        if ((int)ship_queue_.size() >= cfg_.ship_queue_capacity) {
            // Drop oldest to make room
            ship_queue_.pop_front();
            dropped_.fetch_add(1);
        }
        ship_queue_.push_back(std::move(ev));
    }
    ship_cv_.notify_one();
}

bool FimCollector::on_fim_event(uint32_t pid, const std::string& basename,
                                 uint64_t ktime_ns, const char* operation) {
    if (!try_acquire_token(pid)) {
        rate_limited_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    auto key = merge_key(pid, basename);
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(merge_mtx_);
        // Check if a matching write_fd is already pending
        auto it = pending_fim_.find(key);
        if (it != pending_fim_.end()) {
            // T4.8.22 BUGFIX: previous code published a SINGLE event with
            // abs_path=basename (the basename alone, not the resolved path)
            // and relied on a "the resolver will overwrite" comment that
            // was never true — the resolver had already fired and the
            // write_fd was sitting in pending_fim_, not in flight. The
            // result was a "fake resolved" event with the wrong path
            // (the basename, not /etc/passwd).
            //
            // Fix: this path is the FIM-write_fd merge — the write_fd
            // has already been resolved (or failed) by the time we got
            // here. The pending_fim_ entry holds the operation that was
            // captured at on_write_fd_event time. We publish the event
            // with abs_path from the FimEvent stored alongside.
            //
            // BUT: the on_write_fd_event does NOT store an FimEvent in
            // pending_fim_, it only stores {received_at, operation}.
            // So we cannot recover the abs_path. To preserve correctness,
            // we publish with abs_path=basename (best we have) and a
            // clear "pending_fd" resolution tag so consumers know the
            // path was NOT resolved by /proc lookup.
            FimEvent ev;
            ev.basename = basename;
            ev.pid = pid;
            ev.ktime_ns = ktime_ns;
            std::snprintf(ev.operation, sizeof(ev.operation), "%s", operation);
            ev.abs_path = "<merged:" + basename + ">";
            ev.resolution = "pending_fd";
            ev.enqueued_at = std::chrono::system_clock::now();
            // MITRE tag from the abs_path (preferred) or fallback to basename
            // MITRE tagging retiré — le backend calcule côté serveur. Voir issue #40.
            pending_fim_.erase(it);
            publish(std::move(ev));
            merged_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        // No match: store this fim as pending, wait for write_fd
        pending_fim_[key] = PendingFim{now, operation};
    }
    return true;
}

bool FimCollector::on_write_fd_event(uint32_t pid, int fd, uint64_t ktime_ns) {
    if (!try_acquire_token(pid)) {
        rate_limited_.fetch_add(1);
        return false;
    }
    // T4.8.21: capture a pending fim basename for this pid (if any)
    // BEFORE submitting to the resolver. If the resolver fails (CB
    // OPEN, ENOENT, empty), we publish the event with the captured
    // basename + `<no_fd_resolved:...>` tag, instead of losing the
    // basename by overwriting with `<unknown>`. The merge window is
    // 100ms, so a write_fd that arrives > 100ms after its fim will
    // not find a pending match — that's the case we still mark
    // `<unknown>` (correct: we have no info).
    std::string pending_basename;
    {
        std::lock_guard<std::mutex> lock(merge_mtx_);
        // Look for ANY pending fim with this pid (any basename)
        // The merge key is "pid:basename", so we scan for pid: prefix
        std::string prefix = std::to_string(pid) + ":";
        for (auto& kv : pending_fim_) {
            if (kv.first.compare(0, prefix.size(), prefix) == 0) {
                pending_basename = kv.first.substr(prefix.size());
                break;
            }
        }
    }
    // Submit to FdResolver. The callback will publish to the ship queue.
    auto req = fd::ResolveRequest{
        (uint32_t)pid, fd, ktime_ns,
        [this, pending_basename](uint32_t pid_cb, [[maybe_unused]] int fd_cb, uint64_t ktime_cb,
               const std::string& abs_path, bool ok) {
            FimEvent ev;
            ev.pid = pid_cb;
            ev.ktime_ns = ktime_cb;
            ev.abs_path = abs_path;
            if (abs_path.empty() && !pending_basename.empty()) {
                // T4.8.21: fallback to pending basename (from the matching
                // fim event). Without this, every unresolved event was
                // marked `<unknown>`, losing the basename information
                // entirely.
                ev.basename = pending_basename;
                ev.abs_path = "<no_fd_resolved:" + pending_basename + ">";
                ev.resolution = "no_fim";
            } else {
                ev.basename = abs_path;
                // Extract basename from abs_path
                auto pos = ev.basename.find_last_of('/');
                if (pos != std::string::npos) {
                    ev.basename = ev.basename.substr(pos + 1);
                }
                if (ev.basename.empty()) ev.basename = "<unknown>";
                ev.resolution = ok ? "ok" : "cb_open";
            }
            std::snprintf(ev.operation, sizeof(ev.operation), "write");
            ev.enqueued_at = std::chrono::system_clock::now();
            // T4.8.21: MITRE tagging needs the abs_path (e.g. "/etc/passwd")
            // to match the rule patterns. We try abs_path first, then fall
            // back to the basename. The first non-empty result wins.
            // This restores the t4.8.20 behavior where tag("/etc/passwd")
            // → T1003.008.
            // MITRE tagging retiré — le backend calcule côté serveur. Voir issue #40.
            // Garbage-collect old pending entries (older than merge window)
            {
                std::lock_guard<std::mutex> lock(merge_mtx_);
                garbage_collect_pending();
            }
            publish(std::move(ev));
        }
    };
    return resolver_.submit(req);
}

void FimCollector::garbage_collect_pending() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - cfg_.fim_window;
    for (auto it = pending_fim_.begin(); it != pending_fim_.end();) {
        if (it->second.received_at < cutoff) {
            // Fim event arrived but no matching write_fd: try fallback.
            // v4.8.0 (T4.8 hotfix): if write_fd never came (kernel
            // optimization, missing kprobe), try resolving via /proc/<pid>/cwd
            // before giving up with a generic "<no_fd_resolved>" tag.
            //
            // T4.8.22 BUGFIX: the previous code did
            //   uint32_t pid_val = std::stoul(it->first);
            // but it->first is the merge key "pid:basename" (e.g.
            // "1234:passwd"), so std::stoul throws std::invalid_argument
            // on the first call (stoul stops at ':'). This made the
            // very first GC iteration std::terminate the agent.
            //
            // Fix: split on ':' to extract the pid prefix. Falls back
            // to 0 (unknown pid) if the key is malformed, instead of
            // throwing.
            std::string basename;
            uint32_t pid_val = 0;
            auto colon = it->first.find(':');
            if (colon != std::string::npos) {
                basename = it->first.substr(colon + 1);
                try {
                    pid_val = static_cast<uint32_t>(
                        std::stoul(it->first.substr(0, colon)));
                } catch (...) {
                    pid_val = 0;  // malformed key — best effort
                }
            } else {
                basename = it->first;  // legacy / fallback
            }
            std::string resolved = resolve_via_cwd(pid_val, basename);
            FimEvent ev;
            ev.basename = basename;
            ev.pid = pid_val;
            if (!resolved.empty()) {
                ev.abs_path = resolved;
                ev.resolution = "cwd_fallback";
            } else {
                ev.abs_path = "<no_fd_resolved:" + basename + ">";
                ev.resolution = "no_fim";
            }
            std::snprintf(ev.operation, sizeof(ev.operation), "%s",
                          it->second.operation.c_str());
            ev.enqueued_at = std::chrono::system_clock::now();
            // T12 audit fix #17: prefer ev.abs_path (resolved) over
            // basename. MITRE_RULES patterns are full paths like
            // "/etc/passwd" or "/etc/shadow" — they don't match
            // basename-only "passwd" or "shadow". Tag the resolved
            // path first (which is the cwd_fallback result or the
            // synthetic "<no_fd_resolved:basename>" marker), then
            // fall back to basename as a safety net.
            // MITRE tagging retiré — le backend calcule côté serveur. Voir issue #40.
            it = pending_fim_.erase(it);
            publish(std::move(ev));
        } else {
            ++it;
        }
    }
}

void FimCollector::publish(FimEvent ev) {
    {
        std::lock_guard<std::mutex> lock(ship_mtx_);
        if ((int)ship_queue_.size() >= cfg_.ship_queue_capacity) {
            // Drop oldest to make room (FIM events are time-sensitive,
            // newer is more relevant than older)
            ship_queue_.pop_front();
            dropped_.fetch_add(1);
        }
        ship_queue_.push_back(std::move(ev));
    }
    ship_cv_.notify_one();
}

void FimCollector::watchdog_loop() {
    while (!stop_.load()) {
        for (int i = 0; i < (int)cfg_.watchdog_period.count() * 10 && !stop_.load(); ++i) {
            std::this_thread::sleep_for(100ms);
        }
        if (stop_.load()) break;
        // T4.8.20 PHASE 2 fix: garbage-collect pending fim events
        // whose write_fd never arrived (e.g. kernel 6.8 static_call
        // optimization skips sys_write kprobe for SSH-launched root
        // processes — see MEMORY card #65 / T4.8.8). Without this,
        // pending_fim_ grows indefinitely with events that have no
        // write_fd partner, until a coincidental merge key match
        // triggers garbage_collect_pending() in a callback.
        {
            std::lock_guard<std::mutex> lock(merge_mtx_);
            garbage_collect_pending();
        }
        // Emit a watchdog ping
        FimEvent ev;
        ev.abs_path = "<watchdog>";
        ev.basename = "<watchdog>";
        ev.pid = 0;
        ev.ktime_ns = 0;
        std::snprintf(ev.operation, sizeof(ev.operation), "watchdog");
        ev.resolution = "alive";
        ev.enqueued_at = std::chrono::system_clock::now();
        publish(std::move(ev));
        wdog_pings_.fetch_add(1);
    }
}

size_t FimCollector::ship_queue_depth() const {
    std::lock_guard<std::mutex> lock(ship_mtx_);
    return ship_queue_.size();
}

size_t FimCollector::merge_queue_depth() const {
    std::lock_guard<std::mutex> lock(merge_mtx_);
    return pending_fim_.size();
}

}  // namespace logsoc::agent::fim
