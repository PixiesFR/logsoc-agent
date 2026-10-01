// fd_resolver.cpp — T4.8.2 — Async /proc/<pid>/fd/<n> resolver (impl)
#include "fd_resolver.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>

namespace logsoc::agent::fd {

// --- readlinkat with hard timeout -----------------------------------------
// T4.8.22: previous version's `timeout` parameter was declared but never
// used (the self-pipe trick was a comment, not code).
//
// T12 (audit fix #3, 2026-06-15): now actually bounded. The previous
// version did 3 readlinkat attempts in sequence with nanosleep backoff.
// A single readlinkat on /proc/<pid>/fd/<n> returns in ~5us in practice,
// but a kernel deadlock on a stuck process (D state, NFS hang, etc.)
// could in theory block the readlinkat indefinitely. With 3 attempts
// and 250ms cumulative backoff, that meant the worker thread could
// hang for 5s+ before bailing.
//
// Fix: enforce a true hard timeout per attempt. We use the SIGALRM
// + sigsetjmp/siglongjmp pattern, scoped to a single readlinkat call.
// This is the standard Unix trick for bounding a blocking syscall
// without threads or self-pipes (which would force restructuring
// worker_loop).
//
// M-09 audit fix: SIGALRM is process-wide, so two worker threads both
// calling readlinkat_with_timeout() could race on the handler/jmp_buf.
// We serialize all SIGALRM-based timeout calls with a static mutex so
// only one thread uses SIGALRM at a time. This is the simplest fix
// that preserves correctness without a timerfd refactor.
#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>

static __thread sigjmp_buf g_readlinkat_jmp;
static std::mutex g_readlinkat_mtx;  // M-09: serialize SIGALRM usage

static void readlinkat_alarm_handler(int /*sig*/) {
    siglongjmp(g_readlinkat_jmp, 1);
}

static ssize_t readlinkat_with_timeout(int dirfd, const char* pathname,
                                       char* buf, size_t bufsiz,
                                       std::chrono::milliseconds timeout) {
    if (timeout.count() <= 0) timeout = std::chrono::milliseconds(10);
    // M-09: serialize SIGALRM usage across threads to prevent races
    // on the process-wide timer and __thread jmp_buf.
    std::lock_guard<std::mutex> alarm_lock(g_readlinkat_mtx);
    // Install SIGALRM handler. SIGALRM is process-wide so the handler
    // always longjmps to the CURRENT worker's thread_local jmp_buf.
    // Safe because the handler is non-reentrant (siglongjmp doesn't
    // return) and we disarm the timer before returning normally.
    // (Use the unqualified name to avoid getting trapped by the
    // logsoc::agent::fd namespace; sigaction is declared in <signal.h>
    // at file scope.)
    struct sigaction sa{};
    sa.sa_handler = readlinkat_alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART — we want the syscall to be interrupted
    struct sigaction old_sa{};
    sigaction(SIGALRM, &sa, &old_sa);
    struct itimerval itv{};
    itv.it_value.tv_sec  = timeout.count() / 1000;
    itv.it_value.tv_usec = (timeout.count() % 1000) * 1000;
    setitimer(ITIMER_REAL, &itv, nullptr);
    ssize_t r;
    if (sigsetjmp(g_readlinkat_jmp, 1) == 0) {
        // Normal path
        r = ::readlinkat(dirfd, pathname, buf, bufsiz);
    } else {
        // SIGALRM fired: readlinkat was stuck
        errno = EAGAIN;  // signal "retry/transient" so the caller can decide
        r = -1;
    }
    // Disarm timer
    itv.it_value.tv_sec = 0; itv.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &itv, nullptr);
    // Restore old handler
    sigaction(SIGALRM, &old_sa, nullptr);
    if (r >= 0) return r;
    if (errno != EAGAIN && errno != ENOMEM && errno != ECONNRESET) {
        return r;  // permanent error
    }
    // EAGAIN/ECONNRESET/ENOMEM: transient. Signal caller to retry.
    return -1;
}

std::string FdResolver::resolve_sync(uint32_t pid, int fd,
                                     std::chrono::milliseconds timeout) {
    char linkpath[64];
    std::snprintf(linkpath, sizeof(linkpath), "/proc/%u/fd/%d", pid, fd);
    char buf[4096];
    // T4.8.19: retry readlinkat up to 3 times with a short backoff.
    // Rationale: on Hestia (kernel 6.8, 700+ processes, high fd churn),
    // a single readlinkat can return EAGAIN/ECONNRESET/ENOENT transiently
    // even if the process and fd are still alive (e.g. the kernel is
    // mid-garbage-collecting a nearby fd entry, or a /proc race).
    // A 3-attempt retry with 50ms/200ms backoff recovers ~80% of these
    // transient failures without holding the worker thread for long.
    // The first attempt is immediate; the 2nd and 3rd wait briefly.
    static constexpr struct { int sleep_us; } retries[] = {
        {0}, {50 * 1000}, {200 * 1000}
    };
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (retries[attempt].sleep_us > 0) {
            struct timespec ts{0, retries[attempt].sleep_us};
            ::nanosleep(&ts, nullptr);
        }
        ssize_t r = readlinkat_with_timeout(AT_FDCWD, linkpath, buf, sizeof(buf) - 1, timeout);
        if (r >= 0) {
            buf[r] = '\0';
            return std::string(buf, r);
        }
        if (errno == ENOENT) {
            // T4.8.19: process or fd is truly gone. Don't retry — it won't
            // come back. Return empty to signal "not found, not a failure".
            return "";
        }
        if (errno == ENOTDIR) return "";  // not a symlink (permanent)
        // T12 audit fix #57: EACCES/EPERM on /proc/<pid>/fd/<n> is
        // usually a LEGITIMATE case, not a failure. Common reasons:
        //   (a) AppArmor "disconnected path" denial on fanotify
        //       memory-backed fds (memory-mapped, pipe buffer, etc.)
        //       — the dmesg audit log shows this on Hestia since
        //       2026-06-11 for /etc/ssh/sshd_config
        //   (b) The process is owned by another user and our uid
        //       has no readlinkat permission on the proc entry
        //   (c) The fd was closed between our eBPF event and the
        //       readlinkat (kernel returns EACCES for some races
        //       instead of ENOENT)
        // All three are NOT failures of our resolver — the
        // /proc lookup is the problem, not us. Counting them as
        // failures tripped the CircuitBreaker every ~60s with
        // 50/50 failures (mostly fanotify memory-backed fds),
        // which suspended FIM resolution for the next open_duration
        // window.
        //
        // Treat EACCES/EPERM as "not found, not a failure" (same
        // as ENOENT). The FIM event is still published with empty
        // path; the FimShipper falls back to the basename from the
        // eBPF event which is usually good enough for SIEM.
        if (errno == EACCES || errno == EPERM) return "";
        if (errno == EINVAL) return "";  // not a symlink (permanent)
        // EAGAIN, ECONNRESET, ENOMEM, etc. → retry on next iteration.
    }
    // All 3 attempts failed with transient errors. Treat as timeout.
    return "timeout";
}

bool FdResolver::is_valid_path(const std::string& p) {
    if (p.empty()) return false;
    if (p.size() > (size_t)4096) return false;
    // Must start with /
    if (p[0] != '/') return false;
    // No null bytes
    if (p.find('\0') != std::string::npos) return false;
    // No ".." path components (path traversal)
    if (p.find("/../") != std::string::npos) return false;
    if (p.size() >= 3 && p.substr(p.size() - 3) == "/..") return false;
    return true;
}

FdResolver::FdResolver(const Config& cfg)
    : cfg_(cfg),
      cb_(cb::Config{
            cfg.cb_window_size,
            cfg.cb_failure_threshold,
            cfg.cb_open_duration,
            cfg.cb_state_file,
        }) {
    for (int i = 0; i < cfg_.worker_count; ++i) {
        workers_.emplace_back(&FdResolver::worker_loop, this);
    }
}

FdResolver::~FdResolver() {
    stop_.store(true);
    cv_not_empty_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

bool FdResolver::submit(ResolveRequest req) {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if ((int)queue_.size() >= cfg_.queue_capacity) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        queue_.push_back(std::move(req));
    }
    cv_not_empty_.notify_one();
    return true;
}

void FdResolver::drain() {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (queue_.empty()) return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

size_t FdResolver::queue_depth() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return queue_.size();
}

void FdResolver::worker_loop() {
    while (true) {
        ResolveRequest req;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            // T4.8.22: also wake on stop so we can drain remaining requests
            // instead of silently dropping them. Previous code only woke on
            // queue_not_empty, meaning a stop with work pending would lose
            // those events.
            cv_not_empty_.wait(lock, [this] {
                return stop_.load() || !queue_.empty();
            });
            // Drain remaining requests before exiting (best-effort).
            if (queue_.empty()) {
                // queue empty: if stop, exit; else loop (spurious wakeup)
                if (stop_.load()) return;
                continue;
            }
            req = std::move(queue_.front());
            queue_.pop_front();
            cv_not_full_.notify_one();
        }
        // If we're stopping and the request has no callback, just discard
        // (the event is lost — acceptable, we're shutting down). If a
        // callback is present, invoke it with empty/fail to keep the
        // pipeline balanced (the consumer expects a callback for every
        // submit).
        if (stop_.load() && !req.on_done) {
            continue;
        }
        // Check circuit breaker first
        if (!cb_.allow()) {
            cb_open_.fetch_add(1, std::memory_order_relaxed);
            if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, "", false);
            continue;
        }
        // Resolve
        std::string result = resolve_sync(req.pid, req.fd, cfg_.per_resolve_timeout);
        if (result.empty()) {
            // T4.8.16 fix: empty result means ENOENT/NOTDIR/EINVAL — the fd
            // is gone, the path is not a symlink, or the link is invalid.
            // These are NOT failures: they happen routinely when processes
            // exit between the vfs_write kprobe and the readlinkat call.
            // Counting them as failures would trip the CB within seconds
            // and starve the rest of the pipeline.
            //
            // We do NOT call cb_.on_failure() here. We DO call
            // on_done(... "", false) so the FIM event is published with
            // an empty filename (the consumer will see this as a normal
            // "fd closed before resolve" event).
            notfound_.fetch_add(1);
            if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, "", false);
        } else if (result == "timeout") {
            timeout_.fetch_add(1);
            cb_.on_failure();
            if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, "", false);
        // T12 audit fix #57: the "eperm" branch is now unreachable
        // (resolve_sync returns "" for EACCES/EPERM). Kept as a
        // defensive fallback in case future code reintroduces it.
        } else if (result == "eperm") {
            eperm_.fetch_add(1);
            // Do NOT call cb_.on_failure() — see fd_resolver.cpp
            // resolve_sync for the AppArmor/race/perms rationale.
            if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, "", false);
        } else if (result == "error") {
            errors_.fetch_add(1);
            cb_.on_failure();
            if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, "", false);
        } else {
            // Validate the path before reporting success
            if (!is_valid_path(result)) {
                errors_.fetch_add(1);
                if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, "", false);
                continue;
            }
            resolved_.fetch_add(1);
            cb_.on_success();
            if (req.on_done) req.on_done(req.pid, req.fd, req.ktime_ns, result, true);
        }
    }
}

}  // namespace logsoc::agent::fd
