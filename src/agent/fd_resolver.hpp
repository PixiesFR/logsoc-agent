// fd_resolver.hpp — T4.8.2 — Async /proc/<pid>/fd/<n> resolver with timeout
//
// V4.8: replaces the broken openat + open_path_cache BPF pattern.
// Given (pid, fd) from a write_fd event, resolves the absolute path
// by reading /proc/<pid>/fd/<fd> with a 10ms timeout. The result is
// then merged with the FIM event (from type 4) by (pid, ktime_ns).
//
// Properties:
// - Worker pool: N threads, MPSC queue (caller pushes, workers pop)
// - Hard 10ms timeout per resolve (uses openat2+close-on-exec pattern)
// - Validation: rejects path > 4096, contains null, contains ".."
// - Metrics: resolved, timeouts, eperm, not_found, cb_open, errors
// - Thread-safe; uses CircuitBreaker to skip /proc lookups when /proc
//   is wedged (e.g., during a kernel lockup)
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "circuit_breaker.hpp"

namespace logsoc::agent::fd {

struct ResolveRequest {
    uint32_t pid;
    int      fd;
    uint64_t ktime_ns;     // for correlation with FIM event
    // The caller can attach arbitrary data (e.g., a callback or
    // a shared_ptr to a queue). We use a sink callback.
    std::function<void(uint32_t /*pid*/, int /*fd*/, uint64_t /*ktime_ns*/,
                       const std::string& /*abs_path*/, bool /*ok*/)> on_done;
};

struct Config {
    int worker_count = 4;                                  // thread pool
    int queue_capacity = 4096;                             // bounded queue
    std::chrono::milliseconds per_resolve_timeout{10};     // hard timeout
    std::chrono::milliseconds open_retry_backoff{2};       // retry if EAGAIN
    int max_retries = 2;                                   // retries on EAGAIN
    int max_path_len = 4096;                               // reject longer
    std::string cb_state_file;                             // CB persistence
    int cb_window_size = 100;
    // T4.8.18 PHASE 2 hotfix v4: increased from 5 to 50. The previous
    // threshold (5) was too aggressive for the production workload on
    // Hestia, where 5 ENOENT/EINVAL results in 1 second is normal during
    // process churn (700+ processes, constant fd open/close). The
    // circuit breaker would trip in seconds and starve the rest of
    // the pipeline (root cause of the 1163 events with
    // filename=<unknown> in ClickHouse).
    //
    // With threshold=50, the CB only trips if /proc is genuinely
    // broken (e.g. ENOSPC, EACCES storm, kernel panic imminent).
    // The trade-off is that the agent may process a few more requests
    // that would have been rejected under a stricter threshold, but
    // in our setup the FdResolver already returns empty on legitimate
    // "fd closed" cases (t4.8.17 fix) so this is safe.
    int cb_failure_threshold = 50;
    std::chrono::milliseconds cb_open_duration{60000};  // 60s OPEN
};

class FdResolver {
public:
    explicit FdResolver(const Config& cfg);
    ~FdResolver();

    // Submit a request. Returns false if the queue is full (backpressure).
    bool submit(ResolveRequest req);

    // Drain all pending requests (used in tests). Blocks until done.
    void drain();

    // Stats
    uint64_t resolved_total() const { return resolved_.load(); }
    uint64_t timeout_total()  const { return timeout_.load(); }
    uint64_t eperm_total()    const { return eperm_.load(); }
    uint64_t not_found_total() const { return notfound_.load(); }
    uint64_t cb_open_total()  const { return cb_open_.load(); }
    uint64_t errors_total()   const { return errors_.load(); }
    uint64_t dropped_total()  const { return dropped_.load(); }
    size_t   queue_depth()    const;

    // For tests: directly resolve a single fd (no queue, no thread).
    // Returns empty string on failure.
    static std::string resolve_sync(uint32_t pid, int fd,
                                    std::chrono::milliseconds timeout);

    // Validates a resolved path. Returns false if path is unsafe.
    // Public for unit tests and for callers that want to validate a
    // path obtained elsewhere (e.g., from a different resolver).
    static bool is_valid_path(const std::string& p);

private:
    Config cfg_;
    cb::CircuitBreaker cb_;
    std::vector<std::thread> workers_;
    std::deque<ResolveRequest> queue_;
    mutable std::mutex mtx_;
    std::condition_variable cv_not_empty_;
    std::condition_variable cv_not_full_;
    std::atomic<bool> stop_{false};
    std::atomic<uint64_t> resolved_{0}, timeout_{0}, eperm_{0};
    std::atomic<uint64_t> notfound_{0}, cb_open_{0}, errors_{0}, dropped_{0};

    void worker_loop();
};

}  // namespace logsoc::agent::fd
