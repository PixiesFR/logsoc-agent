// fim_collector.hpp — T4.8.5 — FIM event orchestrator
//
// V4.8 orchestrator that takes raw BPF events (type 4 fim, type 8 write_fd)
// and produces merged, rate-limited, MITRE-tagged, ship-ready FIM events.
//
// Pipeline (per event):
//  1. Receive fim event (basename, pid, ktime_ns) or write_fd (fd, pid, ktime_ns)
//  2. Merge: if write_fd arrives within ±5ms of a fim with same (pid, basename),
//     resolve fd → abs_path, publish one enriched event
//  3. Rate limit: token bucket per pid (default 100 events/s/pid)
//  4. MITRE tag via MitreMapping
//  5. Enqueue to ship queue (bounded, with overflow drop policy)
//  6. Watchdog: if no events received for 30s, emit a "watchdog_alive" ping
//     so downstream systems know the collector is healthy.
//
// Threading: single consumer thread, BPF events pushed from the ringbuf
// callback. Ship queue popped by the shipper thread.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "fd_resolver.hpp"
#include "mitre_mapping.hpp"

namespace logsoc::agent::fim {

// FIM event after merging, tagging, ready to ship
struct FimEvent {
    std::string abs_path;       // resolved absolute path
    std::string basename;       // from BPF type 4
    uint32_t pid;
    uint64_t ktime_ns;          // for correlation
    char operation[16];        // "write", "create", "unlink"
    std::vector<std::string> mitre;  // technique IDs
    std::string resolution;     // "ok", "no_fim", "cb_open", "timeout", "eperm"
    std::chrono::system_clock::time_point enqueued_at;
};

struct Config {
    int  ship_queue_capacity = 8192;          // bounded queue
    int  rate_limit_per_pid_per_sec = 100;    // token bucket
    // T4.8.22: removed the duplicate `merge_window_us` field that
    // shadowed `fim_window` and was never read by any code path.
    // The single source of truth is now `fim_window`.
    std::chrono::milliseconds fim_window{5};  // ±5ms merge window
    std::chrono::seconds watchdog_period{30}; // alive ping period
    bool enable_watchdog = true;
};

class FimCollector {
public:
    explicit FimCollector(const Config& cfg, fd::FdResolver& resolver);
    ~FimCollector();

    // Push a raw BPF fim event (type 4). Called from the ringbuf callback.
    // Returns false if the merge queue is full (backpressure).
    bool on_fim_event(uint32_t pid, const std::string& basename, uint64_t ktime_ns,
                      const char* operation);

    // Push a raw BPF write_fd event (type 8). The resolver will be invoked
    // to translate (pid, fd) → abs_path. The result is then merged with a
    // pending fim event (within ±5ms).
    bool on_write_fd_event(uint32_t pid, int fd, uint64_t ktime_ns);

    // Pop a ship-ready event. Returns false if the queue is empty.
    // wait: if true, block up to timeout for an event.
    bool pop_ship_event(FimEvent& out, std::chrono::milliseconds timeout);

    // v4.8.0 (T4.8.8): public publish entry for external sources
    // (e.g. FimPoller fallback). The event is enqueued directly into
    // the ship queue without going through the merge window. Used by
    // the FimPoller when eBPF doesn't fire (SSH root + Hestia 6.8).
    void publish_external(FimEvent ev);

    // Stats
    uint64_t merged_total()  const { return merged_.load(); }
    uint64_t dropped_total() const { return dropped_.load(); }
    uint64_t rate_limited_total() const { return rate_limited_.load(); }
    uint64_t watchdog_pings() const { return wdog_pings_.load(); }
    size_t   ship_queue_depth() const;
    size_t   merge_queue_depth() const;

private:
    Config cfg_;
    fd::FdResolver& resolver_;

    // Ship queue (consumer: shipper thread)
    std::deque<FimEvent> ship_queue_;
    mutable std::mutex ship_mtx_;
    std::condition_variable ship_cv_;

    // Merge window: pending fim events waiting for their write_fd companion
    // Key: (pid, basename), Value: timestamp + operation
    struct PendingFim {
        std::chrono::steady_clock::time_point received_at;
        std::string operation;
    };
    std::unordered_map<std::string, PendingFim> pending_fim_;
    mutable std::mutex merge_mtx_;

    // Rate limit: per-pid token bucket
    struct TokenBucket {
        double tokens;
        std::chrono::steady_clock::time_point last_refill;
    };
    std::unordered_map<uint32_t, TokenBucket> buckets_;
    mutable std::mutex rate_mtx_;

    std::thread watchdog_;
    std::atomic<bool> stop_{false};
    std::atomic<uint64_t> merged_{0}, dropped_{0}, rate_limited_{0}, wdog_pings_{0};

    void watchdog_loop();
    void publish(FimEvent ev);
    void garbage_collect_pending();
    static std::string merge_key(uint32_t pid, const std::string& basename);
    bool try_acquire_token(uint32_t pid);
};

}  // namespace logsoc::agent::fim
