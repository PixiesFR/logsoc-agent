// fim_poller.hpp — T4.8.8 — FIM periodic poller (fallback for SSH root eBPF invisibility)
//
// Purpose: detect file modifications on watch_paths even when the eBPF
// kprobe does not fire for SSH-launched processes (Hestia 6.8 kernel bug:
// kprobes don't capture events from cgroup user.slice/user-0.slice/session-N.scope).
//
// Strategy:
// - Poll watch_paths every N seconds (default 5s)
// - For each path, stat() and compute SHA-256
// - Compare with previous snapshot
// - If SHA changed (or mtime changed since last poll), publish a FimEvent
//   with resolution="poller_fallback" and abs_path=path
//
// This is a pure userspace fallback. It does NOT replace eBPF when it
// works — it just provides observability when eBPF misses events.
//
// Threading: single poller thread, sleeps 5s between polls. Cheap.

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace logsoc::agent::fim {

class FimCollector;  // forward decl
struct FimEvent;     // forward decl (used by callback signature)

class FimPoller {
public:
    struct Config {
        std::chrono::seconds poll_interval{5};
        // If non-empty, watch these paths. Empty = poller disabled.
        std::vector<std::string> watch_paths;
    };

    // Original API: publish events to a FimCollector in-process.
    explicit FimPoller(const Config& cfg, FimCollector& collector);

    // T13.2a: callback API for privilege-separated scanners that
    // forward events to a parent agent process via IPC. The callback
    // is invoked on the poller thread for each detected change. It
    // must be non-blocking; use a bounded queue + dedicated dispatcher
    // thread if forwarding might block.
    using EventCallback = std::function<void(const FimEvent&)>;
    explicit FimPoller(const Config& cfg, EventCallback cb);
    ~FimPoller();

    // Force a poll right now (for testing or admin triggers).
    // Returns the number of changes detected.
    int poll_now();

    // Stats
    uint64_t polls_total() const { return polls_.load(); }
    uint64_t changes_total() const { return changes_.load(); }

private:
    Config cfg_;
    // T13.2a: one of these is set in the ctor, the other is null.
    // Tagged union: callback_ != nullptr => callback mode; otherwise
    // collector mode. The mode is set at construction and never changes.
    FimCollector* collector_ = nullptr;
    EventCallback callback_;

    // Path -> last known SHA-256 (hex string)
    std::unordered_map<std::string, std::string> last_sha_;
    mutable std::mutex state_mtx_;

    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<uint64_t> polls_{0};
    std::atomic<uint64_t> changes_{0};

    void run();
    void check_path(const std::string& path);
    static std::string compute_sha256(const std::string& path);
};

}  // namespace logsoc::agent::fim
