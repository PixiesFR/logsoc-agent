// yara_shipper.hpp — T58 v3.14.0
//
// Architecture (per SOC-AGENT#3 alternative, validated by Nova RSSI +
// Codeur 2026-06-10):
//   - Agent captures FIM events (inode + filename + fd) — FanotifyCollector
//   - On heuristic match, agent SHIPS the content to central via HTTP POST
//   - Central scans with libyara (see logsoc-web app/yara_scanner.py)
//   - No YARA in the agent's process — agent stays a sensor, not an analyst
//   - No AppArmor bypass (agent only reads file, doesn't match rules)
//
// Scope:
//   - yara_shipper.hpp: heuristic + bounded queue + background ship thread
//   - Hooked from FanotifyCollector event loop (see agent.cpp)
//
// Threading model:
//   - FIM event loop enqueues (non-blocking) into a bounded queue
//   - A single ship thread drains the queue, POSTs to central, applies rate limit
//   - Main thread does NOT touch the shipper after start() (no locks needed)
//
// Failure modes (graceful degradation):
//   - Central unreachable: enqueue, retry on next interval (drop-oldest if full)
//   - File unreadable (deleted/moved): skip, log INFO
//   - File too large (>4MB cap): skip, log INFO (per central API bound)
//   - Heuristic score 0: don't enqueue at all (saves bandwidth)

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>  // T12.16: kept for future use; was for unique_ptr<MetricsServer>
#include <mutex>
#include <sstream>  // v3.16 (T60b): for std::ostringstream in render_prometheus_metrics()
#include <string>
#include <thread>
#include <vector>

#include "debug.hpp"

namespace logsoc::agent::yara {

// ── Configuration (tunable from AgentConfig later) ─────────────────────


struct ShipperConfig {
    // Central API endpoint (full URL, e.g. "https://central:8000/api/v1/yara/scan")
    std::string endpoint;
    // Bearer token (agent_token) for HMAC auth
    std::string auth_token;
    // Agent ID (UUID assigned at registration)
    std::string agent_id;

    // Queue
    size_t max_queue_size = 1000;  // bounded, drop-oldest on overflow

    // Rate limit
    int min_interval_ms = 10;  // min ms between two ships (rate limit soft)

    // File size cap (mirrors central API bound)
    size_t max_file_size = 4 * 1024 * 1024;  // 4MB

    // Heuristic threshold (only ship if score >= threshold)
    int heuristic_threshold = 3;  // 0-10; 3 = light filter (catch obvious cases)

    // Gzip threshold
    size_t gzip_threshold = 64 * 1024;  // gzip if content > 64KB

    // T12.16 (audit Nova C-05): HTTP metrics server fields removed.
    // The metrics are now pushed in the heartbeat payload instead.
    // Configs that still carry metrics_port or metrics_bind_address
    // are silently ignored at the agent.cpp loader (the JSON keys
    // just don't bind to anything).

    // T4.8.22 SECURITY: TLS verification toggle. Default false (verify
    // ON, the safe default for a SOC product shipping file content).
    // Operators with self-signed certs in dev/test can flip this via
    // the config file. A WARN log is emitted when insecure mode is on.
    // Previous behavior: ALWAYS insecure (CURLOPT_SSL_VERIFYPEER=0),
    // which was a security regression — every ship request could be
    // MITM'd by anyone on the path between agent and central.
    bool tls_insecure_skip_verify = false;
};


// ── Heuristic (T58 spec, validated 2026-06-10) ──────────────────────────


// Compute a 0-10 score for "should we ship this file to central for YARA scan?"
// Heuristics (in order of weight):
//   - Extension:    executable / script / archive → +5
//   - Path:         /tmp, /var/tmp, /dev/shm, /etc/cron.* → +3
//   - Size:         <1KB or >1MB → -1 (too small / too large usually benign)
//   - Hidden file:  starts with '.' and not in allowed list → +2
// Returns 0 if no heuristic matches (file is "obviously benign").
inline int heuristic_score(const std::string& path, size_t file_size) {
    int score = 0;

    // 1. Extension check
    auto ends_with = [](const std::string& s, const std::string& suffix) {
        if (s.size() < suffix.size()) return false;
        return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
    };

    static const std::vector<std::string> kSuspiciousExt = {
        ".elf", ".bin", ".so", ".exe", ".com", ".scr",
        ".sh", ".bash", ".zsh", ".csh",
        ".py", ".pl", ".rb", ".php", ".js",
        ".tar", ".gz", ".bz2", ".xz", ".7z", ".zip", ".rar",
        ".jar", ".war", ".ear", ".class",
        ".dylib", ".dll", ".sys", ".ko",
        ".iso", ".img", ".dmg",
    };
    for (const auto& ext : kSuspiciousExt) {
        if (ends_with(path, ext)) { score += 5; break; }
    }

    // 2. Path check
    static const std::vector<std::string> kSuspiciousPaths = {
        "/tmp/", "/var/tmp/", "/dev/shm/",
        "/etc/cron", "/etc/init.d", "/etc/systemd/",
        "/root/.", "/home/*/.bashrc", "/home/*/.ssh/",
        "/usr/local/bin/", "/opt/",
    };
    for (const auto& p : kSuspiciousPaths) {
        if (path.find(p) != std::string::npos) { score += 3; break; }
    }

    // 3. Size penalty
    if (file_size < 1024) score -= 1;        // too small
    if (file_size > 1024 * 1024) score -= 1;  // too large for "interesting" binaries

    // 4. Hidden file in /tmp or /home (often malware droppers)
    if ((path.find("/tmp/") != std::string::npos ||
         path.find("/dev/shm/") != std::string::npos) &&
        path.find("/.") != std::string::npos) {
        score += 2;
    }

    // Clamp to 0-10
    if (score < 0) score = 0;
    if (score > 10) score = 10;
    return score;
}


// ── Pending job ─────────────────────────────────────────────────────────


struct PendingScan {
    std::string path;
    uint64_t inode = 0;
    size_t file_size = 0;
    int heuristic = 0;
    // v3.16 (T60a): content moved to ship_loop (read on the ship thread,
    // not in the FIM event loop). This removes the 5-10ms sync read cost
    // from the FIM pipeline (especially for 4MB files).
    std::vector<uint8_t> content;
};


// ── Shipper ─────────────────────────────────────────────────────────────


class YaraShipper {
public:
    // T12.16 (audit Nova C-05): ctor/dtor are now simple defaults,
    // defined inline here (no more out-of-line needed since the
    // MetricsServer dep is gone). One less translation-unit hop.
    YaraShipper() = default;
    explicit YaraShipper(ShipperConfig cfg) : cfg_(std::move(cfg)) {}
    ~YaraShipper() = default;

    // T12.16: start the background ship thread. Idempotent.
    void start();

    // T12.16: stop the background ship thread (joins). Idempotent.
    void stop();

    // v3.16 (T60a): enqueue a FIM event for shipping. ASYNC: no file I/O
    // here. The caller is the FIM event loop (FanotifyCollector::run)
    // and must return as fast as possible. The actual file read + POST
    // happens in ship_loop().
    //
    // Returns true if enqueued, false if dropped (heuristic gate, size
    // cap, or queue full + drop-oldest evicted).
    bool enqueue_event(const std::string& path, uint64_t inode, size_t file_size) {
        // 1. Heuristic gate
        int h = heuristic_score(path, file_size);
        if (h < cfg_.heuristic_threshold) {
            return false;  // not suspicious enough
        }

        // 2. Size cap (matches central API)
        if (file_size == 0 || file_size > cfg_.max_file_size) {
            stats_.skipped_size++;
            return false;
        }

        // 3. Bounded queue (drop-oldest on overflow). NO file I/O here.
        {
            std::lock_guard<std::mutex> lk(queue_mtx_);
            if (queue_.size() >= cfg_.max_queue_size) {
                queue_.pop_front();  // drop oldest
                stats_.dropped++;
            }
            queue_.push_back(PendingScan{
                .path = path,
                .inode = inode,
                .file_size = file_size,
                .heuristic = h,
                .content = {},
                // content is read on the ship thread by ship_loop() (T60a).
            });
        }
        cv_.notify_one();
        return true;
    }

    // v3.16 (T60a): alias for the async enqueue (same behavior, clearer
    // name for new code paths that want to emphasize the no-sync-I/O
    // guarantee). Old `enqueue_event` is kept for backward compat.
    bool enqueue_event_async(const std::string& path, uint64_t inode, size_t file_size) {
        return enqueue_event(path, inode, file_size);
    }

    // Snapshot of counters (for /agent-stats endpoint).
    struct Stats {
        std::atomic<uint64_t> shipped{0};
        std::atomic<uint64_t> dropped{0};
        std::atomic<uint64_t> failed{0};
        std::atomic<uint64_t> skipped_size{0};
        std::atomic<uint64_t> skipped_unreadable{0};
        std::atomic<uint64_t> skipped_too_large{0};  // T12.14 (H-07): file > 8MB
        std::atomic<uint64_t> matched{0};  // files that produced >=1 match
    };
    Stats stats_;

    // T12.10 (2026-06-16): snapshot of YaraShipper stats for the
    // heartbeat payload (replaces the T12.10d-to-be-removed
    // /metrics HTTP server). Plain struct, not atomic — caller
    // (heartbeat thread) reads each field via .load(). The struct
    // is POD-ish so it can be passed by value cheaply.
    struct StatsSnapshot {
        uint64_t shipped = 0;
        uint64_t dropped = 0;
        uint64_t failed = 0;
        uint64_t skipped_size = 0;
        uint64_t skipped_unreadable = 0;
        uint64_t skipped_too_large = 0;
        uint64_t matched = 0;
    };
    StatsSnapshot stats_snapshot() const {
        StatsSnapshot s;
        s.shipped           = stats_.shipped.load();
        s.dropped           = stats_.dropped.load();
        s.failed            = stats_.failed.load();
        s.skipped_size      = stats_.skipped_size.load();
        s.skipped_unreadable= stats_.skipped_unreadable.load();
        s.skipped_too_large = stats_.skipped_too_large.load();
        s.matched           = stats_.matched.load();
        return s;
    }

    // v3.16 (T60b): current queue depth (for Prometheus gauge). Locked
    // read since the ship thread and the FIM thread both access the queue.
    size_t queue_depth() const {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        return queue_.size();
    }

    // v3.16 (T60b): render Prometheus metrics text. Exposed publicly so
    // tests / heartbeat callback can grab the same string the metrics
    // HTTP server serves.
    std::string render_prometheus_metrics() const {
        std::ostringstream o;
        o << "# HELP logsoc_yara_shipper_shipped_total Files successfully shipped to central\n"
          << "# TYPE logsoc_yara_shipper_shipped_total counter\n"
          << "logsoc_yara_shipper_shipped_total " << stats_.shipped.load() << "\n"
          << "# HELP logsoc_yara_shipper_dropped_total Files dropped (queue full)\n"
          << "# TYPE logsoc_yara_shipper_dropped_total counter\n"
          << "logsoc_yara_shipper_dropped_total " << stats_.dropped.load() << "\n"
          << "# HELP logsoc_yara_shipper_failed_total Ship attempts that failed (HTTP error / curl error)\n"
          << "# TYPE logsoc_yara_shipper_failed_total counter\n"
          << "logsoc_yara_shipper_failed_total " << stats_.failed.load() << "\n"
          << "# HELP logsoc_yara_shipper_skipped_size_total Files skipped because file_size > max_file_size or == 0\n"
          << "# TYPE logsoc_yara_shipper_skipped_size_total counter\n"
          << "logsoc_yara_shipper_skipped_size_total " << stats_.skipped_size.load() << "\n"
          << "# HELP logsoc_yara_shipper_skipped_unreadable_total Files skipped because read failed (deleted between event and ship, or file_size mismatch)\n"
          << "# TYPE logsoc_yara_shipper_skipped_unreadable_total counter\n"
          << "logsoc_yara_shipper_skipped_unreadable_total " << stats_.skipped_unreadable.load() << "\n"
          << "# HELP logsoc_yara_shipper_skipped_too_large_total Files skipped because file > 8MB hard cap (H-07)\n"
          << "# TYPE logsoc_yara_shipper_skipped_too_large_total counter\n"
          << "logsoc_yara_shipper_skipped_too_large_total " << stats_.skipped_too_large.load() << "\n"
          << "# HELP logsoc_yara_shipper_matched_total Files that produced >=1 YARA match on central\n"
          << "# TYPE logsoc_yara_shipper_matched_total counter\n"
          << "logsoc_yara_shipper_matched_total " << stats_.matched.load() << "\n"
          << "# HELP logsoc_yara_shipper_queue_depth Current size of the bounded queue\n"
          << "# TYPE logsoc_yara_shipper_queue_depth gauge\n"
          << "logsoc_yara_shipper_queue_depth " << queue_depth() << "\n";
        return o.str();
    }

    const ShipperConfig& config() const { return cfg_; }

private:
    void ship_loop() {
        LOG_INFO("[YaraShipper] ship loop entered");
        while (running_.load()) {
            std::unique_lock<std::mutex> lk(queue_mtx_);
            cv_.wait_for(lk, std::chrono::milliseconds(500),
                         [this]() { return !queue_.empty() || !running_.load(); });
            if (!running_.load() && queue_.empty()) break;
            if (queue_.empty()) continue;

            PendingScan job = std::move(queue_.front());
            queue_.pop_front();
            lk.unlock();

            ship_one(std::move(job));
        }
        LOG_INFO("[YaraShipper] ship loop exiting");
    }

    // Ship one job via libcurl. Implementation in yara_shipper.cpp.
    void ship_one(PendingScan job);

    ShipperConfig cfg_;
    std::thread ship_thread_;
    std::atomic<bool> running_{false};
    std::deque<PendingScan> queue_;
    // v3.16 (T60b): mutable because queue_depth() is const (read-only
    // gauge accessor) and needs to lock the mutex.
    mutable std::mutex queue_mtx_;
    std::condition_variable cv_;

    // T12.16 (audit Nova C-05): metrics HTTP server removed.
    // (was: class MetricsServer; std::unique_ptr<MetricsServer> metrics_server_;)
};

}  // namespace logsoc::agent::yara
