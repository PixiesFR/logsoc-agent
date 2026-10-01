// fim_metrics.hpp — T4.8.6 — Prometheus metrics for FIM pipeline
//
// V4.8 metrics: 16 metrics covering the full FIM pipeline
// (resolver + collector + circuit breaker). Exposed as a thread-safe
// scrape() function returning a Prometheus text-format string.
//
// Health check: is_healthy() returns true if all subsystems are alive.
// Liveness check: liveness() returns the agent uptime + version.

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace logsoc::agent::metrics {

// Global counters (atomic, no mutex). Reset only on agent restart.
struct Counters {
    // FdResolver counters
    std::atomic<uint64_t> fd_resolved{0};
    std::atomic<uint64_t> fd_timeout{0};
    std::atomic<uint64_t> fd_eperm{0};
    std::atomic<uint64_t> fd_not_found{0};
    std::atomic<uint64_t> fd_cb_open{0};
    std::atomic<uint64_t> fd_errors{0};
    std::atomic<uint64_t> fd_dropped{0};

    // FimCollector counters
    std::atomic<uint64_t> fim_merged{0};
    std::atomic<uint64_t> fim_dropped{0};
    std::atomic<uint64_t> fim_rate_limited{0};
    std::atomic<uint64_t> fim_watchdog_pings{0};
    std::atomic<uint64_t> fim_shipped{0};     // events sent to backend

    // T4.8.9: NetworkCollector counters (pcap-based packet capture)
    // Mirrors src/network/pcap_collector.hpp::NetworkStats so the
    // agent has a single unified /metrics surface for all data sources.
    // Snapshotted from NetworkStats on every scrape (cheap, atomic load).
    std::atomic<uint64_t> net_packets_captured{0};
    std::atomic<uint64_t> net_packets_dropped{0};
    std::atomic<uint64_t> net_events_pushed{0};
    std::atomic<uint64_t> net_flush_errors{0};

    // CircuitBreaker counters
    std::atomic<uint64_t> cb_trips{0};

    // Errors
    std::atomic<uint64_t> parse_errors{0};
    std::atomic<uint64_t> ship_errors{0};

    // Agent-wide
    std::atomic<int64_t> agent_start_time_unix{0};
    std::atomic<uint64_t> agent_version_hash{0};  // git commit short hash
};

class FimMetrics {
public:
    FimMetrics();

    // T8 fix: Meyers-singleton accessor for the global counters struct.
    // The counters are constructed on first call (which sets
    // agent_start_time_unix to "now" via the lambda in .cpp).
    static Counters& instance_ref();

    // Access to global counters (singleton pattern, no ownership).
    // Returns the same object as instance_ref(); kept for source compat.
    static Counters& counters();

    // Render Prometheus text-format metrics. Includes all counters
    // plus queue depths (queried live from FimCollector/FdResolver).
    std::string scrape(int ship_queue_depth, int merge_queue_depth,
                       int resolver_queue_depth, const std::string& agent_version) const;

    // Health check: returns true if all subsystems are healthy.
    // For V4.8: always returns true. Future: check CB state, last event time.
    bool is_healthy() const;

    // Liveness: returns "ok" + uptime in seconds + version
    std::string liveness(const std::string& agent_version) const;

    // Reset all counters (admin endpoint, requires future gate)
    void reset();

    // Set the version string used in scrape() output (logsoc_fim_agent_info{version=...}).
    // Stored in the singleton Counters struct as agent_version_hash (uint64).
    // The actual version string is stored separately because Counters is POD-ish.
    static void set_agent_version(const std::string& version);
    static const std::string& agent_version();

    // T12.10 (2026-06-16): lightweight snapshot of the Counters
    // struct for the heartbeat payload. Replaces the
    // to-be-removed /metrics HTTP server with an outbound-only
    // channel (T12.10d). POD-ish, all fields are atomic .load()
    // of the corresponding Counters fields.
    struct CountersSnapshot {
        // FdResolver
        uint64_t fd_resolved = 0;
        uint64_t fd_timeout = 0;
        uint64_t fd_eperm = 0;
        uint64_t fd_not_found = 0;
        uint64_t fd_cb_open = 0;
        uint64_t fd_errors = 0;
        uint64_t fd_dropped = 0;
        // FimCollector
        uint64_t fim_merged = 0;
        uint64_t fim_dropped = 0;
        uint64_t fim_rate_limited = 0;
        uint64_t fim_watchdog_pings = 0;
        uint64_t fim_shipped = 0;
        // NetworkCollector
        uint64_t net_packets_captured = 0;
        uint64_t net_packets_dropped = 0;
        uint64_t net_events_pushed = 0;
        uint64_t net_flush_errors = 0;
        // CircuitBreaker
        uint64_t cb_trips = 0;
        // Yara engine
        uint64_t yara_rules_loaded = 0;
        uint64_t yara_scans_total = 0;
        uint64_t yara_matches_total = 0;
    };
    static CountersSnapshot snapshot();

    // T4.8.9: snapshot the NetworkStats counters from
    // src/network/pcap_collector.hpp into the unified FimMetrics
    // Counters. Called from the agent main loop every ~1s so the
    // /metrics endpoint never blocks on the NetworkCollector mutex.
    // Pass 0 for any field you don't want to overwrite.
    static void set_net_stats(uint64_t packets_captured,
                              uint64_t packets_dropped,
                              uint64_t events_pushed,
                              uint64_t flush_errors);

private:
    // T8 fix: instance_ is now a reference (Meyers singleton), initialized
    // in .cpp from instance_ref() which sets agent_start_time_unix on
    // first call. Replaces the old `static Counters instance_;` which
    // never had its constructor called.
    static Counters& instance_;
    static std::string version_;
};

}  // namespace logsoc::agent::metrics
