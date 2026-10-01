// fim_metrics.cpp — T4.8.6 — Prometheus metrics for FIM pipeline (impl)
#include "fim_metrics.hpp"

#include <chrono>
#include <cstdio>
#include <sstream>

namespace logsoc::agent::metrics {

// T8 fix: agent_start_time_unix is now initialized at first access via
// the static local in counters() (Meyers singleton pattern). The previous
// code relied on FimMetrics::FimMetrics() being called explicitly to set
// the start time, but the static global `Counters FimMetrics::instance_`
// did NOT trigger the constructor (no FimMetrics object was ever
// instantiated in the codebase). This left agent_start_time_unix at 0,
// and the metrics thread computed uptime_s = now - 0 = ~1.78B (56 years).
//
// The static local pattern is the standard C++ idiom for "initialize on
// first use" globals. Thread-safe by the standard (since C++11).
// We use a function-local struct to do the timestamp init because
// Counters is not movable (it contains std::atomic fields which are
// not copy-constructible), so we can't return it by value from a
// lambda and we can't use a default-init static local + post-init
// pattern either (the latter would have a brief window of 0).
Counters& FimMetrics::instance_ref() {
    // Meyers singleton: instance constructed on first call to this fn.
    // The default-init runs first (atomics to 0), then we set
    // agent_start_time_unix. The brief window where it's 0 is only
    // visible inside this function (single-threaded init), and the
    // metrics thread reads via the returned reference, not the
    // function-local. So no race.
    static Counters inst;
    if (inst.agent_start_time_unix.load(std::memory_order_relaxed) == 0) {
        inst.agent_start_time_unix.store(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count(),
            std::memory_order_relaxed);
    }
    return inst;
}

// Backward-compat: the legacy `Counters FimMetrics::instance_;` global
// has been replaced. We keep a reference for any direct accesses that
// might exist. On first read, it returns the static-local instance.
Counters& FimMetrics::instance_ = FimMetrics::instance_ref();

std::string FimMetrics::version_ = "unknown";

FimMetrics::FimMetrics() {
    // T8 fix: no longer relied upon for start time init (see instance_ref
    // above). Kept for ABI/source compat with any code that still calls it.
}

Counters& FimMetrics::counters() {
    return instance_;
}

// T12.10 (2026-06-16): snapshot all Counters into a POD struct for
// the heartbeat payload. Each field is a .load() on the
// corresponding atomic, so the snapshot is consistent-enough for
// monitoring (no torn reads on x86-64, may interleave with concurrent
// increments by ~1-2 events which is fine for stats).
FimMetrics::CountersSnapshot FimMetrics::snapshot() {
    CountersSnapshot s;
    const Counters& c = instance_;
    s.fd_resolved       = c.fd_resolved.load();
    s.fd_timeout        = c.fd_timeout.load();
    s.fd_eperm          = c.fd_eperm.load();
    s.fd_not_found      = c.fd_not_found.load();
    s.fd_cb_open        = c.fd_cb_open.load();
    s.fd_errors         = c.fd_errors.load();
    s.fd_dropped        = c.fd_dropped.load();
    s.fim_merged        = c.fim_merged.load();
    s.fim_dropped       = c.fim_dropped.load();
    s.fim_rate_limited  = c.fim_rate_limited.load();
    s.fim_watchdog_pings= c.fim_watchdog_pings.load();
    s.fim_shipped       = c.fim_shipped.load();
    s.net_packets_captured = c.net_packets_captured.load();
    s.net_packets_dropped  = c.net_packets_dropped.load();
    s.net_events_pushed    = c.net_events_pushed.load();
    s.net_flush_errors     = c.net_flush_errors.load();
    s.cb_trips         = c.cb_trips.load();
    return s;
}

void FimMetrics::set_agent_version(const std::string& version) {
    version_ = version;
}

const std::string& FimMetrics::agent_version() {
    return version_;
}

void FimMetrics::set_net_stats(uint64_t packets_captured,
                               uint64_t packets_dropped,
                               uint64_t events_pushed,
                               uint64_t flush_errors) {
    instance_.net_packets_captured.store(packets_captured, std::memory_order_relaxed);
    instance_.net_packets_dropped.store(packets_dropped, std::memory_order_relaxed);
    instance_.net_events_pushed.store(events_pushed, std::memory_order_relaxed);
    instance_.net_flush_errors.store(flush_errors, std::memory_order_relaxed);
}

std::string FimMetrics::scrape(int ship_q, int merge_q, int res_q,
                                const std::string& ver) const {
    std::ostringstream out;
    auto& c = instance_;

    auto emit = [&out](const char* name, const char* help, uint64_t v) {
        out << "# HELP " << name << " " << help << "\n"
            << "# TYPE " << name << " counter\n"
            << name << " " << v << "\n";
    };
    auto emit_gauge = [&out](const char* name, const char* help, int64_t v) {
        out << "# HELP " << name << " " << help << "\n"
            << "# TYPE " << name << " gauge\n"
            << name << " " << v << "\n";
    };

    // FdResolver metrics (6)
    emit("logsoc_fim_fd_resolved_total",
         "Number of /proc/<pid>/fd/<n> lookups that succeeded",
         c.fd_resolved.load());
    emit("logsoc_fim_fd_timeout_total",
         "Number of fd lookups that exceeded the 10ms timeout",
         c.fd_timeout.load());
    emit("logsoc_fim_fd_eperm_total",
         "Number of fd lookups that failed with EACCES/EPERM",
         c.fd_eperm.load());
    emit("logsoc_fim_fd_not_found_total",
         "Number of fd lookups that returned ENOENT (fd closed or pid exited)",
         c.fd_not_found.load());
    emit("logsoc_fim_fd_cb_open_total",
         "Number of fd lookups skipped because the CircuitBreaker was OPEN",
         c.fd_cb_open.load());
    emit("logsoc_fim_fd_errors_total",
         "Number of fd lookups that failed with an unexpected error",
         c.fd_errors.load());
    emit("logsoc_fim_fd_dropped_total",
         "Number of fd resolver requests dropped due to full queue",
         c.fd_dropped.load());

    // FimCollector metrics (4)
    emit("logsoc_fim_merged_total",
         "Number of fim events that merged a write_fd companion",
         c.fim_merged.load());
    emit("logsoc_fim_dropped_total",
         "Number of ship-queue events dropped due to full queue",
         c.fim_dropped.load());
    emit("logsoc_fim_rate_limited_total",
         "Number of events dropped by per-pid rate limiter",
         c.fim_rate_limited.load());
    emit("logsoc_fim_watchdog_pings_total",
         "Number of watchdog pings emitted to the ship queue",
         c.fim_watchdog_pings.load());
    emit("logsoc_fim_shipped_total",
         "Number of events successfully shipped to the backend",
         c.fim_shipped.load());

    // T4.8.9: NetworkCollector metrics (4)
    // Snapshot from NetworkStats atomics in src/network/pcap_collector.hpp.
    // The agent main loop periodically calls FimMetrics::set_net_stats(...)
    // (every 1s) so the metrics endpoint never blocks on a shared mutex
    // and never touches the NetworkCollector directly.
    emit("logsoc_fim_net_packets_captured_total",
         "Number of packets successfully captured by pcap",
         c.net_packets_captured.load());
    emit("logsoc_fim_net_packets_dropped_total",
         "Number of packets dropped (unparseable or filtered out)",
         c.net_packets_dropped.load());
    emit("logsoc_fim_net_events_pushed_total",
         "Number of network events pushed to the ship queue",
         c.net_events_pushed.load());
    emit("logsoc_fim_net_flush_errors_total",
         "Number of network flush callback errors (ship failure, etc.)",
         c.net_flush_errors.load());

    // CircuitBreaker metrics (1)
    emit("logsoc_fim_circuit_breaker_trips_total",
         "Number of times the CircuitBreaker has tripped (CLOSED→OPEN)",
         c.cb_trips.load());

    // Errors (2)
    emit("logsoc_fim_parse_errors_total",
         "Number of events that failed to parse",
         c.parse_errors.load());
    emit("logsoc_fim_ship_errors_total",
         "Number of ship attempts that failed (HTTP error, timeout, etc.)",
         c.ship_errors.load());

    // Gauges (4)
    emit_gauge("logsoc_fim_ship_queue_depth",
               "Current depth of the FimCollector ship queue",
               ship_q);
    emit_gauge("logsoc_fim_merge_queue_depth",
               "Current depth of the FimCollector pending_fim map",
               merge_q);
    emit_gauge("logsoc_fim_resolver_queue_depth",
               "Current depth of the FdResolver worker queue",
               res_q);
    emit_gauge("logsoc_fim_agent_start_time_seconds",
               "Unix timestamp of the agent's last start",
               c.agent_start_time_unix.load());

    // Metadata
    out << "# HELP logsoc_fim_agent_info Agent version\n"
        << "# TYPE logsoc_fim_agent_info gauge\n"
        << "logsoc_fim_agent_info{version=\"" << ver << "\"} 1\n";

    return out.str();
}

bool FimMetrics::is_healthy() const {
    // V4.8: always healthy. Future: check CB state, last event time,
    // disk space on state file, etc.
    return true;
}

std::string FimMetrics::liveness(const std::string& ver) const {
    auto start = instance_.agent_start_time_unix.load();
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto uptime = (start > 0) ? (now - start) : 0;
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "{\"status\":\"ok\",\"uptime_seconds\":%ld,\"version\":\"%s\"}\n",
                  (long)uptime, ver.c_str());
    return std::string(buf);
}

void FimMetrics::reset() {
    auto& c = instance_;
    c.fd_resolved.store(0);
    c.fd_timeout.store(0);
    c.fd_eperm.store(0);
    c.fd_not_found.store(0);
    c.fd_cb_open.store(0);
    c.fd_errors.store(0);
    c.fd_dropped.store(0);
    c.fim_merged.store(0);
    c.fim_dropped.store(0);
    c.fim_rate_limited.store(0);
    c.fim_watchdog_pings.store(0);
    c.fim_shipped.store(0);
    c.net_packets_captured.store(0);
    c.net_packets_dropped.store(0);
    c.net_events_pushed.store(0);
    c.net_flush_errors.store(0);
    c.cb_trips.store(0);
    c.parse_errors.store(0);
    c.ship_errors.store(0);
    // Do NOT reset agent_start_time_unix or agent_version_hash
}

}  // namespace logsoc::agent::metrics
