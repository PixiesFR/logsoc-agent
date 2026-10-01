// test_fim_metrics.cpp — T4.8.6 — unit tests for FimMetrics
//
// Build:
//   g++ -std=c++17 -O2 -pthread -Isrc/agent -o test_fim_metrics
//       tests/test_fim_metrics.cpp src/agent/fim_metrics.cpp
//   ./test_fim_metrics

#include "../src/agent/fim_metrics.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

using namespace logsoc::agent::metrics;
using namespace std::chrono_literals;

static int g_passed = 0;
static int g_failed = 0;

#define EXPECT(cond, msg)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg);\
            g_failed++;                                                        \
        } else {                                                               \
            g_passed++;                                                        \
        }                                                                      \
    } while (0)

static void test_counters_singleton() {
    FimMetrics m;
    m.counters().fd_resolved.store(42);
    FimMetrics m2;
    EXPECT(m2.counters().fd_resolved.load() == 42, "counters are singleton (shared)");
}

static void test_scrape_includes_all_metrics() {
    FimMetrics m;
    m.reset();
    m.counters().fd_resolved.store(100);
    m.counters().fd_timeout.store(5);
    m.counters().fd_eperm.store(2);
    m.counters().fd_not_found.store(10);
    m.counters().fd_cb_open.store(1);
    m.counters().fd_errors.store(0);
    m.counters().fd_dropped.store(3);
    m.counters().fim_merged.store(50);
    m.counters().fim_dropped.store(0);
    m.counters().fim_rate_limited.store(20);
    m.counters().fim_watchdog_pings.store(3);
    m.counters().fim_shipped.store(200);
    m.counters().cb_trips.store(2);
    m.counters().parse_errors.store(0);
    m.counters().ship_errors.store(1);

    std::string out = m.scrape(10, 5, 2, "v4.8.0-test");
    // Check every metric is present
    EXPECT(out.find("logsoc_fim_fd_resolved_total 100") != std::string::npos, "fd_resolved");
    EXPECT(out.find("logsoc_fim_fd_timeout_total 5") != std::string::npos, "fd_timeout");
    EXPECT(out.find("logsoc_fim_fd_eperm_total 2") != std::string::npos, "fd_eperm");
    EXPECT(out.find("logsoc_fim_fd_not_found_total 10") != std::string::npos, "fd_not_found");
    EXPECT(out.find("logsoc_fim_fd_cb_open_total 1") != std::string::npos, "fd_cb_open");
    EXPECT(out.find("logsoc_fim_fd_errors_total 0") != std::string::npos, "fd_errors");
    EXPECT(out.find("logsoc_fim_fd_dropped_total 3") != std::string::npos, "fd_dropped");
    EXPECT(out.find("logsoc_fim_merged_total 50") != std::string::npos, "fim_merged");
    EXPECT(out.find("logsoc_fim_dropped_total 0") != std::string::npos, "fim_dropped");
    EXPECT(out.find("logsoc_fim_rate_limited_total 20") != std::string::npos, "fim_rate_limited");
    EXPECT(out.find("logsoc_fim_watchdog_pings_total 3") != std::string::npos, "fim_watchdog_pings");
    EXPECT(out.find("logsoc_fim_shipped_total 200") != std::string::npos, "fim_shipped");
    EXPECT(out.find("logsoc_fim_circuit_breaker_trips_total 2") != std::string::npos, "cb_trips");
    EXPECT(out.find("logsoc_fim_parse_errors_total 0") != std::string::npos, "parse_errors");
    EXPECT(out.find("logsoc_fim_ship_errors_total 1") != std::string::npos, "ship_errors");

    // Gauges
    EXPECT(out.find("logsoc_fim_ship_queue_depth 10") != std::string::npos, "ship_queue_depth");
    EXPECT(out.find("logsoc_fim_merge_queue_depth 5") != std::string::npos, "merge_queue_depth");
    EXPECT(out.find("logsoc_fim_resolver_queue_depth 2") != std::string::npos, "resolver_queue_depth");

    // Version
    EXPECT(out.find("version=\"v4.8.0-test\"") != std::string::npos, "version metadata");
}

static void test_scrape_prometheus_format() {
    FimMetrics m;
    std::string out = m.scrape(0, 0, 0, "v4.8.0");
    // Every metric should have HELP and TYPE comments
    EXPECT(out.find("# HELP") != std::string::npos, "has HELP comments");
    EXPECT(out.find("# TYPE") != std::string::npos, "has TYPE comments");
    EXPECT(out.find("counter") != std::string::npos, "has counter type");
    EXPECT(out.find("gauge") != std::string::npos, "has gauge type");
    // Newlines between metrics
    EXPECT(out.find("\n\n") == std::string::npos, "no double newlines");
}

static void test_healthz_returns_true() {
    FimMetrics m;
    EXPECT(m.is_healthy(), "is_healthy returns true");
}

static void test_liveness_format() {
    FimMetrics m;
    std::string l = m.liveness("v4.8.0");
    EXPECT(l.find("\"status\":\"ok\"") != std::string::npos, "status ok");
    EXPECT(l.find("\"version\":\"v4.8.0\"") != std::string::npos, "version in JSON");
    EXPECT(l.find("uptime_seconds") != std::string::npos, "uptime in JSON");
}

static void test_liveness_uptime_increases() {
    FimMetrics m;
    auto l1 = m.liveness("v4.8.0");
    std::this_thread::sleep_for(1.1s);
    auto l2 = m.liveness("v4.8.0");
    // Parse uptime from JSON (simple)
    auto find_int = [](const std::string& s, const std::string& key) -> int {
        auto p = s.find("\"" + key + "\":");
        if (p == std::string::npos) return -1;
        p += key.size() + 3;
        return std::atoi(s.c_str() + p);
    };
    int u1 = find_int(l1, "uptime_seconds");
    int u2 = find_int(l2, "uptime_seconds");
    EXPECT(u2 > u1, "uptime increased");
    EXPECT(u2 - u1 >= 1, "uptime delta >= 1s");
}

static void test_reset_zeroes_counters_but_keeps_metadata() {
    FimMetrics m;
    m.counters().fd_resolved.store(999);
    m.counters().cb_trips.store(7);
    m.reset();
    EXPECT(m.counters().fd_resolved.load() == 0, "fd_resolved reset");
    EXPECT(m.counters().cb_trips.load() == 0, "cb_trips reset");
    EXPECT(m.counters().agent_start_time_unix.load() > 0, "start_time preserved");
}

int main() {
    std::printf("=== FimMetrics tests ===\n");
    test_counters_singleton();
    test_scrape_includes_all_metrics();
    test_scrape_prometheus_format();
    test_healthz_returns_true();
    test_liveness_format();
    test_liveness_uptime_increases();
    test_reset_zeroes_counters_but_keeps_metadata();
    std::printf("=== %d/%d passed, %d failed ===\n",
                g_passed, g_passed + g_failed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
