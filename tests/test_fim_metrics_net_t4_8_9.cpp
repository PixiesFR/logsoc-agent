// test_fim_metrics_net_t4_8_9.cpp — T4.8.9 — unit tests for the
// NetworkCollector → FimMetrics unification.
//
// Validates:
//   1. set_net_stats() stores values in the correct Counters atomics
//   2. scrape() includes the 4 new net_* metrics with correct values
//   3. reset() zeros the net_* atomics (but not agent_start_time)
//   4. scrape() does not throw on extreme values (UINT64_MAX-ish)
//
// Build:
//   g++ -std=c++17 -O0 -g -Wall -pthread -Isrc
//       -o /tmp/test_fim_metrics_net_t4_8_9
//       tests/test_fim_metrics_net_t4_8_9.cpp src/agent/fim_metrics.cpp
//   /tmp/test_fim_metrics_net_t4_8_9
//
// Pass criteria: 0 failures, ASan-clean, valgrind-clean.

#include "../src/agent/fim_metrics.hpp"

#include <cstdint>
#include <iostream>
#include <string>

using namespace logsoc::agent::metrics;

static int g_failures = 0;

#define EXPECT(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << #cond << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
        ++g_failures; \
    } \
} while(0)

#define EXPECT_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a != _b) { \
        std::cerr << "FAIL: " << #a << " == " << #b \
                  << " (got " << _a << " vs " << _b << ") at " \
                  << __FILE__ << ":" << __LINE__ << "\n"; \
        ++g_failures; \
    } \
} while(0)

int main() {
    FimMetrics m;
    FimMetrics::set_agent_version("test-version");

    // -------- Test 1: set_net_stats round-trip --------
    FimMetrics::set_net_stats(100, 5, 95, 2);
    EXPECT_EQ(FimMetrics::counters().net_packets_captured.load(), 100u);
    EXPECT_EQ(FimMetrics::counters().net_packets_dropped.load(), 5u);
    EXPECT_EQ(FimMetrics::counters().net_events_pushed.load(), 95u);
    EXPECT_EQ(FimMetrics::counters().net_flush_errors.load(), 2u);

    // -------- Test 2: scrape() includes the 4 new metrics --------
    {
        std::string s = m.scrape(0, 0, 0, "test-version");
        EXPECT(s.find("logsoc_fim_net_packets_captured_total 100") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_packets_dropped_total 5") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_events_pushed_total 95") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_flush_errors_total 2") != std::string::npos);
    }

    // -------- Test 3: zero values do not crash, scrape renders 0 --------
    FimMetrics::set_net_stats(0, 0, 0, 0);
    {
        std::string s = m.scrape(0, 0, 0, "test-version");
        EXPECT(s.find("logsoc_fim_net_packets_captured_total 0") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_packets_dropped_total 0") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_events_pushed_total 0") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_flush_errors_total 0") != std::string::npos);
    }

    // -------- Test 4: extreme values do not crash --------
    FimMetrics::set_net_stats(UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX);
    {
        std::string s = m.scrape(0, 0, 0, "test-version");
        // The exact formatted number is huge; just check the keys exist
        EXPECT(s.find("logsoc_fim_net_packets_captured_total ") != std::string::npos);
        EXPECT(s.find("logsoc_fim_net_flush_errors_total ") != std::string::npos);
    }

    // -------- Test 5: reset() zeros the net_* counters --------
    FimMetrics::set_net_stats(42, 7, 35, 1);
    EXPECT_EQ(FimMetrics::counters().net_packets_captured.load(), 42u);
    m.reset();
    EXPECT_EQ(FimMetrics::counters().net_packets_captured.load(), 0u);
    EXPECT_EQ(FimMetrics::counters().net_packets_dropped.load(), 0u);
    EXPECT_EQ(FimMetrics::counters().net_events_pushed.load(), 0u);
    EXPECT_EQ(FimMetrics::counters().net_flush_errors.load(), 0u);

    // -------- Test 6: reset() does NOT zero agent_start_time_unix --------
    int64_t start_before = FimMetrics::counters().agent_start_time_unix.load();
    FimMetrics::set_net_stats(1, 1, 1, 1);
    m.reset();
    int64_t start_after = FimMetrics::counters().agent_start_time_unix.load();
    EXPECT_EQ(start_before, start_after);

    if (g_failures == 0) {
        std::cerr << "=== ALL FimMetrics net_* tests PASSED ===\n";
        return 0;
    } else {
        std::cerr << "=== " << g_failures << " FimMetrics net_* tests FAILED ===\n";
        return 1;
    }
}
