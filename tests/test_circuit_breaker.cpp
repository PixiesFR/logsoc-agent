// test_circuit_breaker.cpp — T4.8.4 — unit tests for CircuitBreaker
//
// Build:
//   g++ -std=c++17 -O2 -pthread -Isrc/agent -o test_circuit_breaker
//       tests/test_circuit_breaker.cpp src/agent/circuit_breaker.cpp
//   ./test_circuit_breaker

#include "../src/agent/circuit_breaker.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <utime.h>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

using namespace logsoc::agent::cb;
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

static std::string make_tmp_state() {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "/tmp/cb_state_%d.json", getpid());
    // Clean up first
    ::unlink(buf);
    return buf;
}

static void test_starts_closed() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "starts CLOSED");
    EXPECT(cb.allow(), "allow()=true when CLOSED");
    EXPECT(cb.trips_total() == 0, "trips=0");
}

static void test_threshold_trips_open() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.window_size = 10;
    cfg.failure_threshold = 3;
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "starts CLOSED");
    for (int i = 0; i < 2; ++i) cb.on_failure();
    EXPECT(cb.state() == State::CLOSED, "still CLOSED at 2/3");
    cb.on_failure();
    EXPECT(cb.state() == State::OPEN, "OPEN at 3/3");
    EXPECT(!cb.allow(), "allow()=false when OPEN");
    EXPECT(cb.trips_total() == 1, "trips=1 after 1 trip");
}

// T4.8.18 PHASE 2: production has 700+ processes, fd churn is high.
// Default threshold (5) was too aggressive, caused CB to trip in
// seconds on Hestia. New default is 50. This test verifies the
// default-config behavior.
static void test_default_threshold_is_50() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    // Use the default threshold (don't override) — should be 50
    EXPECT(cfg.failure_threshold == 50, "default failure_threshold is 50 (was 5, too aggressive)");
    EXPECT(cfg.open_duration == std::chrono::milliseconds{60000},
           "default open_duration is 60s (was 30s)");
    // Verify the CB itself uses these defaults
    CircuitBreaker cb(cfg);
    for (int i = 0; i < 49; ++i) cb.on_failure();
    EXPECT(cb.state() == State::CLOSED, "49/50 failures → still CLOSED (default threshold is 50)");
    cb.on_failure();
    EXPECT(cb.state() == State::OPEN, "50/50 failures → OPEN");
}

static void test_recovery_after_timeout() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.window_size = 10;
    cfg.failure_threshold = 2;
    cfg.open_duration = 100ms;
    CircuitBreaker cb(cfg);
    cb.on_failure();
    cb.on_failure();
    EXPECT(cb.state() == State::OPEN, "OPEN");
    EXPECT(!cb.allow(), "OPEN: no allow");
    std::this_thread::sleep_for(150ms);
    // T4.8.14 hotfix: after open_duration, allow() now transitions
    // directly to CLOSED (not HALF_OPEN) to avoid the deadlock where
    // HALF_OPEN is never reached because no requests flow when CB is OPEN.
    EXPECT(cb.allow(), "after 150ms: allow (recovery to CLOSED)");
    EXPECT(cb.state() == State::CLOSED, "CLOSED after timeout recovery");
    // Window is reset → can absorb N failures again before re-tripping
    cb.on_failure();
    EXPECT(cb.state() == State::CLOSED, "1 failure after recovery → still CLOSED (window reset)");
}

static void test_half_open_failure_reopens() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.failure_threshold = 2;
    cfg.open_duration = 50ms;
    CircuitBreaker cb(cfg);
    cb.on_failure();
    cb.on_failure();
    EXPECT(cb.state() == State::OPEN, "OPEN");
    std::this_thread::sleep_for(80ms);
    // T4.8.14 hotfix: transitions to CLOSED, not HALF_OPEN. So the
    // post-allow state is CLOSED, not HALF_OPEN. The "probe failed →
    // re-OPEN" code path is now exercised only by an explicit trip()
    // or by reaching failure_threshold in the recovered window.
    EXPECT(cb.allow(), "after 80ms: allow (recovery to CLOSED)");
    EXPECT(cb.state() == State::CLOSED, "CLOSED after timeout");
    // 2 fresh failures → re-trip
    cb.on_failure();
    cb.on_failure();
    EXPECT(cb.state() == State::OPEN, "re-OPEN after 2 fresh failures");
    EXPECT(!cb.allow(), "OPEN: no allow again");
}

static void test_success_resets_window() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.window_size = 5;
    cfg.failure_threshold = 3;
    CircuitBreaker cb(cfg);
    cb.on_failure();
    cb.on_failure();
    EXPECT(cb.state() == State::CLOSED, "2/3 failures, still CLOSED");
    for (int i = 0; i < 5; ++i) cb.on_success();
    // Window is now [fail, fail, succ, succ, succ] → 2 failures only
    cb.on_failure();  // 3rd failure
    EXPECT(cb.state() == State::CLOSED, "3rd failure + 5 successes → still CLOSED (window slid)");
}

static void test_sliding_window_eviction() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.window_size = 4;
    cfg.failure_threshold = 3;
    CircuitBreaker cb(cfg);
    cb.on_failure();
    cb.on_failure();
    cb.on_failure();
    EXPECT(cb.state() == State::OPEN, "3/3 → OPEN");
    // After trip, we can still call on_success (records in window)
    cb.on_success();  // would add a success to window but CB is OPEN
    EXPECT(cb.state() == State::OPEN, "still OPEN");
}

static void test_persistence_creates_file() {
    auto sf = make_tmp_state();
    {
        Config cfg;
        cfg.state_file = sf;
        cfg.failure_threshold = 1;
        CircuitBreaker cb(cfg);
        cb.on_failure();  // trips
        EXPECT(cb.state() == State::OPEN, "OPEN");
    }
    // File should now exist and contain "OPEN"
    std::ifstream in(sf);
    EXPECT(in.good(), "state file exists after trip");
    std::stringstream ss;
    ss << in.rdbuf();
    auto body = ss.str();
    EXPECT(body.find("OPEN") != std::string::npos, "file contains OPEN");
    EXPECT(body.find("trips") != std::string::npos, "file contains trips counter");
}

static void test_load_restores_open() {
    auto sf = make_tmp_state();
    // T4.8.16: we no longer restore the state, only the trips counter.
    // The state always starts CLOSED. This test now asserts that a
    // persisted OPEN file is IGNORED at boot (safer default).
    {
        std::ofstream out(sf);
        out << "{\"state\":\"OPEN\",\"trips\":7}\n";
    }
    Config cfg;
    cfg.state_file = sf;
    cfg.failure_threshold = 999;  // would not naturally trip
    cfg.open_duration = 60s;
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "persisted OPEN is ignored at boot → starts CLOSED");
    EXPECT(cb.trips_total() == 7, "trips=7 still restored for metrics");
}

// T4.8.16 PHASE 2 hotfix v2: unconditionally start CLOSED at boot.
// The previous design (restore OPEN from disk) could deadlock the
// agent if the previous run died before the recovery timer could
// trigger. Symptom in prod: every fim_v4_8 event had filename=<unknown>
// and tag cb_open, even after restart.
// See circuit_breaker.cpp::load_state() comment for the full analysis.
static void test_load_stale_open_resets_to_closed() {
    auto sf = make_tmp_state();
    {
        std::ofstream out(sf);
        out << "{\"state\":\"OPEN\",\"trips\":42}\n";
    }
    Config cfg;
    cfg.state_file = sf;
    cfg.failure_threshold = 999;
    cfg.open_duration = 60s;
    // Backdate mtime — but T4.8.16 doesn't even look at mtime anymore.
    struct utimbuf ut;
    ut.actime = ut.modtime = std::time(nullptr) - 120;
    ::utime(sf.c_str(), &ut);
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "always CLOSED at boot regardless of mtime");
    EXPECT(cb.trips_total() == 42, "trips=42 still restored for observability");
    EXPECT(cb.allow(), "CLOSED → allow()=true");
}

// T4.8.16: a fresh HALF_OPEN file is also ignored (we never persist
// HALF_OPEN in production, but if the file is corrupted that way,
// we should still start CLOSED).
static void test_load_halffopen_ignored() {
    auto sf = make_tmp_state();
    {
        std::ofstream out(sf);
        out << "{\"state\":\"HALF_OPEN\",\"trips\":3}\n";
    }
    Config cfg;
    cfg.state_file = sf;
    cfg.open_duration = 60s;
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "persisted HALF_OPEN ignored at boot → CLOSED");
}

static void test_load_missing_file_is_closed() {
    auto sf = make_tmp_state();
    ::unlink(sf.c_str());  // ensure missing
    Config cfg;
    cfg.state_file = sf;
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "missing file → CLOSED (safe default)");
}

static void test_load_corrupt_file_is_closed() {
    auto sf = make_tmp_state();
    {
        std::ofstream out(sf);
        out << "this is not json\n";
    }
    Config cfg;
    cfg.state_file = sf;
    CircuitBreaker cb(cfg);
    EXPECT(cb.state() == State::CLOSED, "corrupt file → CLOSED");
}

static void test_no_persist_if_state_file_empty() {
    Config cfg;
    // state_file empty → no file written
    CircuitBreaker cb(cfg);
    cb.trip();
    EXPECT(cb.state() == State::OPEN, "OPEN even without persistence");
}

static void test_trips_counter() {
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.failure_threshold = 1;
    cfg.open_duration = 50ms;
    CircuitBreaker cb(cfg);
    cb.on_failure();  // trip 1
    EXPECT(cb.trips_total() == 1, "trips=1");
    std::this_thread::sleep_for(80ms);
    cb.allow();  // HALF_OPEN
    cb.on_success();  // CLOSED
    cb.on_failure();  // trip 2
    EXPECT(cb.trips_total() == 2, "trips=2 after second trip");
    cb.on_failure();  // already OPEN, no new trip
    EXPECT(cb.trips_total() == 2, "trips still 2");
}

static void test_concurrent_calls() {
    // Stress: 4 threads × 10000 calls each. Should never crash, never
    // report inconsistent state.
    auto sf = make_tmp_state();
    Config cfg;
    cfg.state_file = sf;
    cfg.failure_threshold = 50;
    cfg.window_size = 100;
    CircuitBreaker cb(cfg);
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&cb, t]() {
            for (int i = 0; i < 10000; ++i) {
                if (cb.allow()) {
                    if (t % 2 == 0) cb.on_success();
                    else cb.on_failure();
                }
            }
        });
    }
    for (auto& th : threads) th.join();
    // Just check it didn't crash and the trips counter is sane.
    EXPECT(cb.trips_total() < 1000, "trips counter sane (no runaway)");
    EXPECT(cb.state() == State::OPEN || cb.state() == State::HALF_OPEN,
           "concurrent stress ended in OPEN or HALF_OPEN");
}

static void test_state_name() {
    EXPECT(std::strcmp(state_name(State::CLOSED), "CLOSED") == 0, "CLOSED");
    EXPECT(std::strcmp(state_name(State::OPEN), "OPEN") == 0, "OPEN");
    EXPECT(std::strcmp(state_name(State::HALF_OPEN), "HALF_OPEN") == 0, "HALF_OPEN");
}

int main() {
    std::printf("=== CircuitBreaker tests ===\n");
    test_starts_closed();
    test_threshold_trips_open();
    test_default_threshold_is_50();
    test_recovery_after_timeout();
    test_half_open_failure_reopens();
    test_success_resets_window();
    test_sliding_window_eviction();
    test_persistence_creates_file();
    test_load_restores_open();
    test_load_stale_open_resets_to_closed();
    test_load_halffopen_ignored();
    test_load_missing_file_is_closed();
    test_load_corrupt_file_is_closed();
    test_no_persist_if_state_file_empty();
    test_trips_counter();
    test_concurrent_calls();
    test_state_name();
    std::printf("=== %d/%d passed, %d failed ===\n",
                g_passed, g_passed + g_failed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
