// test_fim_collector.cpp — T4.8.5 — unit tests for FimCollector
//
// Build:
//   g++ -std=c++17 -O2 -pthread -Isrc/agent -o test_fim_collector
//       tests/test_fim_collector.cpp
//       src/agent/fim_collector.cpp src/agent/fd_resolver.cpp
//       src/agent/circuit_breaker.cpp
//   ./test_fim_collector

#include "../src/agent/fim_collector.hpp"
#include "../src/agent/fd_resolver.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <thread>
#include <unistd.h>

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

static std::string make_tmp_cb() {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "/tmp/fim_cb_%d.json", getpid());
    ::unlink(buf);
    return buf;
}

static void test_write_fd_resolves_and_publishes() {
    logsoc::agent::fd::Config fdc;
    fdc.cb_state_file = make_tmp_cb();
    fdc.worker_count = 2;
    fdc.queue_capacity = 16;
    fdc.per_resolve_timeout = 100ms;
    logsoc::agent::fd::FdResolver resolver(fdc);
    logsoc::agent::fim::Config fc;
    fc.enable_watchdog = false;
    fc.ship_queue_capacity = 16;
    logsoc::agent::fim::FimCollector coll(fc, resolver);
    int fd = ::open("/etc/hostname", O_RDONLY);
    EXPECT(fd >= 0, "open /etc/hostname");
    EXPECT(coll.on_write_fd_event((uint32_t)::getpid(), fd, 12345ULL), "submit write_fd");
    logsoc::agent::fim::FimEvent ev;
    EXPECT(coll.pop_ship_event(ev, 500ms), "pop returns true");
    EXPECT(ev.abs_path == "/etc/hostname", "abs_path is /etc/hostname");
    EXPECT(ev.resolution == "ok", "resolution=ok");
    ::close(fd);
}

static void test_mitre_tag_on_passwd() {
    logsoc::agent::fd::Config fdc;
    fdc.cb_state_file = make_tmp_cb();
    fdc.worker_count = 2;
    logsoc::agent::fd::FdResolver resolver(fdc);
    logsoc::agent::fim::Config fc;
    fc.enable_watchdog = false;
    logsoc::agent::fim::FimCollector coll(fc, resolver);
    int fd = ::open("/etc/passwd", O_RDONLY);
    EXPECT(fd >= 0, "open /etc/passwd");
    coll.on_write_fd_event((uint32_t)::getpid(), fd, 99);
    logsoc::agent::fim::FimEvent ev;
    coll.pop_ship_event(ev, 500ms);
    EXPECT(!ev.mitre.empty(), "MITRE tags present");
    EXPECT(ev.mitre[0] == "T1003.008", "first technique is T1003.008");
    ::close(fd);
}

static void test_ship_queue_overflow_drops_oldest() {
    logsoc::agent::fd::Config fdc;
    fdc.cb_state_file = make_tmp_cb();
    fdc.worker_count = 1;
    logsoc::agent::fd::FdResolver resolver(fdc);
    logsoc::agent::fim::Config fc;
    fc.enable_watchdog = false;
    fc.ship_queue_capacity = 2;
    logsoc::agent::fim::FimCollector coll(fc, resolver);
    int fd = ::open("/etc/hostname", O_RDONLY);
    EXPECT(fd >= 0, "open");
    for (int i = 0; i < 5; ++i) {
        coll.on_write_fd_event((uint32_t)::getpid(), fd, (uint64_t)i);
    }
    std::this_thread::sleep_for(200ms);
    int popped = 0;
    logsoc::agent::fim::FimEvent ev;
    while (coll.pop_ship_event(ev, 50ms)) popped++;
    EXPECT(popped == 2, "queue cap 2 → only 2 events kept");
    EXPECT(coll.dropped_total() >= 3, "dropped >= 3");
    ::close(fd);
}

static void test_rate_limit_per_pid() {
    logsoc::agent::fd::Config fdc;
    fdc.cb_state_file = make_tmp_cb();
    fdc.worker_count = 0;
    logsoc::agent::fd::FdResolver resolver(fdc);
    logsoc::agent::fim::Config fc;
    fc.enable_watchdog = false;
    fc.rate_limit_per_pid_per_sec = 5;
    logsoc::agent::fim::FimCollector coll(fc, resolver);
    int accepted = 0;
    for (int i = 0; i < 100; ++i) {
        if (coll.on_fim_event(12345, "foo.txt", (uint64_t)i, "write")) {
            accepted++;
        }
    }
    EXPECT(accepted <= 6, "first burst accepted, rest rate-limited");
    EXPECT(coll.rate_limited_total() >= 94, "rate_limited >= 94");
}

static void test_watchdog_pings() {
    logsoc::agent::fd::Config fdc;
    fdc.cb_state_file = make_tmp_cb();
    logsoc::agent::fd::FdResolver resolver(fdc);
    logsoc::agent::fim::Config fc;
    fc.enable_watchdog = true;
    fc.watchdog_period = 1s;
    logsoc::agent::fim::FimCollector coll(fc, resolver);
    std::this_thread::sleep_for(1.2s);
    logsoc::agent::fim::FimEvent ev;
    EXPECT(coll.pop_ship_event(ev, 100ms), "watchdog ping received");
    EXPECT(std::string(ev.operation) == "watchdog", "operation=watchdog");
    EXPECT(coll.watchdog_pings() >= 1, "watchdog_pings >= 1");
}

static void test_destructor_clean() {
    for (int i = 0; i < 20; ++i) {
        logsoc::agent::fd::Config fdc;
        fdc.cb_state_file = make_tmp_cb();
        logsoc::agent::fd::FdResolver resolver(fdc);
        logsoc::agent::fim::Config fc;
        fc.enable_watchdog = true;
        logsoc::agent::fim::FimCollector coll(fc, resolver);
    }
    EXPECT(true, "20 ctor/dtor cycles OK");
}

// T4.8.22: regression test for bug #6 — std::stoul("1234:passwd") CRASH.
// garbage_collect_pending() must NOT throw on a valid pid:basename key.
//
// The previous code did `uint32_t pid_val = std::stoul(it->first);` which
// throws std::invalid_argument when it->first is "1234:passwd" (stoul
// stops at the ':'). This is a real-world regression because EVERY pending
// fim key is "pid:basename" — so the very first GC iteration would
// std::terminate the agent. This test reproduces the exact scenario and
// asserts that garbage_collect_pending completes without exception.
static void test_gc_no_crash_on_pid_colon_basename() {
    logsoc::agent::fd::Config fdc;
    fdc.cb_state_file = make_tmp_cb();
    fdc.worker_count = 2;  // need workers to process the resolver queue
    logsoc::agent::fd::FdResolver resolver(fdc);
    logsoc::agent::fim::Config fc;
    fc.enable_watchdog = false;
    fc.fim_window = 5ms;  // tiny merge window so GC kicks in fast
    logsoc::agent::fim::FimCollector coll(fc, resolver);

    // Capture exceptions thrown by the GC. If the previous stoul() bug
    // is present, the GC will throw std::invalid_argument. The callback
    // runs in a worker thread, so we must rely on the destructor NOT
    // aborting: if std::terminate fires, the test process dies with
    // signal 6 and g_failed stays at the previous value.
    coll.on_fim_event(1234u, "passwd", 99999ULL, "write");
    // Wait > merge window so the pending entry is now "stale"
    std::this_thread::sleep_for(20ms);
    // Trigger GC by submitting a write_fd for a different pid (any pid).
    // The callback (in on_write_fd_event) calls garbage_collect_pending,
    // which will iterate pending_fim_ and try to parse the key.
    int fd = ::open("/etc/hostname", O_RDONLY);
    EXPECT(fd >= 0, "open /etc/hostname for write_fd trigger");
    coll.on_write_fd_event(9999u, fd, 1ULL);  // different pid → GC runs in callback
    std::this_thread::sleep_for(50ms);
    // Drain events — the stale passwd event should have been published via
    // GC, AND the new hostname event via the resolver callback.
    logsoc::agent::fim::FimEvent ev;
    int popped = 0;
    while (coll.pop_ship_event(ev, 50ms)) popped++;
    EXPECT(popped >= 1, "at least 1 event published (no crash)");
    ::close(fd);
    // The test only succeeds if no exception escaped the FimCollector.
    // If garbage_collect_pending threw std::invalid_argument, the
    // std::thread in FdResolver would std::terminate, killing the
    // process. We made it here, so the bug is fixed.
    EXPECT(true, "no crash on pid:basename GC");
}

int main() {
    std::printf("=== FimCollector tests ===\n");
    test_write_fd_resolves_and_publishes();
    test_mitre_tag_on_passwd();
    test_ship_queue_overflow_drops_oldest();
    test_rate_limit_per_pid();
    test_watchdog_pings();
    test_destructor_clean();
    test_gc_no_crash_on_pid_colon_basename();
    std::printf("=== %d/%d passed, %d failed ===\n",
                g_passed, g_passed + g_failed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
