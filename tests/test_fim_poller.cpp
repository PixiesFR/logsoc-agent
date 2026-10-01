// test_fim_poller.cpp — T4.8.8 — Unit tests for FimPoller fallback
//
// What we test:
//   1. Initial snapshot is silent (no events on startup).
//   2. Modify a watched file → 1 event with resolution="poller_fallback".
//   3. Delete a watched file → 1 event with operation="delete".
//   4. Re-create same content → no event (SHA matches).
//   5. Modify again → 1 event.
//   6. polls_total() and changes_total() reflect activity.

#include "../src/agent/fim_poller.hpp"
#include "../src/agent/fim_collector.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;

static int g_failures = 0;

#define EXPECT(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << #cond << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
        ++g_failures; \
    } else { \
        std::cout << "  ok: " << #cond << "\n"; \
    } \
} while (0)

// Test wrapper: we can call FimPoller::poll_now() directly to avoid
// waiting 5s for the thread to tick.
static int run_tests() {
    namespace logsoc_fim = logsoc::agent::fim;

    // Create a temp dir for the tests
    fs::path tmpdir = fs::temp_directory_path() / "fim_poller_test";
    fs::create_directories(tmpdir);
    fs::path watched1 = tmpdir / "watched1.txt";
    fs::path watched2 = tmpdir / "watched2.txt";

    // Initial content
    {
        std::ofstream f1(watched1); f1 << "content_v1\n";
        std::ofstream f2(watched2); f2 << "content_a\n";
    }

    // Real FimCollector would need a FdResolver. To keep the test simple
    // and not require that, we can directly verify the FimPoller detects
    // changes via check_path() / poll_now().
    //
    // However FimPoller takes a FimCollector& and pushes events to it.
    // We need a real (but minimal) FimCollector.
    logsoc::agent::fd::Config fdc;
    fdc.worker_count = 1;
    fdc.queue_capacity = 16;
    fdc.per_resolve_timeout = std::chrono::milliseconds(10);
    logsoc::agent::fd::FdResolver resolver(fdc);

    logsoc_fim::Config fcc;
    fcc.ship_queue_capacity = 64;
    fcc.rate_limit_per_pid_per_sec = 100;
    fcc.fim_window = std::chrono::milliseconds(5);
    fcc.enable_watchdog = false;
    logsoc_fim::FimCollector collector(fcc, resolver);

    // Start the poller in a way that doesn't run the thread (we'll
    // call poll_now manually) — but the ctor starts a thread by default.
    // We use watch_paths to enable the thread.
    logsoc_fim::FimPoller::Config pc;
    pc.poll_interval = std::chrono::seconds(1);
    pc.watch_paths = {watched1.string(), watched2.string()};
    logsoc_fim::FimPoller poller(pc, collector);

    // 1. First poll (initial snapshot) — should NOT publish events
    int changes = poller.poll_now();
    EXPECT(changes == 0);  // wait, poll_now returns nothing for now — changes is 0

    // 2. Modify watched1
    {
        std::ofstream f(watched1); f << "content_v2\n";
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    poller.poll_now();
    EXPECT(poller.changes_total() == 1);

    // Pop the event from the collector
    logsoc_fim::FimEvent ev;
    bool got = collector.pop_ship_event(ev, std::chrono::milliseconds(200));
    EXPECT(got);
    if (got) {
        EXPECT(ev.abs_path == watched1.string());
        EXPECT(ev.resolution == "poller_fallback");
    }

    // 3. Modify watched2
    {
        std::ofstream f(watched2); f << "content_b\n";
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    poller.poll_now();
    EXPECT(poller.changes_total() == 2);
    // Drain the modify event
    {
        logsoc_fim::FimEvent tmp;
        collector.pop_ship_event(tmp, std::chrono::milliseconds(200));
    }

    // 4. Re-create watched1 with same content (no change)
    {
        std::ofstream f(watched1); f << "content_v2\n";
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    poller.poll_now();
    EXPECT(poller.changes_total() == 2);  // still 2, no new change

    // 5. Delete watched2
    fs::remove(watched2);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    poller.poll_now();
    EXPECT(poller.changes_total() == 3);

    // Pop the delete event
    got = collector.pop_ship_event(ev, std::chrono::milliseconds(200));
    EXPECT(got);
    if (got) {
        EXPECT(std::string(ev.operation) == "delete");
    }

    // 6. Re-create watched2 with new content
    {
        std::ofstream f(watched2); f << "content_c\n";
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    poller.poll_now();
    EXPECT(poller.changes_total() == 4);
    // Drain
    {
        logsoc_fim::FimEvent tmp;
        collector.pop_ship_event(tmp, std::chrono::milliseconds(200));
    }

    // Verify polls_total() tracks
    EXPECT(poller.polls_total() >= 6);

    // Cleanup
    fs::remove_all(tmpdir);

    return g_failures;
}

int main() {
    std::cout << "=== FimPoller tests ===\n";
    int failures = run_tests();
    if (failures == 0) {
        std::cout << "=== ALL PASSED ===\n";
        return 0;
    }
    std::cerr << "=== " << failures << " FAILED ===\n";
    return 1;
}
