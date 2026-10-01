// test_fd_resolver.cpp — T4.8.2 — unit tests for FdResolver
//
// Build:
//   g++ -std=c++17 -O2 -pthread -Isrc/agent -o test_fd_resolver
//       tests/test_fd_resolver.cpp
//       src/agent/fd_resolver.cpp src/agent/circuit_breaker.cpp
//   ./test_fd_resolver

#include "../src/agent/fd_resolver.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace logsoc::agent::fd;
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
    std::snprintf(buf, sizeof(buf), "/tmp/fd_cb_%d.json", getpid());
    ::unlink(buf);
    return buf;
}

// 1. resolve_sync on a real file via /proc/self/fd/<n>
static void test_resolve_self() {
    int fd = ::open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        std::fprintf(stderr, "skip test_resolve_self: cannot open /etc/hostname\n");
        g_passed++;  // soft-skip
        return;
    }
    std::string p = FdResolver::resolve_sync(::getpid(), fd, 100ms);
    EXPECT(p == "/etc/hostname", "resolve_sync returns the absolute path");
    ::close(fd);
}

// 2. resolve_sync on a closed fd returns empty
static void test_resolve_closed_fd() {
    int fd = ::open("/etc/hostname", O_RDONLY);
    ::close(fd);
    std::string p = FdResolver::resolve_sync(::getpid(), fd, 100ms);
    EXPECT(p.empty(), "closed fd → empty result");
}

// 3. resolve_sync on a non-existent pid
static void test_resolve_invalid_pid() {
    std::string p = FdResolver::resolve_sync(99999999, 0, 50ms);
    EXPECT(p.empty(), "non-existent pid → empty");
}

// 4. is_valid_path
static void test_is_valid_path() {
    EXPECT(FdResolver::is_valid_path("/etc/passwd"), "valid abs path");
    EXPECT(FdResolver::is_valid_path("/"), "root");
    EXPECT(!FdResolver::is_valid_path(""), "empty");
    EXPECT(!FdResolver::is_valid_path("etc/passwd"), "relative");
    EXPECT(!FdResolver::is_valid_path(std::string(5000, 'a')), "too long");
    EXPECT(!FdResolver::is_valid_path("/foo/../bar"), "path traversal");
    EXPECT(!FdResolver::is_valid_path("/foo/../"), "path traversal end");
    EXPECT(FdResolver::is_valid_path("/foo/bar"), "nested path");
    EXPECT(FdResolver::is_valid_path("/proc/self/fd/3"), "proc path");
}

// 5. submit() and on_done callback fires
static void test_submit_callback() {
    Config cfg;
    cfg.cb_state_file = make_tmp_cb();
    cfg.worker_count = 2;
    cfg.queue_capacity = 16;
    cfg.per_resolve_timeout = 100ms;
    FdResolver r(cfg);
    int fd = ::open("/etc/hostname", O_RDONLY);
    EXPECT(fd >= 0, "open /etc/hostname");
    std::atomic<bool> done{false};
    std::string captured;
    bool captured_ok = false;
    ResolveRequest req{(uint32_t)::getpid(), fd, 12345ULL,
        [&](uint32_t, int, uint64_t, const std::string& p, bool ok) {
            captured = p;
            captured_ok = ok;
            done.store(true);
        }};
    EXPECT(r.submit(req), "submit returns true");
    for (int i = 0; i < 100 && !done.load(); ++i) std::this_thread::sleep_for(10ms);
    EXPECT(done.load(), "on_done called within 1s");
    EXPECT(captured_ok, "on_done reports ok=true");
    EXPECT(captured == "/etc/hostname", "captured path matches");
    EXPECT(r.resolved_total() == 1, "resolved_total=1");
    ::close(fd);
}

// 6. Backpressure: full queue returns false
static void test_queue_full() {
    Config cfg;
    cfg.cb_state_file = make_tmp_cb();
    cfg.worker_count = 0;  // no workers, queue never drains
    cfg.queue_capacity = 2;
    cfg.per_resolve_timeout = 10ms;
    FdResolver r(cfg);
    EXPECT(r.submit(ResolveRequest{1, 0, 0, nullptr}), "submit 1");
    EXPECT(r.submit(ResolveRequest{1, 0, 0, nullptr}), "submit 2");
    EXPECT(!r.submit(ResolveRequest{1, 0, 0, nullptr}), "submit 3 (queue full)");
    EXPECT(r.dropped_total() == 1, "dropped=1");
}

// 7. Stats: errors on non-existent pid
static void test_stats_not_found() {
    Config cfg;
    cfg.cb_state_file = make_tmp_cb();
    cfg.worker_count = 1;
    cfg.queue_capacity = 16;
    cfg.per_resolve_timeout = 50ms;
    FdResolver r(cfg);
    std::atomic<int> cnt{0};
    ResolveRequest req{99999999, 0, 0,
        [&](uint32_t, int, uint64_t, const std::string&, bool) {
            cnt.fetch_add(1);
        }};
    EXPECT(r.submit(req), "submit");
    for (int i = 0; i < 100 && cnt.load() == 0; ++i) std::this_thread::sleep_for(10ms);
    EXPECT(cnt.load() == 1, "on_done called");
    EXPECT(r.not_found_total() == 1, "not_found_total=1");
}

// 8. Stress: 1000 resolves
static void test_stress() {
    Config cfg;
    cfg.cb_state_file = make_tmp_cb();
    cfg.worker_count = 4;
    cfg.queue_capacity = 1024;
    cfg.per_resolve_timeout = 50ms;
    FdResolver r(cfg);
    std::atomic<int> done{0};
    int fd = ::open("/etc/hostname", O_RDONLY);
    EXPECT(fd >= 0, "open /etc/hostname");
    for (int i = 0; i < 1000; ++i) {
        r.submit(ResolveRequest{(uint32_t)::getpid(), fd, (uint64_t)i,
            [&](uint32_t, int, uint64_t, const std::string&, bool) {
                done.fetch_add(1);
            }});
    }
    for (int i = 0; i < 500 && done.load() < 1000; ++i) std::this_thread::sleep_for(10ms);
    EXPECT(done.load() == 1000, "all 1000 done");
    EXPECT(r.resolved_total() == 1000, "resolved_total=1000");
    EXPECT(r.timeout_total() == 0, "no timeouts");
    EXPECT(r.eperm_total() == 0, "no eperm");
    ::close(fd);
}

// 9. Concurrent submit from many threads
static void test_concurrent_submit() {
    Config cfg;
    cfg.cb_state_file = make_tmp_cb();
    cfg.worker_count = 4;
    cfg.queue_capacity = 8192;
    cfg.per_resolve_timeout = 50ms;
    FdResolver r(cfg);
    std::atomic<int> done{0};
    int fd = ::open("/etc/hostname", O_RDONLY);
    EXPECT(fd >= 0, "open");
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 500; ++i) {
                r.submit(ResolveRequest{(uint32_t)::getpid(), fd, (uint64_t)(t * 1000 + i),
                    [&](uint32_t, int, uint64_t, const std::string&, bool) {
                        done.fetch_add(1);
                    }});
            }
        });
    }
    for (auto& th : threads) th.join();
    for (int i = 0; i < 500 && done.load() < 2000; ++i) std::this_thread::sleep_for(10ms);
    EXPECT(done.load() == 2000, "all 2000 done across 4 threads");
    ::close(fd);
}

// 10. Destructor is clean (no thread leaks, no crashes)
static void test_destructor_clean() {
    for (int i = 0; i < 50; ++i) {
        Config cfg;
        cfg.cb_state_file = make_tmp_cb();
        cfg.worker_count = 4;
        cfg.queue_capacity = 64;
        cfg.per_resolve_timeout = 10ms;
        FdResolver r(cfg);
        // Submit a few requests
        r.submit(ResolveRequest{1, 0, 0, nullptr});
        r.submit(ResolveRequest{1, 0, 0, nullptr});
    }
    EXPECT(true, "50 constructors+destructors did not crash");
}

int main() {
    std::printf("=== FdResolver tests ===\n");
    test_resolve_self();
    test_resolve_closed_fd();
    test_resolve_invalid_pid();
    test_is_valid_path();
    test_submit_callback();
    test_queue_full();
    test_stats_not_found();
    test_stress();
    test_concurrent_submit();
    test_destructor_clean();
    std::printf("=== %d/%d passed, %d failed ===\n",
                g_passed, g_passed + g_failed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
