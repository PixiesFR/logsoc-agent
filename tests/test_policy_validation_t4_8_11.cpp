// test_policy_validation_t4_8_11.cpp — T4.8.11 — unit tests for the
// defensive policy validation added to agent.cpp::pull_policy_once().
//
// Build:
//   g++ -std=c++17 -O0 -g -Wall -pthread -Isrc -o /tmp/test_policy_validation_t4_8_11 \
//       tests/test_policy_validation_t4_8_11.cpp
//   /tmp/test_policy_validation_t4_8_11
//
// This test is a copy of the validation logic, so it is NOT a
// "test the real code" but a "test the test the real code mirrors".
// If you change the validation in agent.cpp, mirror the change here.

#include "json.hpp"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using json = nlohmann::json;

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
                  << " (got '" << _a << "' vs '" << _b << "') at " \
                  << __FILE__ << ":" << __LINE__ << "\n"; \
        ++g_failures; \
    } \
} while(0)

static bool is_valid_ipv4(const std::string& s) {
    if (s.empty()) return false;
    const char* cur = s.c_str();
    for (int i = 0; i < 4; i++) {
        char* end = nullptr;
        long v = std::strtol(cur, &end, 10);
        if (end == cur) return false;
        if (v < 0 || v > 255) return false;
        if (i < 3) {
            if (*end != '.') return false;
            cur = end + 1;
        } else {
            if (*end != '\0') return false;
        }
    }
    return true;
}

static bool is_valid_watch_path(const std::string& path) {
    if (path.empty()) return false;
    if (path.size() > 4096) return false;
    if (path[0] != '/') return false;
    if (path.find("/../") != std::string::npos) return false;
    if (path.size() >= 3 && path.compare(0, 3, "../") == 0) return false;
    if (path.size() >= 3 &&
        path.compare(path.size() - 3, 3, "/..") == 0) return false;
    return true;
}

int main() {
    // -------- IPv4 validation --------
    EXPECT(is_valid_ipv4("127.0.0.1"));
    EXPECT(is_valid_ipv4("0.0.0.0"));
    EXPECT(is_valid_ipv4("255.255.255.255"));
    EXPECT(is_valid_ipv4("192.168.1.42"));
    EXPECT(!is_valid_ipv4(""));                // empty
    EXPECT(!is_valid_ipv4("not-an-ip"));       // garbage
    EXPECT(!is_valid_ipv4("256.0.0.1"));       // part > 255
    EXPECT(!is_valid_ipv4("1.2.3"));           // only 3 parts
    EXPECT(!is_valid_ipv4("1.2.3.4.5"));       // 5 parts
    EXPECT(!is_valid_ipv4("1.2.3."));          // trailing dot
    EXPECT(!is_valid_ipv4(".1.2.3.4"));        // leading dot
    EXPECT(!is_valid_ipv4("1.2.3.a"));         // non-digit
    EXPECT(!is_valid_ipv4("-1.2.3.4"));        // negative
    // Note: strtol("04") returns 4; we accept "1.2.3.04" as 1.2.3.4.
    // This is NOT a security issue (any IPv4 leading zeros still parse to same host).
    // Document the actual behavior:
    EXPECT(is_valid_ipv4("1.2.3.04"));         // leading zero: strtol accepts as 1.2.3.4

    // -------- Path validation --------
    EXPECT(is_valid_watch_path("/etc/passwd"));
    EXPECT(is_valid_watch_path("/"));
    EXPECT(is_valid_watch_path("/var/log/auth.log"));
    EXPECT(!is_valid_watch_path(""));              // empty
    EXPECT(!is_valid_watch_path("etc/passwd"));    // not absolute
    EXPECT(!is_valid_watch_path("relative/path")); // not absolute
    EXPECT(!is_valid_watch_path("../etc/passwd")); // traversal
    EXPECT(!is_valid_watch_path("/a/../etc"));     // traversal
    EXPECT(!is_valid_watch_path("/etc/.."));       // ends with /..
    {
        // Edge case: root "/" IS a valid absolute path with no traversal
        EXPECT(is_valid_watch_path("/"));
        // Edge case: very long paths
        std::string too_long(5000, 'a');
        too_long[0] = '/';
        EXPECT(!is_valid_watch_path(too_long));
    }

    // -------- Threshold clamping --------
    {
        // Simulate the clamp logic from agent.cpp
        auto clamp = [](int t) { if (t < 0) t = 0; if (t > 10) t = 10; return t; };
        EXPECT_EQ(clamp(0), 0);
        EXPECT_EQ(clamp(3), 3);
        EXPECT_EQ(clamp(10), 10);
        EXPECT_EQ(clamp(-5), 0);
        EXPECT_EQ(clamp(99), 10);
    }

    // -------- JSON parsing sanity --------
    {
        json j = json::parse(R"({"policy": {"metrics_bind_address": "0.0.0.0"}})");
        EXPECT(j.is_object());
        EXPECT(j["policy"].is_object());
        EXPECT_EQ(j["policy"]["metrics_bind_address"].get<std::string>(), "0.0.0.0");
    }
    {
        // Reject malformed JSON
        bool caught = false;
        try { json::parse("{not valid"); } catch (...) { caught = true; }
        EXPECT(caught);
    }
    {
        // Reject non-object root
        json j = json::parse("[1, 2, 3]");
        EXPECT(!j.is_object());
    }

    if (g_failures == 0) {
        std::cerr << "=== ALL policy validation tests PASSED ===\n";
        return 0;
    } else {
        std::cerr << "=== " << g_failures << " policy validation tests FAILED ===\n";
        return 1;
    }
}
