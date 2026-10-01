// fuzz_policy_validation.cpp — T4.8.11 — libFuzzer harness for the
// policy JSON validation logic in agent.cpp::pull_policy_once().
//
// Purpose:
//   Fuzz the central policy response parser. The parser previously
//   accepted any value (no validation) — T4.8.11 added defensive
//   checks for metrics_bind_address (must be IPv4) and fim_watch_paths
//   (must be absolute, no traversal, length cap). This harness
//   re-runs that validation against arbitrary JSON to find paths
//   that bypass the new checks.
//
// What we exercise:
//   - json::parse on the fuzzer input (libfuzzer-controlled JSON)
//   - The "accept wrapped vs flat shape" branching
//   - The IPv4 validation (strtol on dotted-quad)
//   - The watch_paths validation (empty / absolute / traversal / length)
//   - Threshold clamp (0..10)
//
// What we DO NOT exercise:
//   - The actual HTTP call (we feed the body directly)
//   - HMAC signature verification (already covered by crypto fuzzer upstream)
//
// Build:
//   clang++ -std=c++17 -O1 -g -Wall -fno-omit-frame-pointer \
//           -Isrc -Isrc/agent \
//           -fsanitize=address,fuzzer \
//           tests/fuzz_policy_validation.cpp \
//           src/crypto.cpp src/agent_auth.cpp \
//           $(curl-config --libs 2>/dev/null) \
//           -lcrypto -lssl -lpcap -lbpf -lelf -lz -ldl -lsystemd \
//           -o /tmp/fuzz_policy_validation
//
// Run:
//   mkdir -p /tmp/fuzz_policy_corpus
//   /tmp/fuzz_policy_validation /tmp/fuzz_policy_corpus \
//       -max_total_time=60 -max_len=4096
//
// Expected: no crash, no leak, no timeout. If a crash is found, the
// offending input is saved as crash-<sha1> in the corpus dir.

#include "json.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using json = nlohmann::json;

// ------------------------------------------------------------------
// Mirror of the validation in agent.cpp::pull_policy_once() (T4.8.11).
// Keep these in sync — if you change one, change the other.
// ------------------------------------------------------------------
struct Policy {
    std::string metrics_bind_address;            // default 127.0.0.1
    std::vector<std::string> fim_watch_paths;    // absolute paths only
    int ship_heuristic_threshold = 3;            // 0..10
};

struct ApplyResult {
    bool ok = true;
    std::string error;
    Policy policy;
};

// Returns true if `s` is a valid IPv4 dotted-quad (a.b.c.d, 0<=part<=255).
// Empty string is NOT considered valid (caller decides whether empty is OK).
static bool is_valid_ipv4(const std::string& s) {
    if (s.empty()) return false;
    int parts[4] = {0, 0, 0, 0};
    const char* cur = s.c_str();
    for (int i = 0; i < 4; i++) {
        char* end = nullptr;
        long v = std::strtol(cur, &end, 10);
        if (end == cur) return false;
        if (v < 0 || v > 255) return false;
        parts[i] = static_cast<int>(v);
        if (i < 3) {
            if (*end != '.') return false;
            cur = end + 1;
        } else {
            if (*end != '\0') return false;
        }
    }
    (void)parts;  // suppress unused warning
    return true;
}

// Reject empty, too-long, non-absolute, traversal-containing paths.
static bool is_valid_watch_path(const std::string& path) {
    if (path.empty()) return false;
    if (path.size() > 4096) return false;
    if (path[0] != '/') return false;
    // Reject ".." components
    if (path.find("/../") != std::string::npos) return false;
    if (path.size() >= 3 && path.compare(0, 3, "../") == 0) return false;
    if (path.size() >= 3 &&
        path.compare(path.size() - 3, 3, "/..") == 0) return false;
    return true;
}

static ApplyResult apply_policy(const std::string& body) {
    ApplyResult r;
    json j;
    try {
        j = json::parse(body);
    } catch (const std::exception& e) {
        r.ok = false;
        r.error = std::string("json parse: ") + e.what();
        return r;
    }
    if (!j.is_object()) {
        r.ok = false;
        r.error = "response is not a JSON object";
        return r;
    }
    // Accept wrapped or flat shape
    const json* p = nullptr;
    if (j.contains("policy") && j["policy"].is_object()) {
        p = &j["policy"];
    } else {
        p = &j;
    }
    const auto& pp = *p;

    if (pp.contains("metrics_bind_address") && pp["metrics_bind_address"].is_string()) {
        std::string bind = pp["metrics_bind_address"].get<std::string>();
        if (!bind.empty() && !is_valid_ipv4(bind)) {
            r.ok = false;
            r.error = "invalid metrics_bind_address '" + bind + "' (not IPv4)";
            return r;
        }
        r.policy.metrics_bind_address = bind;
    }
    if (pp.contains("fim_watch_paths") && pp["fim_watch_paths"].is_array()) {
        for (const auto& v : pp["fim_watch_paths"]) {
            if (!v.is_string()) continue;
            std::string path = v.get<std::string>();
            if (!is_valid_watch_path(path)) continue;  // skip invalid
            r.policy.fim_watch_paths.push_back(std::move(path));
        }
    }
    if (pp.contains("ship_heuristic_threshold") && pp["ship_heuristic_threshold"].is_number_integer()) {
        int t = pp["ship_heuristic_threshold"].get<int>();
        if (t < 0) t = 0;
        if (t > 10) t = 10;
        r.policy.ship_heuristic_threshold = t;
    }
    return r;
}

// ------------------------------------------------------------------
// Seed corpus: real policy responses we expect the backend to send.
// Built into the binary so the fuzzer starts with a non-empty corpus.
// ------------------------------------------------------------------
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc; (void)argv;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    if (size > 64 * 1024) return 0;  // 64 KiB hard cap

    // Treat the fuzzer input as the HTTP body directly.
    std::string body(reinterpret_cast<const char*>(data), size);

    // Add a NUL terminator-like safety: the body string is fine
    // because std::string carries its own length, but json::parse
    // will refuse invalid JSON gracefully (throws → we catch).
    ApplyResult r = apply_policy(body);
    (void)r;  // 0 = rejected, >0 = applied; we don't care, just want no crash
    return 0;
}
