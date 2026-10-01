// test_yara_blob_load.cpp — T77 / v3.21.0
//
// Unit test for YaraEngine::load_compiled_blob(). The flow:
//   1. Compile a tiny YARA rule via yr_compiler_add_string() +
//      yr_compiler_get_rules() + yr_rules_save_stream() → blob.
//   2. Compute SHA256 of the blob.
//   3. Call load_compiled_blob() with that blob and sha256.
//   4. Verify rule_count() == 1, and that scan_buffer finds the match.
//
// We also test the failure paths:
//   - Empty blob → 0 returned, previous ruleset preserved.
//   - Bad SHA256 → 0 returned, previous ruleset preserved.
//   - Garbage blob → 0 returned, previous ruleset preserved.
//
// The libyara public API for SERIALIZING rules is yr_rules_save_stream
// (we use this here, in the test, to produce a valid blob). The
// corresponding DESERIALIZE API is yr_rules_load_stream (used internally
// by YaraEngine::load_compiled_blob). This is the canonical pattern.

#include "yara/yara_engine.hpp"
#include <yara.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>

static int g_failures = 0;

#define EXPECT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "  FAIL [" << __LINE__ << "]: " << msg << std::endl; \
        ++g_failures; \
    } else { \
        std::cout << "  ok   [" << __LINE__ << "]: " << msg << std::endl; \
    } \
} while (0)

// Tiny in-memory YR_STREAM writer used to produce a blob.
struct MemWriter {
    std::vector<uint8_t>& buf;
};
static size_t mem_write(const void* ptr, size_t size, size_t count, void* user) {
    auto* mw = static_cast<MemWriter*>(user);
    size_t bytes = size * count;
    auto* p = static_cast<const uint8_t*>(ptr);
    mw->buf.insert(mw->buf.end(), p, p + bytes);
    return count;
}

// SHA256 helper (re-declared here since yara_engine::sha256_hex is private).
// We use the openssl SHA256 via SHA256() from <openssl/sha.h>.
#include <openssl/sha.h>
static std::string sha256_hex_str(const std::vector<uint8_t>& data) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), md);
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + 2*i, 3, "%02x", md[i]);
    }
    return std::string(hex);
}

// Compile a 1-rule YR_RULES*, save it to blob, return blob + sha256.
static std::vector<uint8_t> compile_and_save(const std::string& rule_text,
                                             std::string* out_sha) {
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "yr_compiler_create failed" << std::endl;
        return {};
    }
    int rc = yr_compiler_add_string(compiler, rule_text.c_str(), nullptr);
    if (rc != 0) {
        char errbuf[512];
        std::cerr << "yr_compiler_add_string: " << yr_compiler_get_error_message(compiler, errbuf, sizeof(errbuf)) << std::endl;
        yr_compiler_destroy(compiler);
        return {};
    }
    YR_RULES* rules = nullptr;
    rc = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    if (rc != ERROR_SUCCESS || !rules) {
        std::cerr << "yr_compiler_get_rules failed: " << rc << std::endl;
        return {};
    }

    std::vector<uint8_t> buf;
    MemWriter mw{buf};
    YR_STREAM stream;
    stream.user_data = &mw;
    stream.read = nullptr;
    stream.write = mem_write;
    rc = yr_rules_save_stream(rules, &stream);
    yr_rules_destroy(rules);
    if (rc != ERROR_SUCCESS) {
        std::cerr << "yr_rules_save_stream failed: " << rc << std::endl;
        return {};
    }
    *out_sha = sha256_hex_str(buf);
    return buf;
}

static int test_load_simple_rule() {
    std::cout << "[test_load_simple_rule]" << std::endl;
    logsoc::YaraConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval_sec = 0;  // disable the pull thread
    cfg.scan_flags = 3;  // bit0=file, bit1=memory — both enabled for test

    logsoc::YaraEngine engine(cfg);
    EXPECT(engine.init(), "engine.init() succeeds");

    std::string rule_text =
        "rule T77_test_rule { "
        "  strings: $a = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\" "
        "  condition: $a "
        "}";
    std::string sha;
    std::vector<uint8_t> blob = compile_and_save(rule_text, &sha);
    EXPECT(!blob.empty(), "compile_and_save produced non-empty blob");
    EXPECT(!sha.empty(), "sha256 computed");
    std::cout << "  blob size=" << blob.size() << " sha=" << sha << std::endl;

    size_t n = engine.load_compiled_blob(blob, sha);
    EXPECT(n == 1, "load_compiled_blob returns 1 on success");
    // After the T77.5 BUGFIX, rule_count() returns rules_.size()
    // (= number of YR_RULES* chunks) when the severity map is empty.
    // A loaded blob = 1 chunk. The exact rule count is not exposed
    // by libyara's public load API; we get a chunk-count lower bound.
    EXPECT(engine.rule_count() == 1, "rule_count()=1 (1 YR_RULES* chunk loaded; T77.5 BUGFIX)");

    // Scan a buffer that matches. total_matches_ is bumped by the
    // YR_CALLBACK when the rule fires. We verify it incremented
    // (proving the rule IS active in the YR_RULES*).
    uint64_t before_matches = engine.total_matches();
    const std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE$";
    engine.scan_buffer("test_target", (const uint8_t*)eicar.data(), eicar.size(), "memory");
    EXPECT(engine.total_scans() == 1, "total_scans incremented");
    EXPECT(engine.total_matches() == before_matches + 1, "EICAR match found by the loaded rule");
    return 0;
}

static int test_bad_sha() {
    std::cout << "[test_bad_sha]" << std::endl;
    logsoc::YaraConfig cfg;
    cfg.enabled = true;
    logsoc::YaraEngine engine(cfg);
    EXPECT(engine.init(), "engine.init() succeeds");

    std::string rule_text = "rule t { condition: true }";
    std::string sha;
    std::vector<uint8_t> blob = compile_and_save(rule_text, &sha);

    size_t before = engine.rule_count();
    size_t n = engine.load_compiled_blob(blob, "0000000000000000000000000000000000000000000000000000000000000000");
    EXPECT(n == 0, "bad sha → returns 0");
    EXPECT(engine.rule_count() == before, "ruleset unchanged on bad sha");
    return 0;
}

static int test_empty_blob() {
    std::cout << "[test_empty_blob]" << std::endl;
    logsoc::YaraConfig cfg;
    cfg.enabled = true;
    logsoc::YaraEngine engine(cfg);
    EXPECT(engine.init(), "engine.init() succeeds");

    std::vector<uint8_t> empty_blob;
    size_t n = engine.load_compiled_blob(empty_blob, "");
    EXPECT(n == 0, "empty blob → returns 0");
    return 0;
}

static int test_garbage_blob() {
    std::cout << "[test_garbage_blob]" << std::endl;
    logsoc::YaraConfig cfg;
    cfg.enabled = true;
    logsoc::YaraEngine engine(cfg);
    EXPECT(engine.init(), "engine.init() succeeds");

    std::vector<uint8_t> garbage(1024, 0xDE);
    std::string sha = sha256_hex_str(garbage);
    size_t before = engine.rule_count();
    size_t n = engine.load_compiled_blob(garbage, sha);
    EXPECT(n == 0, "garbage blob → returns 0");
    EXPECT(engine.rule_count() == before, "ruleset unchanged on garbage");
    return 0;
}

static int test_empty_sha_ok() {
    std::cout << "[test_empty_sha_ok] (no sha check if expected_sha256 is empty)" << std::endl;
    logsoc::YaraConfig cfg;
    cfg.enabled = true;
    logsoc::YaraEngine engine(cfg);
    EXPECT(engine.init(), "engine.init() succeeds");

    std::string rule_text = "rule no_sha_check { condition: true }";
    std::string sha;
    std::vector<uint8_t> blob = compile_and_save(rule_text, &sha);

    size_t n = engine.load_compiled_blob(blob, "");  // empty expected → skip check
    EXPECT(n == 1, "load with empty expected sha → still works");
    // T77.5 BUGFIX: rule_count() now returns rules_.size() (1
    // chunk) when severity map is empty, not 0.
    EXPECT(engine.rule_count() == 1, "rule_count()=1 (T77.5 BUGFIX: chunk count, not 0)");
    return 0;
}

int main() {
    yr_initialize();
    test_load_simple_rule();
    test_bad_sha();
    test_empty_blob();
    test_garbage_blob();
    test_empty_sha_ok();
    yr_finalize();

    std::cout << "\n=== " << (g_failures == 0 ? "PASS" : "FAIL")
              << " (" << g_failures << " failures) ===" << std::endl;
    return g_failures == 0 ? 0 : 1;
}
