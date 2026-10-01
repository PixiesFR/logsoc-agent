// fuzz_yara_load_blob.cpp — T4.8.11 — libFuzzer harness for YaraEngine::load_compiled_blob
//
// Purpose:
//   Fuzz the binary blob loader. The .yarac format is libyara-internal
//   and the parser has historically been a source of CVEs (yr_rules_load
//   reads variable-length integers, offsets, and a serialized rules
//   graph — any unchecked offset can be turned into a heap read/write).
//
// What we exercise:
//   - yr_rules_load_stream (the only entry point we call)
//   - The libyara internal deserializer (rule atoms, jump tables, etc.)
//   - Our severity_json sidecar parser (json::parse on attacker-influenced
//     string — the SHA256 is verified first, but if the attacker
//     controls the central response they can match it)
//
// What we DO NOT exercise:
//   - scan_buffer / scan_file (already isolated; no fuzzer benefit)
//   - compile_rules() (YARA source compilation; libyara's own
//     yr_compiler_* is already covered by upstream's oss-fuzz corpus)
//
// Build:
//   clang++ -std=c++17 -O1 -g -Wall -fno-omit-frame-pointer \
//           -Isrc -Isrc/yara \
//           -fsanitize=address,fuzzer,fuzzer-no-link \
//           tests/fuzz_yara_load_blob.cpp \
//           src/yara/yara_engine.cpp \
//           src/agent/sha256_helper.cpp \
//           -lpcap -lbpf -lelf -lz -ldl -lcrypto -lyara \
//           -o /tmp/fuzz_yara_load_blob
//
//   # Then link libFuzzer:
//   clang++ ... -fsanitize=fuzzer ...  # drops the no-link
//
// Run (60s, default corpus in /tmp/fuzz_yara_corpus):
//   mkdir -p /tmp/fuzz_yara_corpus
//   /tmp/fuzz_yara_load_blob /tmp/fuzz_yara_corpus
//       -max_total_time=60 -max_len=1048576 -rss_limit_mb=2048
//
// Expected on PASS: "DEDUP_TOKEN:" stays stable across runs, exit 0.
// Expected on BUG: crash dump in stderr, non-zero exit. The fuzzer
// will save the crashing input to crash-<sha1>.bin in the corpus dir.

#include "../src/yara/yara_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 1. Split the fuzzer input into:
    //    - first 1 byte: mode (0=pure blob, 1=blob+sidecar, 2=blob+forced-no-sha)
    //    - remaining: payload bytes
    //
    // Layout v2: we no longer embed a fake SHA in the fuzzer input.
    // Instead, we pass empty expected_sha (skip SHA verify) on most
    // inputs so the yr_rules_load_stream path is actually exercised.
    // The SHA verify path is unit-tested separately (test_yara_blob_load).
    if (size < 1) {
        return 0;
    }
    if (size > 16 * 1024 * 1024) {
        return 0;  // 16 MiB hard cap; libyara will OOM otherwise
    }

    uint8_t mode = data[0];
    const uint8_t* payload = data + 1;
    size_t payload_size = size - 1;

    std::vector<uint8_t> blob;
    std::string expected_sha;     // empty = skip verify (we want to hit yr_rules_load_stream)
    std::string severity_json;    // empty = no sidecar

    if (mode == 0) {
        // 0 = pure blob, no sidecar — main fuzz target
        blob.assign(payload, payload + payload_size);
    } else if (mode == 1) {
        // 1 = blob + 256-byte sidecar — exercises json::parse
        size_t sidecar_len = (payload_size > 256) ? 256 : payload_size;
        size_t blob_size = payload_size - sidecar_len;
        if (blob_size > 0) {
            blob.assign(payload, payload + blob_size);
        }
        if (sidecar_len > 0) {
            severity_json.assign(reinterpret_cast<const char*>(payload + blob_size), sidecar_len);
        }
    } else {
        // 2..255: pure blob (uniformly random bytes → yr_rules_load_stream)
        blob.assign(payload, payload + payload_size);
    }

    // Build a minimal YaraConfig and YaraEngine. We need yr_initialize
    // to have been called, so the YaraEngine ctor handles it. We
    // construct a fresh engine per fuzzer iteration to mirror the
    // "load a brand-new blob into a fresh ruleset" code path.
    logsoc::YaraConfig cfg;
    cfg.enabled = true;
    cfg.chunk_size = 1000;  // T65 default; not used by load_compiled_blob
    cfg.max_compile_ms = 0; // not used by load_compiled_blob

    // We intentionally leak the YaraEngine if it throws during ctor,
    // but YaraEngine's ctor does not throw — it returns ERROR_SUCCESS
    // or logs to stderr. yr_initialize is also non-throwing.
    logsoc::YaraEngine engine(cfg);

    // 2. Fuzz target: load_compiled_blob. This calls:
    //    - sha256_hex(blob) (cheap, always done)
    //    - yr_rules_load_stream  <-- THE surface we want to fuzz
    //    - yr_rules_destroy (on error)
    //    - json::parse(severity_json) on the sidecar (mode 1)
    //
    // Expected outcomes on adversarial input:
    //   - 0 returned (yr_rules_load_stream error, empty blob)
    //   - non-zero returned (successful load, 1 chunk)
    //   - stderr noise (acceptable, we don't care)
    //
    // Unexpected outcomes (these are BUGS):
    //   - crash (segfault, abort, ASan report)
    //   - hang > 5s (libyara internal loop on crafted input)
    //   - heap corruption detected by ASan
    size_t result = engine.load_compiled_blob(blob, expected_sha, severity_json);
    (void)result;  // 0 = rejected, >0 = chunks loaded

    // 3. YaraEngine destructor calls yr_rules_destroy on rules_.
    //    If the load succeeded, we now have a real YR_RULES* in engine.
    //    If load failed, rules_ is empty and dtor is a no-op.

    return 0;
}
