// yara/yara_engine.hpp — YARA HQ integration for the LogSOC agent
//
// This module compiles a set of YARA rules pulled from the central
// (via /api/v1/yara/active) and exposes simple scan functions for
// files, process memory, network buffers, and log lines.
//
// Threading: the engine is read-mostly after rule load. The compiled
// YR_RULES* is immutable between updates, so scan_file/scan_buffer
// can be called concurrently from any thread. update_rules() is the
// only writer and uses a swap (atomic-like) under a mutex.
//
// Mode bitmask (matches the backend scan_flags):
//   bit 0 = file      → scan_file()
//   bit 1 = memory    → scan_memory()
//   bit 2 = network   → scan_buffer() (called by pcap module)
//   bit 3 = logs      → scan_buffer() (called by worker, not agent)
//
// The agent only handles bits 0, 1, 2. Bit 3 (logs) is the worker's
// job — the agent never touches log lines.

#pragma once

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// Include yara.h in the header so its typedefs (YR_COMPILER, YR_RULES,
// YR_RULE) match the forward declarations used in method signatures.
#include <yara.h>

namespace logsoc {

struct YaraConfig {
    bool enabled = false;                 // master switch (false = engine inert)
    int scan_flags = 0;                   // bitmask: which modes this agent runs
    std::string central_url;              // for heartbeat pull
    std::string agent_id;                 // for /yara/results posting
    std::string hmac_token;               // for HMAC-signed heartbeat
    int heartbeat_interval_sec = 300;     // pull rules every N seconds
    int max_rule_size_kb = 64;            // reject rules larger than this
    int max_scan_file_mb = 50;            // skip files larger than this
    int scan_timeout_ms = 5000;           // per-scan timeout
    int match_post_interval_sec = 10;     // throttle match posts to central
    int max_compile_ms = 30000;           // v3.17.0 (T61.1): bound the
                                          //   compile_rules() wall time.
                                          //   0 = unbounded (legacy).
    int chunk_size = 1000;                // v3.19.0 (T65): compile rules
                                          //   in chunks of N to avoid
                                          //   libyara 4.5's "merge fails
                                          //   when too many rules interact"
                                          //   bug. Each chunk is compiled
                                          //   in its own YR_RULES*; we keep
                                          //   a vector of YR_RULES* and
                                          //   scan with each at scan time.
};

struct YaraMatch {
    std::string rule_id;
    std::string rule_name;
    std::string severity;       // low|medium|high|critical (from YaraRule.severity)
    std::string source_type;    // file|memory|network|log
    std::string target_path;    // path, "tcp:5tuple", "/proc/<pid>/exe", etc.
    std::string payload_sha256; // SHA256 of the scanned content
    std::string raw_match;      // JSON: which strings matched at which offsets
};

class YaraEngine {
public:
    explicit YaraEngine(const YaraConfig& cfg);
    ~YaraEngine();

    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;

    // Initialize the libyara library. Returns true on success.
    bool init();

    // Pull active rules from central (HTTP) and recompile. Replaces
    // the current rule set atomically. Returns number of rules loaded.
    // 0 = no rules (or central unreachable, leaves previous set intact).
    size_t pull_rules_from_central();

    // Re-compile from a list of {rule_id, rule_text}. Used by tests
    // and by pull_rules_from_central internally.
    size_t compile_rules(const std::vector<std::pair<std::string, std::string>>& rules);

    // T77 (v3.21.0): load a pre-compiled YARA ruleset blob (format
    // `.yarac` from libyara 4.5). This is the central-push counterpart
    // to compile_rules(): instead of compiling .yar source, we load
    // already-compiled bytes. ~100x faster than compile_rules() at
    // 7761 rules (8s vs 0.08s), and the format is portable across
    // libyara 4.5.x patch versions.
    //
    // PITFALLS:
    //   - We do NOT use yr_compiler_load_rules_from_buffer (this
    //     function does NOT exist in libyara's public API).
    //     The libyara way to load a pre-compiled blob is
    //     yr_rules_load_stream() with a memory-backed YR_STREAM.
    //   - The blob MUST have been produced by libyara MAJOR+MINOR
    //     4.0+ (we tested with 4.5). 4.0 → 4.5 patches are OK.
    //     For libyara < 4.0, this method will not work and the
    //     fallback compile_rules path must be used.
    //   - On error, the previous ruleset is preserved (atomic
    //     swap semantics — we never half-update).
    //
    // Returns: number of chunks loaded (=1 in this case, since
    // the blob is a single YR_RULES*). 0 = error (logged).
    //
    // T77.6: severity_json is a JSON sidecar
    //   {"<rule_id>": "low"|"medium"|"high"|"critical"}
    // pushed by the admin tool. The .yarac binary itself
    // doesn't carry per-rule metadata, so without this the
    // matches show severity="unknown" in the UI. If empty,
    // rule_severity_ stays empty (matches → "unknown").
    size_t load_compiled_blob(const std::vector<uint8_t>& blob,
                              const std::string& expected_sha256,
                              const std::string& severity_json = "");

    // Scan a file on disk. source_type must be "file" or "memory".
    // Posts matches to central asynchronously (throttled).
    void scan_file(const std::string& path, const std::string& source_type = "file");

    // Scan a memory buffer. Used by pcap module (source_type=network)
    // and by callers that have already read the file into memory.
    void scan_buffer(const std::string& target_id, const uint8_t* data, size_t len,
                     const std::string& source_type);

    // Statistics (for heartbeat)
    size_t rule_count() const;
    uint64_t total_scans() const { return total_scans_.load(); }
    uint64_t total_matches() const { return total_matches_.load(); }
    uint64_t total_compile_errors() const { return compile_errors_.load(); }
    // v3.17.0 (T61.1): how many times compile_rules() hit the
    // deadline. 0 = never (good). >0 = ruleset is stale, agent is
    // running on the previous ruleset until the next successful pull.
    uint64_t total_compile_timeouts() const { return compile_timeouts_.load(); }

    // Called from C-style libyara callback. Public so the friend
    // C function can bump the counter; not part of the public API.
    void bump_match_count() { total_matches_.fetch_add(1); }

private:
    // Apply pending rules atomically (called under mutex_).
    // v3.19.0 (T65): takes a vector<YR_RULES*> instead of a single one
    // because rules are chunked at compile time.
    void apply_compiled(std::vector<YR_RULES*>&& chunks);

    // SHA256 of a buffer (used for payload_sha256 field).
    static std::string sha256_hex(const uint8_t* data, size_t len);

    // SHA256 of a file path.
    static std::string sha256_file(const std::string& path);

    // Post a single match to /api/v1/yara/results (HTTP POST).
    void post_match(const YaraMatch& m);

    // Throttled post (drops matches if last post was < interval ago).
    bool should_post_now();

    YaraConfig cfg_;

    // Active rules (read by scan threads). v3.19.0 (T65): vector of
    // YR_RULES* instead of a single pointer. Each chunk is compiled in
    // isolation to avoid libyara 4.5's "merge with too many rules
    // fails" bug. At scan time, we iterate over the chunks and call
    // yr_rules_scan_mem for each, merging the matches.
    std::vector<YR_RULES*> rules_;

    // Rule metadata: rule_id → severity (parallel to rules_).
    std::map<std::string, std::string> rule_severity_;
    std::map<std::string, std::string> rule_names_;

    // v3.10.4: SHA256 of the last compiled ruleset. Used to skip
    // re-compilation when the rules haven't changed between pulls
    // (which is the common case — periodic pull_interval_sec=300s but
    // rules are updated rarely). Without this cache, every 5min pull
    // would re-run the O(n²) compile and burn ~6h CPU per 8h uptime.
    std::string last_ruleset_hash_;

    mutable std::mutex mutex_;

    std::atomic<uint64_t> total_scans_{0};
    std::atomic<uint64_t> total_matches_{0};
    std::atomic<uint64_t> compile_errors_{0};
    // v3.17.0 (T61.1): see total_compile_timeouts()
    std::atomic<uint64_t> compile_timeouts_{0};

    std::chrono::steady_clock::time_point last_post_at_;
};

} // namespace logsoc
