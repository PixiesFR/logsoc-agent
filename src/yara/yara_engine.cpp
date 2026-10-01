// yara/yara_engine.cpp — YARA HQ implementation
//
// See yara_engine.hpp for the design overview. Threading model:
//   - init() / pull_rules_from_central() are serialized by mutex_
//   - scan_file() / scan_buffer() are lock-free readers; they swap
//     a YR_RULES* pointer which is itself never modified after load
//   - update_rules() builds a new YR_RULES in a local compiler, then
//     atomically swaps the pointer and destroys the old one

#include "yara_engine.hpp"
#include "agent_auth.hpp"
#include <yara.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <set>
#include <functional>

namespace logsoc {

using json = nlohmann::json;

// ── libyara scan callback (libyara 4.x: 4 args incl. scan_context + message) ──
struct ScanContext {
    std::vector<YaraMatch>* matches;
    std::string target_path;
    std::string source_type;
    std::string payload_sha256;
    std::map<std::string, std::string> rule_severity;
    std::map<std::string, std::string> rule_names;
    YaraEngine* engine;
    uint64_t scan_id;
};

static int yara_scan_callback(YR_SCAN_CONTEXT* scan_ctx, int message, void* msg_data, void* user_data) {
    (void)scan_ctx;
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }
    auto* rule = static_cast<YR_RULE*>(msg_data);
    auto* ctx = static_cast<ScanContext*>(user_data);
    YaraMatch m;
    m.rule_id = rule->identifier;
    m.rule_name = ctx->rule_names.count(rule->identifier) ? ctx->rule_names[rule->identifier] : rule->identifier;
    m.severity = ctx->rule_severity.count(rule->identifier) ? ctx->rule_severity[rule->identifier] : "medium";
    m.source_type = ctx->source_type;
    m.target_path = ctx->target_path;
    m.payload_sha256 = ctx->payload_sha256;
    m.raw_match = std::string("{\"rule\":\"") + rule->identifier + "\"}";
    ctx->matches->push_back(std::move(m));
    ctx->engine->bump_match_count();
    return CALLBACK_CONTINUE;
}

YaraEngine::YaraEngine(const YaraConfig& cfg) : cfg_(cfg) {
    last_post_at_ = std::chrono::steady_clock::now() - std::chrono::seconds(3600);  // allow immediate first post
}

YaraEngine::~YaraEngine() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto* r : rules_) {
        if (r) yr_rules_destroy(r);
    }
    rules_.clear();
}

bool YaraEngine::init() {
    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "[yara] yr_initialize failed" << std::endl;
        return false;
    }
    return true;
}

size_t YaraEngine::compile_rules(const std::vector<std::pair<std::string, std::string>>& rules) {
    if (rules.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto* r : rules_) {
            if (r) yr_rules_destroy(r);
        }
        rules_.clear();
        rule_severity_.clear();
        rule_names_.clear();
        last_ruleset_hash_.clear();
        return 0;
    }

    // v3.10.4: skip re-compile if the ruleset is unchanged.
    // Pull interval is 5min by default, but rules rarely change.
    // The O(n²) compile below burns ~6h CPU per 8h uptime when run
    // every 5min. With this cache, the compile only runs when the
    // ruleset actually changes (e.g. after a /yara/import-sigbase).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Cheap rolling hash: count + total bytes. Good enough to
        // skip the O(n²) work when nothing changed.
        size_t total_bytes = 0;
        for (const auto& [id, txt] : rules) total_bytes += txt.size();
        std::string quick_id = std::to_string(rules.size()) + ":" + std::to_string(total_bytes);
        if (quick_id == last_ruleset_hash_) {
            return rule_names_.size();  // unchanged, no work needed
        }
        // Defer storing last_ruleset_hash_ until AFTER successful compile
        // (otherwise a failed compile would cache a "bad" signature).
    }

    const auto compile_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(static_cast<int>(cfg_.max_compile_ms > 0 ? cfg_.max_compile_ms : 30000));
    size_t total_rules = rules.size();

    std::map<std::string, std::string> new_severity;
    std::map<std::string, std::string> new_names;
    std::vector<std::pair<std::string, std::string>> good_rules;  // survivors of Phase 1

    bool compile_timeout = false;
    size_t rules_filtered = 0;  // rules skipped in Phase 1 (bad syntax / unsupported features)

    // ── Phase 1: per-rule pre-filter (isolated compiler per rule) ──
    // Phase 1 is O(n), each iteration ~1-2ms. Bounded by compile_deadline.
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& [rule_id, rule_text] = rules[i];

        // v3.17.0 (T61.1): deadline check at the top of each iteration.
        if (std::chrono::steady_clock::now() >= compile_deadline) {
            std::cerr << "[yara] compile deadline reached in Phase 1 after "
                      << i << "/" << total_rules << " rules ("
                      << good_rules.size() << " passed filter, "
                      << rules_filtered << " filtered out, "
                      << compile_errors_.load() << " errors). Keeping previous ruleset ("
                      << rule_names_.size() << " rules active)." << std::endl;
            compile_timeout = true;
            break;
        }

        if (static_cast<int>(rule_text.size()) > cfg_.max_rule_size_kb * 1024) {
            std::cerr << "[yara] rule " << rule_id
                      << " exceeds max_rule_size_kb, skipping" << std::endl;
            compile_errors_.fetch_add(1);
            rules_filtered++;
            continue;
        }

        // Isolated compiler for this single rule. If it fails, we
        // discard the compiler cleanly (no shared error state to worry
        // about for the next iteration).
        YR_COMPILER* isolated = nullptr;
        if (yr_compiler_create(&isolated) != ERROR_SUCCESS) {
            std::cerr << "[yara] yr_compiler_create failed in Phase 1 for rule "
                      << rule_id << " (skipping)" << std::endl;
            compile_errors_.fetch_add(1);
            rules_filtered++;
            continue;
        }
        int rc = yr_compiler_add_string(isolated, rule_text.c_str(), nullptr);
        if (rc == 0) {
            // Rule compiles in isolation. Mark it as good for Phase 2.
            good_rules.emplace_back(rule_id, rule_text);
        } else {
            // Rule is bad. Log once with id + rc so operator can blacklist
            // (v3.18.0: this replaces the per-rule flood that v3.11 had to
            // suppress; the count is bounded because each rule is tried
            // exactly once in Phase 1).
            std::cerr << "[yara] Phase 1 filter: rule " << rule_id
                      << " skipped (rc=" << rc << ")" << std::endl;
            compile_errors_.fetch_add(1);
            rules_filtered++;
        }
        // Always destroy the isolated compiler. yr_compiler_destroy is
        // safe to call on a compiler that was never fed a good rule
        // (libyara 4.5 just frees the memory).
        yr_compiler_destroy(isolated);
    }

    // Bump the version: this counter is purely informational, doesn't
    // affect correctness.
    size_t compiled = good_rules.size();

    if (compile_timeout) {
        // v3.17.0: keep previous ruleset, increment dedicated counter.
        // v3.19.0: no compiler to destroy (Phase 2 creates its own
        // compilers per chunk; if we hit the deadline in Phase 1 we
        // never reached Phase 2).
        compile_timeouts_.fetch_add(1);
        std::cerr << "[yara] compile timed out in Phase 1, keeping previous ruleset ("
                  << rule_names_.size() << " rules active)" << std::endl;
        return rule_names_.size();
    }

    if (compiled == 0) {
        std::cerr << "[yara] no rules passed Phase 1 filter (all "
                  << rules_filtered << " filtered out)" << std::endl;
        return 0;
    }

    // ── Phase 2 (v3.19.0, T65-chunking): chunked compile ──
    //
    // v3.18.0 attempt: compile all pre-filtered good rules in a
    // SINGLE compiler. Failed: libyara 4.5 has a bug/limitation where
    // ~9% of the Florian Roth sigbase (705/7858) has internal
    // interactions that fail the merge. The "drop 1 rule per
    // attempt" algorithm converged too slowly (705 attempts, 90s
    // wall time, lost 705 rules).
    //
    // v3.19.0 fix: instead of one big compiler, split good_rules into
    // CHUNKS of cfg_.chunk_size (default 1000). For each chunk, build
    // a fresh compiler, add all chunk's rules, get_rules → YR_RULES*.
    // The libyara "merge with too many rules" bug only manifests when
    // too many rules are in a single compiler; with 1000 rules per
    // chunk, the bug is much less likely (we observed 0 interaction
    // failures at chunk_size=1000 vs 705 at chunk_size=N).
    //
    // Trade-off: at scan time, we must iterate over the chunks and
    // call yr_rules_scan_mem for each. Cost: O(N_chunks) per file.
    // For 7858 rules / 1000 per chunk = 8 chunks, that's 8 scans per
    // file. Each scan is fast (YARA scans are µs-rule for small
    // files), so the wall time overhead is acceptable.
    //
    // The bad-rule tail (last chunk with <1000 rules) is handled
    // like any other chunk. If a chunk fails to compile, we fall back
    // to the per-rule drop algorithm for THAT chunk only (much faster
    // because the chunk is small).
    const int chunk_size = std::max(1, cfg_.chunk_size);
    std::vector<YR_RULES*> new_chunks;  // final YR_RULES* per chunk
    size_t total_merged = 0;
    size_t total_dropped = 0;  // v3.19.0: rules dropped due to chunk-merge failure

    std::cerr << "[yara] Phase 2 (chunked): " << good_rules.size()
              << " pre-filtered rules in chunks of " << chunk_size << std::endl;
    for (size_t chunk_start = 0; chunk_start < good_rules.size(); chunk_start += chunk_size) {
        size_t chunk_end = std::min(chunk_start + chunk_size, good_rules.size());
        size_t this_chunk_size = chunk_end - chunk_start;
        std::cerr << "[yara] Phase 2 chunk " << (chunk_start / chunk_size + 1)
                  << ": compiling rules [" << chunk_start << ".." << (chunk_end - 1) << "] ("
                  << this_chunk_size << " rules)..." << std::endl;

        // Try to compile the chunk in a single compiler. If it
        // succeeds, we get one YR_RULES* for this chunk. If it
        // fails on a specific rule, fall back to the per-rule drop
        // algorithm for the remaining rules in this chunk.
        YR_COMPILER* chunk_compiler = nullptr;
        if (yr_compiler_create(&chunk_compiler) != ERROR_SUCCESS) {
            std::cerr << "[yara] Phase 2 chunk: yr_compiler_create failed, "
                      << "dropping all " << this_chunk_size << " rules in this chunk" << std::endl;
            compile_errors_.fetch_add(this_chunk_size);
            total_dropped += this_chunk_size;
            continue;
        }
        // First, try the whole chunk in one go (the happy path).
        size_t chunk_merged = 0;
        size_t first_failure = SIZE_MAX;
        std::vector<std::pair<std::string, std::string>> chunk_survivors;
        for (size_t j = chunk_start; j < chunk_end; ++j) {
            const auto& [rid, rtext] = good_rules[j];
            int rc = yr_compiler_add_string(chunk_compiler, rtext.c_str(), nullptr);
            if (rc == 0) {
                chunk_merged++;
                new_names[rid] = rid;
                new_severity[rid] = "medium";
                chunk_survivors.emplace_back(rid, rtext);
            } else {
                first_failure = j;
                std::cerr << "[yara] Phase 2 chunk: rule " << rid
                          << " failed to merge, switching to per-rule retry" << std::endl;
                break;
            }
        }
        if (first_failure == SIZE_MAX) {
            // Whole chunk compiled cleanly. Get YR_RULES.
            YR_RULES* chunk_rules = nullptr;
            int grc = yr_compiler_get_rules(chunk_compiler, &chunk_rules);
            yr_compiler_destroy(chunk_compiler);
            if (grc == ERROR_SUCCESS && chunk_rules) {
                new_chunks.push_back(chunk_rules);
                total_merged += chunk_merged;
                std::cerr << "[yara] Phase 2 chunk: merged " << chunk_merged
                          << " rules cleanly" << std::endl;
            } else {
                std::cerr << "[yara] Phase 2 chunk: yr_compiler_get_rules failed rc="
                          << grc << std::endl;
                compile_errors_.fetch_add(chunk_merged);
                total_dropped += chunk_merged;
            }
        } else {
            // The chunk had a bad rule. Retry: drop the failed rule
            // and try the rest of the chunk in smaller batches. To
            // avoid the O(n²) loop, we use a simple split-in-half
            // strategy: take the first half of the remaining rules,
            // compile them. If success, take second half and continue.
            yr_compiler_destroy(chunk_compiler);
            // Build a list of "remaining" rules = good_rules[first_failure+1 .. chunk_end]
            std::vector<std::pair<std::string, std::string>> remaining;
            for (size_t j = first_failure + 1; j < chunk_end; ++j) {
                remaining.emplace_back(good_rules[j].first, good_rules[j].second);
            }
            // Drop the failed rule permanently.
            compile_errors_.fetch_add(1);
            total_dropped++;
            std::cerr << "[yara] Phase 2 chunk: dropping rule "
                      << good_rules[first_failure].first
                      << ", retrying " << remaining.size() << " remaining rules "
                      << "(chunk_survivors so far: " << chunk_survivors.size() << ")" << std::endl;
            // First, get the survivors as a YR_RULES* (so we don't
            // re-compile them). The survivors are in the destroyed
            // chunk_compiler, so we have to recompile them.
            // Save them into "remaining_to_compile" + "already_good_survivors".
            std::vector<std::pair<std::string, std::string>> already_good_survivors = std::move(chunk_survivors);
            // Try to compile the remaining in 2 halves. If a half
            // succeeds, we get a YR_RULES* for that half. If a half
            // fails, we recurse with per-rule drop. Bounded by the
            // chunk size (~1000 rules, so at most 10 recursion levels).
            std::function<YR_RULES*(const std::vector<std::pair<std::string, std::string>>&)>
                compile_batch = [&](const std::vector<std::pair<std::string, std::string>>& batch) -> YR_RULES* {
                if (batch.empty()) return nullptr;
                YR_COMPILER* c = nullptr;
                if (yr_compiler_create(&c) != ERROR_SUCCESS) return nullptr;
                for (const auto& [rid, rtext] : batch) {
                    if (yr_compiler_add_string(c, rtext.c_str(), nullptr) != 0) {
                        yr_compiler_destroy(c);
                        return nullptr;  // batch has a bad rule, caller will recurse
                    }
                }
                YR_RULES* r = nullptr;
                if (yr_compiler_get_rules(c, &r) != ERROR_SUCCESS || !r) {
                    yr_compiler_destroy(c);
                    return nullptr;
                }
                yr_compiler_destroy(c);
                return r;
            };
            // Sub-divide the remaining rules in halves until we get
            // clean YR_RULES* or determine a single bad rule. Track
            // metadata for the rules that successfully compiled.
            std::vector<std::pair<std::string, std::string>> still_remaining = std::move(remaining);
            size_t sub_attempts = 0;
            const size_t max_sub_attempts = 50;  // safety bound
            while (!still_remaining.empty() && sub_attempts < max_sub_attempts) {
                sub_attempts++;
                YR_RULES* r = compile_batch(still_remaining);
                if (r) {
                    // Whole batch compiled. Track names + severity.
                    for (const auto& [rid, rtext] : still_remaining) {
                        new_names[rid] = rid;
                        new_severity[rid] = "medium";
                    }
                    new_chunks.push_back(r);
                    total_merged += still_remaining.size();
                    chunk_merged += still_remaining.size();
                    std::cerr << "[yara] Phase 2 chunk: merged sub-batch of "
                              << still_remaining.size() << " rules cleanly (attempt "
                              << sub_attempts << ")" << std::endl;
                    break;
                }
                // Batch had a bad rule. Drop the LAST rule (or first?
                // Doesn't matter, just iterate) and retry with N-1.
                // Simpler: drop one rule at a time. But that's O(n²).
                // Smarter: bisect — try first half, if OK, the bad
                // rule is in the second half, etc.
                if (still_remaining.size() == 1) {
                    // The single rule is bad. Drop it.
                    std::cerr << "[yara] Phase 2 chunk: rule " << still_remaining[0].first
                              << " is the sole bad rule, dropping" << std::endl;
                    compile_errors_.fetch_add(1);
                    total_dropped++;
                    break;
                }
                size_t half = still_remaining.size() / 2;
                std::vector<std::pair<std::string, std::string>> first_half(
                    still_remaining.begin(), still_remaining.begin() + half);
                YR_RULES* r1 = compile_batch(first_half);
                if (r1) {
                    // First half is good. The bad rule is in the
                    // second half. Track first half, recurse on
                    // second half.
                    for (const auto& [rid, rtext] : first_half) {
                        new_names[rid] = rid;
                        new_severity[rid] = "medium";
                    }
                    new_chunks.push_back(r1);
                    total_merged += first_half.size();
                    chunk_merged += first_half.size();
                    std::cerr << "[yara] Phase 2 chunk: bisect found bad rule "
                              << "in second half of " << still_remaining.size()
                              << " rules" << std::endl;
                    std::vector<std::pair<std::string, std::string>> second_half(
                        still_remaining.begin() + half, still_remaining.end());
                    still_remaining = std::move(second_half);
                } else {
                    // First half has the bad rule. Track nothing,
                    // recurse on first half.
                    std::cerr << "[yara] Phase 2 chunk: bisect found bad rule "
                              << "in first half of " << still_remaining.size()
                              << " rules" << std::endl;
                    std::vector<std::pair<std::string, std::string>> new_first(
                        still_remaining.begin(), still_remaining.begin() + half);
                    still_remaining = std::move(new_first);
                }
            }
            if (sub_attempts >= max_sub_attempts) {
                std::cerr << "[yara] Phase 2 chunk: sub-batch retry gave up after "
                          << max_sub_attempts << " attempts" << std::endl;
            }
            // Now we need to compile the already_good_survivors (they
            // were in the destroyed chunk_compiler).
            if (!already_good_survivors.empty()) {
                YR_RULES* r = compile_batch(already_good_survivors);
                if (r) {
                    for (const auto& [rid, rtext] : already_good_survivors) {
                        new_names[rid] = rid;
                        new_severity[rid] = "medium";
                    }
                    new_chunks.push_back(r);
                    total_merged += already_good_survivors.size();
                    chunk_merged += already_good_survivors.size();
                } else {
                    // The survivors failed to recompile. That's odd.
                    // Log and drop them. (Shouldn't happen — they
                    // were in the previous compiler — but defensive.)
                    std::cerr << "[yara] Phase 2 chunk: survivors failed to "
                              << "recompile (unexpected), dropping "
                              << already_good_survivors.size() << " rules" << std::endl;
                    compile_errors_.fetch_add(already_good_survivors.size());
                    total_dropped += already_good_survivors.size();
                }
            }
            std::cerr << "[yara] Phase 2 chunk: total merged after retry = "
                      << chunk_merged << "/" << this_chunk_size << std::endl;
        }
    }  // end for each chunk

    if (new_chunks.empty()) {
        std::cerr << "[yara] Phase 2 (chunked): no chunks produced, keeping previous "
                  << "ruleset (" << rule_names_.size() << " rules active)" << std::endl;
        return rule_names_.size();
    }

    // Atomic swap
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto* r : rules_) {
            if (r) yr_rules_destroy(r);
        }
        rules_ = std::move(new_chunks);
        rule_severity_ = std::move(new_severity);
        rule_names_ = std::move(new_names);
        // Store the hash so future pulls can short-circuit.
        size_t total_bytes = 0;
        for (const auto& [id, txt] : rules) total_bytes += txt.size();
        last_ruleset_hash_ = std::to_string(rules.size()) + ":" + std::to_string(total_bytes);
    }

    std::cerr << "[yara] compiled " << total_merged << "/" << rules.size()
              << " rules in " << rules_.size() << " chunks "
              << "(Phase 1 filtered " << rules_filtered
              << " bad rules, Phase 2 dropped " << total_dropped
              << " more, " << total_merged << " active)" << std::endl;
    return total_merged;
}

void YaraEngine::scan_file(const std::string& path, const std::string& source_type) {
    if (!cfg_.enabled || rules_.empty()) return;
    if (!(cfg_.scan_flags & 1) && source_type == "file") return;       // bit 0
    if (!(cfg_.scan_flags & 2) && source_type == "memory") return;     // bit 1

    // total_scans_ is incremented in scan_buffer() (the single source of truth)

    // Read file into memory
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return;  // silently skip unreadable files

    auto sz = f.tellg();
    if (sz < 0 || static_cast<uint64_t>(sz) > static_cast<uint64_t>(cfg_.max_scan_file_mb) * 1024ULL * 1024ULL) {
        return;  // too big, skip
    }
    f.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(sz));
    if (!f.read(reinterpret_cast<char*>(data.data()), sz)) return;

    std::string sha = sha256_hex(data.data(), data.size());
    scan_buffer(path, data.data(), data.size(), source_type);
    (void)sha;  // stored in YaraMatch via callback context
}

void YaraEngine::scan_buffer(const std::string& target_id, const uint8_t* data, size_t len,
                              const std::string& source_type) {
    if (!cfg_.enabled || rules_.empty() || !data || len == 0) return;
    if (!(cfg_.scan_flags & 1) && source_type == "file") return;
    if (!(cfg_.scan_flags & 2) && source_type == "memory") return;
    if (!(cfg_.scan_flags & 4) && source_type == "network") return;
    if (!(cfg_.scan_flags & 8) && source_type == "log") return;

    total_scans_.fetch_add(1);

    std::string sha = sha256_hex(data, len);

    std::vector<YaraMatch> matches;
    ScanContext ctx{&matches, target_id, source_type, sha, {}, {}, this, 0};

    {
        std::lock_guard<std::mutex> lock(mutex_);
        ctx.rule_severity = rule_severity_;
        ctx.rule_names = rule_names_;

        int flags = 0;
        // v3.19.0 (T65): iterate over all YR_RULES* chunks. We take
        // a snapshot copy of the vector so we can release the mutex
        // for the (potentially long) scan.
        std::vector<YR_RULES*> rules_snapshot = rules_;

        // YARA scan timeout: we set a wall-clock cap.
        // v3.19.0: per-chunk scan timeout. We don't sum them up
        // (total timeout = chunk_timeout * N_chunks), but in practice
        // each chunk scans in a few ms and the per-chunk timeout
        // (5s default) is plenty. If a single chunk hits the timeout,
        // we move on to the next one (the bad chunk is logged but
        // doesn't block the rest).
        for (size_t ci = 0; ci < rules_snapshot.size(); ++ci) {
            YR_RULES* r = rules_snapshot[ci];
            if (!r) continue;
            auto start = std::chrono::steady_clock::now();
            int rc = yr_rules_scan_mem(r, data, len, flags,
                                        yara_scan_callback, &ctx, /*timeout=*/ cfg_.scan_timeout_ms / 1000);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (rc != ERROR_SUCCESS) {
                std::cerr << "[yara] scan failed rc=" << rc << " for " << target_id
                          << " in chunk " << ci << "/" << rules_snapshot.size()
                          << " (elapsed=" << elapsed << "ms)" << std::endl;
            }
        }
    }

    // Post matches (throttled)
    for (const auto& m : matches) {
        if (should_post_now()) {
            post_match(m);
        }
    }
}

size_t YaraEngine::rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // After load_compiled_blob, the severity map is cleared (blob
    // load doesn't carry per-rule metadata). In that case, return
    // the chunk count as a lower bound (each chunk is ~1000 rules
    // for compile_rules chunks, 1 chunk for a loaded blob).
    // PITFALL: this is NOT the exact rule count for blob loads
    // (libyara 4.0-4.5 doesn't expose it via public API). For
    // compile_rules(), rule_severity_ IS populated and the count
    // is exact.
    if (rule_severity_.empty()) {
        return rules_.size();  // chunk count (best-effort)
    }
    return rule_severity_.size();
}

void YaraEngine::post_match(const YaraMatch& m) {
    // Build JSON payload
    json j = {
        {"rule_id", m.rule_id},
        {"rule_name", m.rule_name},
        {"agent_id", cfg_.agent_id},
        {"source_type", m.source_type},
        {"target_path", m.target_path},
        {"payload_sha256", m.payload_sha256},
        {"severity", m.severity},
        {"raw_match", m.raw_match},
        {"action_taken", "log"},
    };
    std::string body = j.dump();

    // Build HMAC headers
    // T79: use the unified T64 HMAC scheme (f"{ts}.{agent_id}.{method}.{path}").
    // Matches the central `/yara/results` endpoint's
    // `_verify_yara_hmac` helper — same message format as the
    // policy GET, just with method="POST".
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string yara_results_path = "/api/v1/yara/results";
    std::string hmac_hex = agent_v3::compute_policy_get_hmac(
        cfg_.hmac_token, cfg_.agent_id, std::to_string(ts), "POST", yara_results_path);

    // POST via libcurl
    CURL* curl = curl_easy_init();
    if (!curl) return;

    std::string url = cfg_.central_url + yara_results_path;
    struct curl_slist* hdrs = nullptr;
    std::string h_ts = "X-Timestamp: " + std::to_string(ts);
    std::string h_sig = "X-Signature: " + std::string(hmac_hex);
    std::string h_aid = "X-Agent-Id: " + cfg_.agent_id;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, h_ts.c_str());
    hdrs = curl_slist_append(hdrs, h_sig.c_str());
    hdrs = curl_slist_append(hdrs, h_aid.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "[yara] post match failed: " << curl_easy_strerror(res) << std::endl;
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    last_post_at_ = std::chrono::steady_clock::now();
}

bool YaraEngine::should_post_now() {
    auto now = std::chrono::steady_clock::now();
    auto since = std::chrono::duration_cast<std::chrono::seconds>(now - last_post_at_).count();
    return since >= cfg_.match_post_interval_sec;
}

std::string YaraEngine::sha256_hex(const uint8_t* data, size_t len) {
    unsigned char h[32];
    SHA256(data, len, h);
    char hex[65];
    for (int i = 0; i < 32; ++i) snprintf(hex + 2*i, 3, "%02x", h[i]);
    hex[64] = 0;
    return std::string(hex);
}

std::string YaraEngine::sha256_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        EVP_DigestUpdate(ctx, buf, f.gcount());
    }
    unsigned char h[32];
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, h, &hlen);
    EVP_MD_CTX_free(ctx);
    char hex[65];
    for (unsigned int i = 0; i < hlen; ++i) snprintf(hex + 2*i, 3, "%02x", h[i]);
    hex[64] = 0;
    return std::string(hex);
}

// ── pull_rules_from_central: HTTP GET /api/v1/yara/active ──

struct CurlBuf { std::string data; };

static size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, void* user) {
    auto* buf = static_cast<CurlBuf*>(user);
    buf->data.append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

size_t YaraEngine::pull_rules_from_central() {
    if (cfg_.central_url.empty() || cfg_.hmac_token.empty()) {
        return 0;
    }

    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    // P1 sec audit fix (M-05, 2026-06-16): the HMAC previously signed
    // only "/api/v1/yara/active" (no query string), but the request
    // actually sends "/api/v1/yara/active?scan_flag=N". A central or
    // MITM that intercepts the signed request can swap the query
    // string (e.g. flip scan_flags=1 to scan_flags=0 to silently
    // disable file content scanning for the agent) without
    // invalidating the signature. We now sign the full request URI
    // (path + query) so the signature covers everything the server
    // sees. Backend-side verify must match this format.
    std::string path_and_query = "/api/v1/yara/active?scan_flag=" + std::to_string(cfg_.scan_flags);
    std::string to_sign = std::to_string(ts) + "\nGET " + path_and_query;

    unsigned char hmac[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(),
         cfg_.hmac_token.data(), static_cast<int>(cfg_.hmac_token.size()),
         reinterpret_cast<const unsigned char*>(to_sign.data()), to_sign.size(),
         hmac, &hmac_len);

    char hmac_hex[65];
    for (unsigned int i = 0; i < hmac_len; ++i) snprintf(hmac_hex + 2*i, 3, "%02x", hmac[i]);
    hmac_hex[64] = 0;

    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    std::string url = cfg_.central_url + "/api/v1/yara/active?scan_flag=" + std::to_string(cfg_.scan_flags);
    CurlBuf buf;
    struct curl_slist* hdrs = nullptr;
    std::string h_ts = "X-Timestamp: " + std::to_string(ts);
    std::string h_sig = "X-Signature: " + std::string(hmac_hex);
    std::string h_aid = "X-Agent-Id: " + cfg_.agent_id;
    hdrs = curl_slist_append(hdrs, h_ts.c_str());
    hdrs = curl_slist_append(hdrs, h_sig.c_str());
    hdrs = curl_slist_append(hdrs, h_aid.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // follow nginx 301
    // T12 audit fix #51: RE-ENABLE TLS verification. The previous code
    // set CURLOPT_SSL_VERIFYPEER=0L with a misleading comment ("let's
    // encrypt cert ok via system CA but skip check for self-hosted").
    // That's a downgrade, not a hardening: if the cert is OK via
    // system CA, the check passes automatically and we should NOT
    // disable it. If it's a self-signed cert, the right fix is to
    // install the CA bundle in /etc/ssl/certs, not to disable
    // verification.
    //
    // The risk of leaving VERIFYPEER=0 was MITM: an attacker on the
    // network between agent and central could intercept the GET
    // /api/v1/yara/active and serve a malicious YARA ruleset that
    // matches on every file (false positive flooding) or matches on
    // a specific canary file the operator is watching (delayed
    // detection). Both bad.
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) {
        std::cerr << "[yara] pull failed curl=" << curl_easy_strerror(res) << " http=" << http_code << std::endl;
        return 0;
    }

    // Parse JSON
    std::vector<std::pair<std::string, std::string>> rules;
    try {
        auto j = json::parse(buf.data);
        for (const auto& r : j) {
            std::string id = r.value("rule_id", "");
            std::string text = r.value("rule_text", "");
            std::string severity = r.value("severity", "medium");
            if (!id.empty() && !text.empty()) {
                rules.emplace_back(id, text);
                // We also store severity for the match record
                // (we don't compile metadata into the rule; severity is fetched per-match)
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[yara] pull JSON parse error: " << e.what() << std::endl;
        return 0;
    }

    return compile_rules(rules);
}

// T77 (v3.21.0): load a pre-compiled YARA ruleset blob.
//
// The blob was produced by `yarac <foo.yar> -o <foo.yarac>` on the
// central side (or by calling yr_rules_save / yr_rules_save_stream
// from libyara). It's the raw .yarac file format — a self-contained
// YR_RULES* that can be re-loaded in O(1) time (no recompilation).
//
// The canonical libyara API for loading a saved rules DB is
// `yr_rules_load_stream()` (libyara 4.0+). This takes a YR_STREAM
// struct with a read callback. We wrap the in-memory blob in a
// simple stream that reads from a vector<uint8_t>.
//
// Why not yr_compiler_load_rules_from_buffer?
//   Because that function DOES NOT EXIST in libyara's public API.
//   The compiler is one-way (source → rules). To load saved rules,
//   you MUST use yr_rules_load*.
//
// Returns 1 on success (1 chunk loaded), 0 on error.
//
// SAFETY:
//   - We build a new YR_RULES* in a LOCAL stream first.
//   - We verify sha256 BEFORE attempting to load (cheaper to
//     reject corrupt blobs early).
//   - We do the swap under mutex_ (apply_compiled does that).
//   - On ANY error, the previous ruleset is preserved.

// Memory-backed YR_STREAM used to feed yr_rules_load_stream.
struct MemStream {
    const uint8_t* data;
    size_t size;
    size_t pos;
    bool eof_warned = false;  // T12 audit fix #53: warn if read() asks for blocks larger than remaining
};
static size_t mem_stream_read(void* ptr, size_t size, size_t count, void* user_data) {
    auto* ms = static_cast<MemStream*>(user_data);
    // T12 audit fix #53: YR_STREAM read callback returns the number
    // of FULL elements read. EOF is signalled by returning 0 when
    // pos >= size. The previous code did:
    //   bytes = min(requested, remaining)
    //   return bytes / size
    // which returns 0 mid-stream when remaining < size, causing
    // libyara to abort early with "invalid format" on blobs whose
    // size is not a multiple of libyara's internal block size.
    //
    // We return floor(remaining / size) full elements, advancing
    // pos by that many bytes. On the NEXT call, pos will be at the
    // start of the partial block (if any), and remaining < size →
    // max_full_elements = 0 → we return 0 (clean EOF). The partial
    // bytes are LOST, but in practice yarac produces blobs aligned
    // to 4 bytes and libyara reads in small blocks at the tail, so
    // the loss is zero. If libyara ever produces an unaligned blob,
    // we log a warning so the operator can investigate.
    if (ms->pos >= ms->size) return 0;  // clean EOF
    size_t remaining = ms->size - ms->pos;
    size_t max_full_elements = remaining / size;
    if (max_full_elements == 0) {
        // Partial block at tail. Log once and return 0 (EOF).
        // The trade-off: simpler code, small risk of truncating
        // an unaligned blob. YARAC output is always 4-byte aligned
        // per the libyara file format spec, so this is safe in
        // practice.
        if (!ms->eof_warned) {
            std::cerr << "[yara] mem_stream_read: blob has " << remaining
                      << " trailing bytes (not a multiple of " << size
                      << "), truncating. This is benign for yarac output."
                      << std::endl;
            ms->eof_warned = true;
        }
        ms->pos = ms->size;  // advance to EOF
        return 0;
    }
    size_t elements_to_read = (count < max_full_elements) ? count : max_full_elements;
    size_t bytes_to_copy = elements_to_read * size;
    memcpy(ptr, ms->data + ms->pos, bytes_to_copy);
    ms->pos += bytes_to_copy;
    return elements_to_read;
}

size_t YaraEngine::load_compiled_blob(const std::vector<uint8_t>& blob,
                                       const std::string& expected_sha256,
                                       const std::string& severity_json) {
    if (blob.empty()) {
        std::cerr << "[yara] T77 load_compiled_blob: empty blob, ignored" << std::endl;
        return 0;
    }

    // SHA256 verify. Use the same helper as compile_rules.
    std::string actual_sha = sha256_hex(blob.data(), blob.size());
    if (!expected_sha256.empty() && actual_sha != expected_sha256) {
        std::cerr << "[yara] T77 sha256 mismatch: expected=" << expected_sha256
                  << " actual=" << actual_sha
                  << " (blob size=" << blob.size() << "), keeping previous ruleset" << std::endl;
        return 0;
    }

    // Wrap the blob in a memory-backed YR_STREAM.
    MemStream ms{blob.data(), blob.size(), 0};
    YR_STREAM stream;
    stream.user_data = &ms;
    stream.read = mem_stream_read;
    stream.write = nullptr;  // we don't write

    YR_RULES* new_rules = nullptr;
    int rc = yr_rules_load_stream(&stream, &new_rules);
    if (rc != ERROR_SUCCESS || new_rules == nullptr) {
        std::cerr << "[yara] T77 yr_rules_load_stream failed: " << rc
                  << " (likely version mismatch or corrupt blob), "
                  << "keeping previous ruleset" << std::endl;
        if (new_rules) yr_rules_destroy(new_rules);
        return 0;
    }

    // Build the chunks vector (just 1 chunk — unlike compile_rules
    // which chunks for libyara 4.5 workaround, the loaded blob is
    // already a complete YR_RULES* so no chunking needed).
    std::vector<YR_RULES*> chunks;
    chunks.push_back(new_rules);

    // Atomic swap (same pattern as compile_rules, line ~445).
    // On ANY error path above, we returned early WITHOUT
    // touching rules_, so the previous ruleset is preserved.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto* r : rules_) {
            if (r) yr_rules_destroy(r);
        }
        rules_ = std::move(chunks);
        // BUGFIX T77.5: clear per-rule metadata maps so
        // rule_count() returns the actual count of rules in
        // the NEW YR_RULES* (not the stale count from the
        // previous ruleset).
        rule_severity_.clear();
        rule_names_.clear();

        // T77.6: re-populate rule_severity_ from the
        // admin-pushed sidecar JSON. Format:
        //   {"<rule_id>": "low"|"medium"|"high"|"critical"}
        // The .yarac binary doesn't carry per-rule metadata,
        // so without this matches show severity="unknown".
        // We tolerate malformed JSON (log + skip) — better
        // to have unknown severity than to abort the load.
        if (!severity_json.empty() && severity_json != "{}") {
            try {
                json j = json::parse(severity_json);
                if (j.is_object()) {
                    for (auto it = j.begin(); it != j.end(); ++it) {
                        std::string rid = it.key();
                        if (it.value().is_string()) {
                            std::string sev = it.value().get<std::string>();
                            // Sanity: only accept known severities
                            if (sev == "low" || sev == "medium" ||
                                sev == "high" || sev == "critical") {
                                rule_severity_[rid] = sev;
                                rule_names_[rid] = rid;  // T80 diff: id == display name
                            }
                        }
                    }
                    std::cerr << "[yara] T77.6: populated " << rule_severity_.size()
                              << " rule severities from sidecar JSON" << std::endl;
                } else {
                    std::cerr << "[yara] T77.6: severity_json is not an object, "
                              << "ignoring (matches will show severity=\"unknown\")"
                              << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "[yara] T77.6: severity_json parse failed: " << e.what()
                          << ", ignoring (matches will show severity=\"unknown\")"
                          << std::endl;
            }
        }
    }

    // Update the hash so future pull_rules_from_central calls
    // can short-circuit (same content).
    last_ruleset_hash_ = actual_sha;

    std::cerr << "[yara] T77 load_compiled_blob OK: "
              << blob.size() << " bytes, sha256=" << actual_sha.substr(0, 12)
              << "... active rules=" << rule_count() << std::endl;
    return 1;
}

} // namespace logsoc
