// sigma_engine.hpp — T29 — Lightweight Sigma-like rule matcher.
//
// KISS implementation: a flat array of rules, each is a substring
// match against a JSON-serialized event + a baseline technique.
//
// A full SigmaHQ (5000+ rules) parser with field-level grammar
// (selection, filter, timeframes) is overkill for the v1 — we ship
// the 25 most security-critical Linux rules as substring patterns.
// Operators can extend the table at compile time without re-architecting.
//
// Each rule has:
//   - id: short stable identifier (Sigma rule title in snake_case)
//   - level: criticality hint (informational, low, medium, high, critical)
//   - pattern: substring to find in the JSON event (case-sensitive)
//   - techniques: ATT&CK techniques it covers
//
// The matcher runs in O(N) per event (25 rules × ~100ns = 2.5µs/event).
// At 1k events/sec that's 0.25% CPU. Negligible.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace logsoc::agent::sigma {

struct SigmaHit {
    std::string id;
    std::string level;       // "informational"|"low"|"medium"|"high"|"critical"
    std::string techniques;  // comma-joined "T1003.008,T1078"
};

struct SigmaRule {
    const char* id;
    const char* level;
    const char* pattern;        // substring (must be present in event JSON)
    const char* techniques;     // comma-joined
};

// The table is defined in the .cpp. Compile-time visible here.
extern const SigmaRule SIGMA_RULES[];
extern const size_t    SIGMA_RULES_COUNT;

// Returns all Sigma hits for a given event JSON. O(N) over the table.
// Substring match — the JSON is small (300-500 bytes typically).
std::vector<SigmaHit> match(const std::string& event_json);

}  // namespace logsoc::agent::sigma
