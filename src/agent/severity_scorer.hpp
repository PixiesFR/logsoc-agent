// severity_scorer.hpp — T29 — Dynamic severity scoring for eBPF events.
//
// Replaces the binary info/medium/high with a 0..100 score based on
// multiple features. The score is then bucketed into severity strings
// for the dashboard:
//   0..19   → info
//   20..49  → low
//   50..74  → medium
//   75..89  → high
//   90..100 → critical
//
// Features (each contributes a weight):
//   - Event type baseline (modload > ptrace > connect > fim > fork > execve)
//   - MITRE technique count (more techniques = higher risk)
//   - Sensitive path access (/etc/shadow, /proc/kallsyms, etc.)
//   - UID = 0 (root) modifier
//   - Suspicious comm (ncat, socat, curl, python interpreter at root)
//   - Outbound port (4444/31337 = boost)
//   - Frequency suppression (already rate-limited upstream; we don't re-do it)
#pragma once
#include <cstdint>
#include <string>

namespace logsoc::agent::severity {

struct ScoreFeatures {
    uint32_t       event_type;
    std::string    comm;
    std::string    path;
    uint32_t       uid;
    uint32_t       dst_port;
    size_t         mitre_count;
};

// Returns a score 0..100. Deterministic (no randomness).
int score(const ScoreFeatures& f);

// Convert 0..100 score to a severity string used in events.
const char* score_to_severity(int s);

}  // namespace logsoc::agent::severity
