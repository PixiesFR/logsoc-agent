#pragma once
// action_validator.hpp — T13.3': parent-side validator for action
// recommendations coming from the ActionRecommenderProcess child.
//
// The child is logsoc:logsoc, has no caps, CANNOT execute actions.
// It sends structured recommendations (action_type, target_pid,
// rule_id, severity). The parent:
//   1. Receives the recommendation from the child (kernel-authenticated
//      via SO_PEERCRED — the parent's kernel guarantees the peer is
//      its own child, no userland trust).
//   2. Applies 3 safety barriers (see validate()).
//   3. If all barriers pass, calls t28::execute() with the parent's
//      root capabilities.
//   4. If any barrier fails, logs and ignores.
//
// This file is the 2nd half of the T13.3' inversion: the parent is
// the executor, the child is the analyst.

#include <set>
#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <map>
#include <atomic>
#include "json.hpp"  // project wrapper, not <nlohmann/json.hpp>

#include "action_recommender_process.hpp"  // ActionRecommendation

namespace action_validator {

// The 3 barriers return reasons that get logged if the barrier fails.
enum class BarrierResult {
    PASS,
    FAIL_RULE_NOT_ALLOWED,    // barrier 1
    FAIL_PID_EXCLUDED,        // barrier 2
    FAIL_ACTION_NOT_ALLOWED,  // barrier 3
};

const char* barrier_result_str(BarrierResult r);

struct ValidationDecision {
    BarrierResult barrier;
    std::string   reason;  // human-readable, for journald
};

class ActionValidator {
public:
    // Load the 3 allowlists from JSON config files. Empty/missing
    // files = no entries (everything fails closed).
    //
    // rules_allowlist.json:
    //   {"rules": ["yara_critical_binary", "sigma_reverse_shell", ...]}
    //
    // pid_exclusions.json:
    //   {"pids": [1, 2, ..., N], "names": ["systemd", "sshd", ...]}
    //
    // action_allowlist.json:
    //   {"actions": ["kill_pid", "block_ip", "quarantine_file"]}
    //
    // All 3 files are signed by the backend in production (HMAC
    // signature verified in agent.cpp before this is constructed).
    // For the MVP, plain JSON is fine.
    void load_rules_allowlist(const std::string& path);
    void load_pid_exclusions(const std::string& path);
    void load_action_allowlist(const std::string& path);

    // Validate a recommendation against the 3 barriers.
    // Returns PASS or a FAIL_* code + reason.
    ValidationDecision validate(const action_recommender::ActionRecommendation& rec) const;

    // Convenience: is the PID in the exclusion list?
    bool is_pid_excluded(int pid) const;

    // Stats (atomic counters for the heartbeat).
    uint64_t validated_total()    const { return validated_total_.load(); }
    uint64_t passed_total()       const { return passed_total_.load(); }
    uint64_t failed_total()       const { return failed_total_.load(); }
    uint64_t by_reason(const std::string& reason) const;

private:
    mutable std::mutex mu_;
    std::set<std::string> rules_allowlist_;
    std::set<int>         pid_exclusions_;
    std::set<std::string> action_allowlist_;

    // Atomic stats
    mutable std::atomic<uint64_t> validated_total_{0};
    mutable std::atomic<uint64_t> passed_total_{0};
    mutable std::atomic<uint64_t> failed_total_{0};
    mutable std::map<std::string, uint64_t> reasons_;  // reason -> count
};

}  // namespace action_validator
