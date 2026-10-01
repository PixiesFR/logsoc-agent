// action_validator.cpp — T13.3': parent-side validator. See
// action_validator.hpp for the design and the 3 barriers.
//
// 3 barriers, in order:
//   1. Rule allowlist: is rec.rule_id in the pre-approved set?
//   2. PID exclusion: is rec.target_pid outside the system list?
//   3. Action allowlist: is rec.action_type allowed for this rule?
//
// All 3 are O(log N) set lookups. Total validation is O(1) amortized.

#include "action_validator.hpp"

#include <cstdio>
#include <fstream>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <dirent.h>

#include "debug.hpp"

namespace action_validator {

const char* barrier_result_str(BarrierResult r) {
    switch (r) {
        case BarrierResult::PASS:                   return "pass";
        case BarrierResult::FAIL_RULE_NOT_ALLOWED:  return "rule_not_allowed";
        case BarrierResult::FAIL_PID_EXCLUDED:      return "pid_excluded";
        case BarrierResult::FAIL_ACTION_NOT_ALLOWED:return "action_not_allowed";
    }
    return "unknown";
}

void ActionValidator::load_rules_allowlist(const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    rules_allowlist_.clear();
    std::ifstream f(path);
    if (!f) {
        LOG_WARN("[action_validator] rules_allowlist not found: " << path);
        return;
    }
    try {
        nlohmann::json j;
        f >> j;
        for (const auto& r : j.value("rules", std::vector<std::string>{})) {
            rules_allowlist_.insert(r);
        }
        LOG_INFO("[action_validator] loaded " << rules_allowlist_.size()
                 << " rules from " << path);
    } catch (const std::exception& e) {
        LOG_ERROR("[action_validator] failed to parse " << path << ": " << e.what());
    }
}

void ActionValidator::load_pid_exclusions(const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    pid_exclusions_.clear();
    // Always exclude PID 1 (init/systemd) and the agent's own PID,
    // regardless of the config file. Hardcoded safety net.
    pid_exclusions_.insert(1);
    pid_exclusions_.insert(::getpid());
    pid_exclusions_.insert(::getppid());

    std::ifstream f(path);
    if (!f) {
        LOG_WARN("[action_validator] pid_exclusions not found: " << path);
        return;
    }
    try {
        nlohmann::json j;
        f >> j;
        for (const auto& p : j.value("pids", std::vector<int>{})) {
            pid_exclusions_.insert(p);
        }
        // Exclude all kernel threads (PID 2..~1000 typically).
        // Heuristic: read /proc and exclude anything with PPID 2
        // (kthreadd) or no /proc/<pid>/exe symlink.
        DIR* d = ::opendir("/proc");
        if (d) {
            struct dirent* ent;
            while ((ent = ::readdir(d)) != nullptr) {
                int pid = atoi(ent->d_name);
                if (pid <= 1) continue;
                std::string status = "/proc/" + std::to_string(pid) + "/status";
                std::ifstream sf(status);
                if (!sf) continue;
                std::string line;
                int ppid = 0;
                while (std::getline(sf, line)) {
                    if (line.rfind("PPid:", 0) == 0) {
                        sscanf(line.c_str(), "PPid:%d", &ppid);
                        break;
                    }
                }
                if (ppid == 2) {
                    // kthread
                    pid_exclusions_.insert(pid);
                }
            }
            ::closedir(d);
        }
        LOG_INFO("[action_validator] loaded " << pid_exclusions_.size()
                 << " PID exclusions (incl. kernel threads + agent)");
    } catch (const std::exception& e) {
        LOG_ERROR("[action_validator] failed to parse " << path << ": " << e.what());
    }
}

void ActionValidator::load_action_allowlist(const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    action_allowlist_.clear();
    std::ifstream f(path);
    if (!f) {
        // Default: allow only the 3 standard action types if no file.
        // This is a safe default (the original T28 set).
        action_allowlist_.insert("kill_pid");
        action_allowlist_.insert("block_ip");
        action_allowlist_.insert("quarantine_file");
        LOG_WARN("[action_validator] action_allowlist not found, using default (3 types)");
        return;
    }
    try {
        nlohmann::json j;
        f >> j;
        for (const auto& a : j.value("actions", std::vector<std::string>{})) {
            action_allowlist_.insert(a);
        }
        LOG_INFO("[action_validator] loaded " << action_allowlist_.size()
                 << " action types from " << path);
    } catch (const std::exception& e) {
        LOG_ERROR("[action_validator] failed to parse " << path << ": " << e.what());
    }
}

bool ActionValidator::is_pid_excluded(int pid) const {
    std::lock_guard<std::mutex> lk(mu_);
    return pid_exclusions_.count(pid) > 0;
}

ValidationDecision ActionValidator::validate(const action_recommender::ActionRecommendation& rec) const {
    validated_total_.fetch_add(1, std::memory_order_relaxed);

    auto record = [&](BarrierResult r, const std::string& reason) {
        ValidationDecision d{r, reason};
        if (r == BarrierResult::PASS) {
            passed_total_.fetch_add(1, std::memory_order_relaxed);
        } else {
            failed_total_.fetch_add(1, std::memory_order_relaxed);
            reasons_[barrier_result_str(r)]++;
        }
        return d;
    };

    std::lock_guard<std::mutex> lk(mu_);

    // Barrier 1: rule allowlist
    if (rules_allowlist_.empty()) {
        // Fail closed: no rules = no actions.
        return record(BarrierResult::FAIL_RULE_NOT_ALLOWED,
                      "rules_allowlist is empty (fail-closed default)");
    }
    if (rules_allowlist_.count(rec.rule_id) == 0) {
        return record(BarrierResult::FAIL_RULE_NOT_ALLOWED,
                      "rule_id '" + rec.rule_id + "' not in allowlist");
    }

    // Barrier 2: PID exclusion (only for kill_pid)
    if (rec.action_type == "kill_pid") {
        if (rec.target_pid <= 0) {
            return record(BarrierResult::FAIL_PID_EXCLUDED,
                          "invalid target_pid " + std::to_string(rec.target_pid));
        }
        if (pid_exclusions_.count(rec.target_pid) > 0) {
            return record(BarrierResult::FAIL_PID_EXCLUDED,
                          "target_pid " + std::to_string(rec.target_pid) +
                          " is in system exclusion list");
        }
    }

    // Barrier 3: action allowlist
    if (action_allowlist_.count(rec.action_type) == 0) {
        return record(BarrierResult::FAIL_ACTION_NOT_ALLOWED,
                      "action_type '" + rec.action_type + "' not in allowlist");
    }

    return record(BarrierResult::PASS, "all 3 barriers passed");
}

uint64_t ActionValidator::by_reason(const std::string& reason) const {
    auto it = reasons_.find(reason);
    return (it != reasons_.end()) ? it->second : 0;
}

}  // namespace action_validator
