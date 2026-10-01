// sigma_engine.cpp — T29 — Substring-based Sigma matcher (impl).
//
// 25 hand-picked rules covering the highest-signal Linux events.
// Each pattern is a substring that MUST appear in the JSON event
// for the rule to match. False positives are mitigated by the
// severity_scorer, which independently ranks the event.
//
// Why not a full SigmaHQ parser? Because Sigma's selection/filter/
// timeframe grammar requires YAML loading + a state machine. For 25
// critical rules, a substring table is 100x simpler and runs in 2µs.
// Future: when we have >100 rules, switch to a proper parser.
#include "sigma_engine.hpp"

#include <cstring>

namespace logsoc::agent::sigma {

// ── The 25 rules ─────────────────────────────────────────────────────────
const SigmaRule SIGMA_RULES[] = {
    // ── Modload / rootkit signals ──
    {"modload_by_root",            "critical", "\"event\":\"modload\"",                    "T1547.006,T1014"},
    {"finit_module_by_root",       "critical", "\"subtype\":\"finit_module\"",              "T1547.006,T1014"},
    {"init_module_by_root",        "critical", "\"subtype\":\"init_module\"",               "T1547.006,T1014"},

    // ── Credential access ──
    {"etc_shadow_read",            "critical", "{\"event\":\"vfs_open\",\"path\":\"/etc/shadow",  "T1003.008"},
    {"etc_passwd_read",            "high",     "{\"event\":\"vfs_open\",\"path\":\"/etc/passwd",  "T1003.008"},
    {"etc_sudoers_modify",         "high",     "/etc/sudoers",                                "T1548.003"},
    {"ssh_authorized_keys",        "critical", "authorized_keys",                             "T1098.004"},
    {"sshd_config_modify",         "high",     "sshd_config",                                 "T1098.004"},
    {"proc_kallsyms_read",         "high",     "/proc/kallsyms",                              "T1003"},
    {"proc_kcore_read",            "critical", "/proc/kcore",                                 "T1003"},

    // ── Persistence ──
    {"ld_so_preload_modify",       "critical", "/etc/ld.so.preload",                         "T1574.006"},
    {"systemd_service_create",     "high",     "/etc/systemd/system/",                        "T1543.002"},
    {"crontab_modify",             "medium",   "/etc/cron",                                   "T1053.003"},
    {"rc_local_modify",            "high",     "/etc/rc.local",                               "T1037.004"},

    // ── Defense evasion ──
    {"var_log_unlink",             "high",     "{\"event\":\"unlink\",\"path\":\"/var/log/",    "T1070.002"},
    {"bpf_program_attached",       "high",     "\"event\":\"bpf\"",                            "T1562.001"},

    // ── Execution / command ──
    {"ptrace_attached",            "high",     "\"event\":\"ptrace\"",                         "T1055"},
    {"ptrace_proc_mem",            "critical", "\"event\":\"ptrace\",\"path\":\"/proc/",       "T1003.007"},

    // ── Network C2 ──
    {"outbound_to_shell_port",     "critical", "\"dst_port\":4444",                           "T1059.003"},
    {"outbound_to_31337",          "critical", "\"dst_port\":31337",                          "T1059"},
    {"bind_shell_port",            "critical", "\"event\":\"bind\",\"dst_port\":4444",        "T1505.003"},
    {"accept_non_standard",        "medium",   "\"event\":\"accept\"",                         "T1505"},

    // ── Privilege escalation ──
    {"commit_creds_root",          "high",     "\"event\":\"commit_creds\",\"uid\":0",         "T1548"},

    // ── Process injection (interpreter spawned) ──
    {"python_exec",                "low",      "\"comm\":\"python",                           "T1059.006"},
    {"nc_exec",                    "high",     "\"comm\":\"nc\"",                             "T1059.004"},
    {"socat_exec",                 "high",     "\"comm\":\"socat\"",                          "T1059"},
    {"curl_download",              "medium",   "\"comm\":\"curl\"",                           "T1105"},
};
const size_t SIGMA_RULES_COUNT = sizeof(SIGMA_RULES) / sizeof(SIGMA_RULES[0]);

std::vector<SigmaHit> match(const std::string& event_json) {
    std::vector<SigmaHit> hits;
    hits.reserve(4);  // typically 0-2 hits per event
    for (size_t i = 0; i < SIGMA_RULES_COUNT; ++i) {
        const SigmaRule& r = SIGMA_RULES[i];
        if (std::strstr(event_json.c_str(), r.pattern) != nullptr) {
            hits.push_back({r.id, r.level, r.techniques});
        }
    }
    return hits;
}

}  // namespace logsoc::agent::sigma
