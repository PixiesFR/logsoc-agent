// mitre_mapping.hpp — T4.8.3 — Path glob → MITRE ATT&CK techniques
//
// Maps Linux file paths to MITRE ATT&CK technique IDs. Used by FimCollector
// to tag fim events with the relevant techniques for SOC dashboards.
//
// V4.8: hardcoded constexpr table (24 rules). Future: external .json file.
// See docs/MITRE-ATTACK-LOGSOC-MAPPING.md for the source paths.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace logsoc::agent::mitre {

struct MitreRule {
    std::string_view pattern;          // fnmatch pattern (FNM_PATHNAME)
    std::array<std::string_view, 2> techniques;  // up to 2 techniques
};

// V4.8 source: docs/MITRE-ATTACK-LOGSOC-MAPPING.md
// 24 rules covering the most security-relevant Linux paths.
// T4.8.22: expanded to 39 rules (added SSH config / authorized_keys /
// known_hosts persistence, and log tampering detection).
inline constexpr std::array<MitreRule, 39> MITRE_RULES = {{
    // Credential access (TA0006)
    {"/etc/passwd",         {{"T1003.008"}}},  // /etc/passwd & /etc/shadow
    {"/etc/shadow",         {{"T1003.008"}}},
    {"/etc/sudoers",        {{"T1548.003"}}},  // Sudo and Sudo Caching
    {"/etc/sudoers.d/*",    {{"T1548.003"}}},
    {"/etc/pam.d/*",        {{"T1556"}}},      // Modify Authentication Process

    // Persistence (TA0003)
    {"/etc/rc.local",       {{"T1037.004"}}},  // RC Scripts
    {"/etc/init.d/*",       {{"T1037.004"}}},
    {"/etc/systemd/system/*", {{"T1543.002"}}}, // Systemd Service
    {"/lib/systemd/system/*", {{"T1543.002"}}},
    {"/usr/lib/systemd/system/*", {{"T1543.002"}}},
    {"/etc/cron*",          {{"T1053.003"}}},  // Cron
    {"/var/spool/cron/*",   {{"T1053.003"}}},
    {"/etc/cron.d/*",       {{"T1053.003"}}},
    {"/etc/cron.daily/*",   {{"T1053.003"}}},

    // Privilege escalation (TA0004)
    {"/etc/sudoers",        {{"T1548.003"}}},
    {"/usr/bin/sudo",       {{"T1548.003"}}},
    {"/usr/bin/su",         {{"T1548"}}},      // Sudo (no specific sub)

    // Defense evasion (TA0005)
    {"/etc/ld.so.conf",     {{"T1574.006"}}},  // Dynamic Linker Hijacking
    {"/etc/ld.so.conf.d/*", {{"T1574.006"}}},
    {"/etc/ld.so.preload",  {{"T1574.006"}}},

    // Account manipulation (TA0003)
    {"/etc/group",          {{"T1098"}}},      // Account Manipulation
    {"/etc/gshadow",        {{"T1098"}}},

    // Kernel/modules (TA0003)
    {"/lib/modules/*",      {{"T1547.006"}}},  // Kernel Modules
    {"/usr/lib/modules/*",  {{"T1547.006"}}},

    // T4.8.22: SSH config persistence & credential access.
    // sshd_config is a high-value target: an attacker who modifies it
    // can disable security checks (PermitRootLogin, PasswordAuth,
    // AllowUsers), add authorized keys, or pivot to other systems. The
    // wildcard catches sshd_config AND drop-in configs in sshd_config.d.
    // Also covers authorized_keys / known_hosts (persistence + MITM).
    {"/etc/ssh/sshd_config",       {{"T1098.004"}}},  // SSH Authorized Keys (modify)
    {"/etc/ssh/sshd_config.d/*",   {{"T1098.004"}}},
    {"/etc/ssh/ssh_config",        {{"T1098.004"}}},
    {"/root/.ssh/authorized_keys", {{"T1098.004"}}},
    {"/home/*/.ssh/authorized_keys",{{"T1098.004"}}},
    {"/root/.ssh/known_hosts",     {{"T1557"}}},  // Adversary-in-the-Middle
    {"/home/*/.ssh/known_hosts",   {{"T1557"}}},

    // T4.8.22: log tampering (defense evasion / T1070)
    {"/var/log/auth.log",      {{"T1070.002"}}},  // Clear Linux/Mac Logs
    {"/var/log/secure",        {{"T1070.002"}}},
    {"/var/log/syslog",        {{"T1070.002"}}},
    {"/var/log/messages",      {{"T1070.002"}}},
    {"/var/log/wtmp",          {{"T1070.002"}}},
    {"/var/log/utmp",          {{"T1070.002"}}},
    {"/var/log/btmp",          {{"T1070.002"}}},
    {"/var/log/lastlog",       {{"T1070.002"}}},
}};

class MitreMapping {
public:
    // Tag a path with the matching MITRE techniques. Returns an empty
    // vector if no rule matches. The first match wins (deterministic).
    //
    // Matching uses fnmatch with FNM_PATHNAME so /etc/cron* matches
    // /etc/crontab but not /etc/something_cron_other.
    static const std::vector<std::string>& tag(const std::string& path);

    // T29: tag an eBPF event with MITRE techniques using ALL available
    // context (type, comm, path, uid, dst_port). This is the multi-
    // dimensional version that combines:
    //   1. Path-based rules (the 39 above)
    //   2. Type-based rules (e.g. type=17 modload → T1014 rootkit)
    //   3. UID-based rules (e.g. uid=0 + modload → T1547.006 kernel module)
    //   4. Port-based rules (e.g. dst_port=4444 → T1059 command shell bind)
    //   5. Comm-based rules (e.g. comm=ncat → T1059.001 PowerShell)
    //
    // Returns a vector (NOT a reference) because it's built per call.
    // The result is sorted and deduplicated.
    static std::vector<std::string> tag_event(uint32_t event_type,
                                              const std::string& comm,
                                              const std::string& path,
                                              uint32_t uid,
                                              uint32_t dst_port);
};

}  // namespace logsoc::agent::mitre
