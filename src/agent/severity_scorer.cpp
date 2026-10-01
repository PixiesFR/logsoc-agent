// severity_scorer.cpp — T29 — Dynamic severity scoring (impl).
//
// The scoring is a hand-tuned weighted sum. Weights were chosen so
// that a "noisy" FIM event scores ~5-15, a root /etc/shadow read ~50,
// a modload by non-modprobe comm ~85, and a ptrace against /proc/<pid>/mem
// by non-root scores ~95.
//
// Not machine-learned (yet). The point of T29 is to give the SOC
// dashboard a continuous signal to plot trends. A future sprint can
// replace this with a gradient-boosted model trained on the labeled
// alerts we accumulate (T77 + Sigma).
#include "severity_scorer.hpp"

#include <algorithm>

namespace logsoc::agent::severity {

// Type baseline — these are the "starting scores" before context.
static int type_baseline(uint32_t t) {
    switch (t) {
    case 17: return 70;  // modload = rootkit indicator, even from modprobe
    case 10: return 60;  // ptrace = process injection
    case 12: return 65;  // bpf = EDR bypass attempt
    case 11: return 35;  // commit_creds = privilege escalation
    case 6:  return 15;  // unlink (often legit)
    case 15: return 30;  // bind (legit services + shells)
    case 14: return 35;  // accept (legit services + backdoors)
    case 13: return 15;  // vfs_open (volume)
    case 4:  return 10;  // fim
    case 16: return 25;  // tcp_v4_connect (C2)
    case 3:  return 25;  // tcp_connect (C2)
    case 2:  return 12;  // execve
    case 9:  return 5;   // fork
    case 1:  return 8;   // write
    case 8:  return 5;   // write_fd
    default: return 10;
    }
}

// Sensitive paths — extra boost when accessed
static bool is_sensitive_path(const std::string& p) {
    if (p.empty()) return false;
    // /etc/shadow, /etc/passwd, /etc/sudoers
    if (p.find("/etc/shadow") == 0)        return true;
    if (p.find("/etc/sudoers") == 0)       return true;
    if (p.find("/etc/pam.d/") == 0)        return true;
    if (p.find("/etc/ssh/sshd_config") == 0) return true;
    if (p.find("/.ssh/authorized_keys") != std::string::npos) return true;
    // /proc/kallsyms, /proc/kcore, /proc/keys — kernel info
    if (p.find("/proc/kallsyms") == 0) return true;
    if (p.find("/proc/kcore") == 0)    return true;
    if (p.find("/proc/keys") == 0)     return true;
    // /etc/ld.so.preload — classic rootkit trick
    if (p.find("/etc/ld.so.preload") == 0) return true;
    // /var/log/ — log tampering
    if (p.find("/var/log/") == 0) return true;
    // /lib/modules/ — kernel module location
    if (p.find("/lib/modules/") == 0) return true;
    return false;
}

static bool is_suspicious_comm(const std::string& c) {
    if (c.empty()) return false;
    return c == "nc" || c == "ncat" || c == "netcat" || c == "socat" ||
           c == "curl" || c == "wget" || c == "python" || c == "python3" ||
           c == "perl" || c == "ruby" || c == "php" || c == "msfconsole";
}

static bool is_shell_port(uint32_t p) {
    return p == 4444 || p == 31337 || p == 1337 || p == 9001 || p == 8888;
}

int score(const ScoreFeatures& f) {
    int s = type_baseline(f.event_type);

    // MITRE technique count — each technique adds context.
    // Cap at +30 to avoid runaway.
    s += std::min((int)f.mitre_count * 6, 30);

    // Sensitive path boost
    if (is_sensitive_path(f.path)) s += 25;
    // /etc/* in general: +10 (covered above, but double for /etc/shadow)
    if (!f.path.empty() && f.path.find("/etc/") == 0 && !is_sensitive_path(f.path)) s += 8;

    // Root UID boost
    if (f.uid == 0) s += 10;

    // Suspicious comm boost
    if (is_suspicious_comm(f.comm)) s += 15;

    // Shell port boost
    if (is_shell_port(f.dst_port)) s += 20;

    // Clamp 0..100
    if (s < 0) s = 0;
    if (s > 100) s = 100;
    return s;
}

const char* score_to_severity(int s) {
    if (s >= 90) return "critical";
    if (s >= 75) return "high";
    if (s >= 50) return "medium";
    if (s >= 20) return "low";
    return "info";
}

}  // namespace logsoc::agent::severity
