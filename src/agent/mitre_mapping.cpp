// mitre_mapping.cpp — T4.8.3 — Path glob → MITRE ATT&CK techniques (impl)
// T29: added tag_event() multi-dimensional mapping.
#include "mitre_mapping.hpp"

#include <fnmatch.h>

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>

namespace logsoc::agent::mitre {

// Singleton empty vector returned when no rule matches.
// Avoids returning a temporary from tag() (would dangle).
static const std::vector<std::string> EMPTY;

const std::vector<std::string>& MitreMapping::tag(const std::string& path) {
    if (path.empty()) {
        return EMPTY;
    }
    for (const auto& rule : MITRE_RULES) {
        if (fnmatch(std::string(rule.pattern).c_str(),
                    path.c_str(),
                    FNM_PATHNAME) == 0) {
            // Copy technique IDs into a fresh vector (caller expects
            // a stable, heap-allocated result).
            static thread_local std::vector<std::string> result;
            result.clear();
            for (const auto& tech : rule.techniques) {
                if (!tech.empty()) {
                    result.emplace_back(tech);
                }
            }
            if (!result.empty()) {
                return result;
            }
        }
    }
    return EMPTY;
}

// T29: small helper — does the comm match any of the names?
static bool comm_is_one_of(const std::string& comm,
                           std::initializer_list<const char*> names) {
    for (const char* n : names) {
        if (comm == n) return true;
    }
    return false;
}

std::vector<std::string> MitreMapping::tag_event(
    uint32_t event_type,
    const std::string& comm,
    const std::string& path,
    uint32_t uid,
    uint32_t dst_port) {
    std::set<std::string> techniques;

    // 1. Path-based rules (39 from MITRE_RULES)
    if (!path.empty()) {
        const auto& from_path = tag(path);
        for (const auto& t : from_path) techniques.insert(t);
    }

    // 2. Type-based rules (covers the 17 eBPF event types)
    switch (event_type) {
    case 1:  // write
        // Generic write — only path-based attribution above.
        break;
    case 2:  // execve
        // Reverse shells / shellcode loaders
        if (comm_is_one_of(comm, {"nc", "ncat", "netcat", "socat",
                                  "bash", "sh", "zsh", "dash"})) {
            // /dev/tcp-style or netcat-based reverse shell
            techniques.insert("T1059.004");  // Unix Shell
        }
        if (comm == "curl" || comm == "wget" || comm == "fetch") {
            techniques.insert("T1105");  // Ingress Tool Transfer
        }
        if (comm == "python" || comm == "python3" || comm == "perl" ||
            comm == "ruby" || comm == "php") {
            techniques.insert("T1059.006");  // Python (and other interpreters)
        }
        if (uid == 0 && (comm == "sudo" || comm == "su")) {
            techniques.insert("T1548.003");  // Sudo and Sudo Caching
        }
        break;
    case 3:  // tcp_connect (outgoing C2)
    case 16: // tcp_v4_connect
        techniques.insert("T1071");  // Application Layer Protocol (C2)
        if (dst_port == 53)        techniques.insert("T1071.004");  // DNS
        else if (dst_port == 443)  techniques.insert("T1071.001");  // HTTPS
        else if (dst_port == 80)   techniques.insert("T1071.001");  // HTTP
        else if (dst_port == 4444) techniques.insert("T1059.003");  // Windows Cmd Shell (bind)
        else if (dst_port == 31337 || dst_port == 1337) techniques.insert("T1059");  // Shell
        break;
    case 4:  // fim
    case 13: // vfs_open
        // Path-based already covered (T1003.008 for /etc/shadow etc.)
        // Add 'File and Directory Discovery' for /proc/<pid>/ reads
        if (path.find("/proc/") == 0 && path.find("/proc/self/") != 0) {
            techniques.insert("T1083");  // File and Directory Discovery
        }
        // Sensitive credential / kernel reads
        if (path.find("/proc/kallsyms") == 0 ||
            path.find("/proc/kcore") == 0 ||
            path.find("/proc/keys") == 0) {
            techniques.insert("T1003");  // OS Credential Dumping
        }
        if (uid == 0 && path.find("/proc/") == 0) {
            // root reading arbitrary /proc/* — possible memory inspection
            techniques.insert("T1003.007");  // Proc Filesystem
        }
        break;
    case 6:  // unlink
        techniques.insert("T1070.004");  // File Deletion
        if (path.find("/var/log/") == 0) {
            techniques.insert("T1070.002");  // Clear Linux Logs
        }
        if (path.find("/etc/") == 0 || path.find("/usr/") == 0 ||
            path.find("/lib/") == 0) {
            techniques.insert("T1485");  // Data Destruction (could be legit)
        }
        break;
    case 8:  // write_fd
        // Generic write — path/comm-based above
        break;
    case 9:  // fork
        // Generic process spawn — covered by execve usually
        break;
    case 10: // ptrace
        techniques.insert("T1055");  // Process Injection (ptrace is the classic)
        if (path.find("/proc/") == 0 || path.find("/mem") != std::string::npos) {
            techniques.insert("T1003.007");  // Proc Filesystem
        }
        break;
    case 11: // commit_creds (privilege escalation)
        techniques.insert("T1548");  // Abuse Elevation Control Mechanism
        if (uid == 0) {
            techniques.insert("T1548.001");  // Setuid/Setgid
        }
        break;
    case 12: // bpf (auto-protection of EDR)
        techniques.insert("T1562.001");  // Disable or Modify Tools (EDR bypass)
        if (uid != 0) {
            techniques.insert("T1068");  // Exploitation for Privilege Escalation
        }
        break;
    case 14: // inet_csk_accept (backdoor)
        techniques.insert("T1059");  // Command and Scripting Interpreter (shell)
        // Shell ports
        if (dst_port == 4444 || dst_port == 31337 || dst_port == 1337 ||
            dst_port == 9001 || dst_port == 8888) {
            techniques.insert("T1505.003");  // Web Shell
        }
        if (comm != "sshd" && comm != "nginx" && comm != "apache2" &&
            comm != "httpd" && comm != "caddy" && comm != "traefik" &&
            !comm.empty()) {
            techniques.insert("T1505");  // Server Software Component
        }
        break;
    case 15: // bind (port binding)
        techniques.insert("T1571");  // Non-Standard Port
        if (dst_port == 4444 || dst_port == 31337 || dst_port == 1337) {
            techniques.insert("T1505.003");  // Web Shell
        }
        break;
    case 17: // modload (rootkit)
        techniques.insert("T1547.006");  // Kernel Modules and Extensions
        techniques.insert("T1014");     // Rootkit
        if (uid == 0) techniques.insert("T1547");  // Boot or Logon Autostart Execution
        // T12 audit fix #13: also try to tag the module name itself.
        // MITRE_RULES contains rules for known-bad module names (e.g.
        // patterns matching "diamorphine", "reptile", "suterusu" — the
        // standard Linux rootkits). The path-based rules above won't
        // match these because the rules are paths, not module basenames.
        // Calling tag(module_name) lets those rules fire. The module
        // name is in `path` (the loader sets t29_path to the modname
        // for type 17, but we also try path here as a fallback in
        // case future code passes a real path).
        if (!path.empty()) {
            // Try the modname/basename. tag() uses fnmatch, so a bare
            // modname like "nfs" won't match path patterns like
            // "/etc/passwd" — but the rootkit rules in MITRE_RULES use
            // glob patterns like "*diamorphine*" that match modnames.
            const auto& from_path = tag(path);
            for (const auto& t : from_path) techniques.insert(t);
        }
        break;
    default:
        break;
    }

    // 3. UID-based cross-cutting rules
    if (uid == 0) {
        // root doing anything that touches a config file = suspicious
        if (path.find("/etc/") == 0 || path.find("/usr/") == 0) {
            // already covered by path-based, just add a generic
            techniques.insert("T1548.005");  // Temporary Elevated Cloud Access (loose)
        }
    }

    // 4. Sort + dedup is already done by std::set, convert to vector
    return std::vector<std::string>(techniques.begin(), techniques.end());
}

}  // namespace logsoc::agent::mitre
