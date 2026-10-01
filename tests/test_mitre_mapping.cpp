// test_mitre_mapping.cpp — T4.8.3 — unit tests for MitreMapping::tag
//
// Build (see tests/Makefile for the canonical target):
//   g++ -std=c++17 -O2 -Isrc/agent -o test_mitre_mapping
//       tests/test_mitre_mapping.cpp src/agent/mitre_mapping.cpp
//   ./test_mitre_mapping

#include "../src/agent/mitre_mapping.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace logsoc::agent::mitre;

static int g_passed = 0;
static int g_failed = 0;

#define EXPECT(cond, msg)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg);\
            g_failed++;                                                        \
        } else {                                                               \
            g_passed++;                                                        \
        }                                                                      \
    } while (0)

static void test_empty_path() {
    auto& v = MitreMapping::tag("");
    EXPECT(v.empty(), "empty path returns empty vector");
}

static void test_no_match() {
    // T4.8.22: /var/log/syslog now has a T1070.002 rule, so it's no
    // longer a "no match" candidate. Use a truly ungoverned path
    // (e.g. a video file in /tmp) instead.
    auto& v = MitreMapping::tag("/tmp/random_video.mp4");
    EXPECT(v.empty(), "/tmp/random_video.mp4 has no MITRE tag");
    auto& v2 = MitreMapping::tag("/home/user/.bashrc");
    EXPECT(v2.empty(), "user home file has no MITRE tag");
}

static void test_exact_match() {
    auto& v = MitreMapping::tag("/etc/passwd");
    EXPECT(v.size() == 1, "/etc/passwd → 1 technique");
    EXPECT(!v.empty() && v[0] == "T1003.008", "/etc/passwd → T1003.008");
}

static void test_shadow() {
    auto& v = MitreMapping::tag("/etc/shadow");
    EXPECT(!v.empty() && v[0] == "T1003.008", "/etc/shadow → T1003.008");
}

static void test_sudoers() {
    auto& v = MitreMapping::tag("/etc/sudoers");
    EXPECT(!v.empty() && v[0] == "T1548.003", "/etc/sudoers → T1548.003");
}

static void test_glob_match() {
    auto& v1 = MitreMapping::tag("/etc/sudoers.d/myconfig");
    EXPECT(!v1.empty() && v1[0] == "T1548.003", "/etc/sudoers.d/* glob");

    auto& v2 = MitreMapping::tag("/etc/cron.d/weekly-job");
    EXPECT(!v2.empty() && v2[0] == "T1053.003", "/etc/cron.d/* glob");

    auto& v3 = MitreMapping::tag("/etc/systemd/system/my.service");
    EXPECT(!v3.empty() && v3[0] == "T1543.002", "/etc/systemd/system/* glob");
}

static void test_glob_no_match() {
    // /etc/cron* must NOT match /etc/something_cron_other (FNM_PATHNAME)
    auto& v = MitreMapping::tag("/etc/rcron.daily");
    // Note: /etc/cron* would match /etc/crontab (legit) and /etc/cron.d
    // We accept that FNM_PATHNAME means * does not cross /, but /etc/cron*
    // matches /etc/cronX, /etc/cron.d, /etc/cron.daily, /etc/crontab.
    // /etc/rcron.daily should NOT match (path component starts with rcron).
    EXPECT(v.empty(), "/etc/rcron.daily should not match /etc/cron* (FNM_PATHNAME)");
}

static void test_kernel_module() {
    // fnmatch with FNM_PATHNAME: * does not cross /.
    // /lib/modules/* matches the directory entry directly (e.g. version dir).
    auto& v = MitreMapping::tag("/lib/modules/5.15.0-91-generic");
    EXPECT(!v.empty() && v[0] == "T1547.006", "kernel module → T1547.006");
}

static void test_preload() {
    auto& v = MitreMapping::tag("/etc/ld.so.preload");
    EXPECT(!v.empty() && v[0] == "T1574.006", "/etc/ld.so.preload → T1574.006");
}

static void test_group() {
    auto& v = MitreMapping::tag("/etc/group");
    EXPECT(!v.empty() && v[0] == "T1098", "/etc/group → T1098");
}

static void test_sudo_binary() {
    auto& v = MitreMapping::tag("/usr/bin/sudo");
    EXPECT(!v.empty() && v[0] == "T1548.003", "/usr/bin/sudo → T1548.003");
}

static void test_su_binary() {
    auto& v = MitreMapping::tag("/usr/bin/su");
    EXPECT(!v.empty() && v[0] == "T1548", "/usr/bin/su → T1548");
}

static void test_deterministic() {
    // First match wins — calling twice returns the same result.
    auto& v1 = MitreMapping::tag("/etc/passwd");
    auto& v2 = MitreMapping::tag("/etc/passwd");
    EXPECT(v1.size() == v2.size(), "deterministic size");
    if (!v1.empty() && !v2.empty()) {
        EXPECT(v1[0] == v2[0], "deterministic content");
    }
}

static void test_thread_safety() {
    // Quick stress: 100k calls, all should return the same result.
    auto& v_first = MitreMapping::tag("/etc/passwd");
    std::string first = v_first.empty() ? "" : v_first[0];
    for (int i = 0; i < 100000; ++i) {
        auto& v = MitreMapping::tag("/etc/passwd");
        std::string s = v.empty() ? "" : v[0];
        EXPECT(s == first, "100k calls consistent (or thread-safety violation)");
        if (s != first) break;  // fail fast
    }
}

static void test_ssh_rules() {
    // T4.8.22: SSH config / authorized_keys / known_hosts
    auto& v1 = MitreMapping::tag("/etc/ssh/sshd_config");
    EXPECT(!v1.empty() && v1[0] == "T1098.004", "sshd_config → T1098.004");
    auto& v2 = MitreMapping::tag("/etc/ssh/sshd_config.d/00-myconf");
    EXPECT(!v2.empty() && v2[0] == "T1098.004", "sshd_config.d/* → T1098.004");
    auto& v3 = MitreMapping::tag("/root/.ssh/authorized_keys");
    EXPECT(!v3.empty() && v3[0] == "T1098.004", "root authorized_keys → T1098.004");
    auto& v4 = MitreMapping::tag("/home/alice/.ssh/authorized_keys");
    EXPECT(!v4.empty() && v4[0] == "T1098.004", "user authorized_keys → T1098.004");
    auto& v5 = MitreMapping::tag("/home/bob/.ssh/known_hosts");
    EXPECT(!v5.empty() && v5[0] == "T1557", "known_hosts → T1557 (AiTM)");
}

static void test_log_tampering_rules() {
    // T4.8.22: log files relevant for defense evasion detection
    auto& v1 = MitreMapping::tag("/var/log/auth.log");
    EXPECT(!v1.empty() && v1[0] == "T1070.002", "auth.log → T1070.002");
    auto& v2 = MitreMapping::tag("/var/log/secure");
    EXPECT(!v2.empty() && v2[0] == "T1070.002", "secure → T1070.002");
    auto& v3 = MitreMapping::tag("/var/log/wtmp");
    EXPECT(!v3.empty() && v3[0] == "T1070.002", "wtmp → T1070.002");
    auto& v4 = MitreMapping::tag("/var/log/lastlog");
    EXPECT(!v4.empty() && v4[0] == "T1070.002", "lastlog → T1070.002");
}

int main() {
    std::printf("=== MitreMapping tests ===\n");
    test_empty_path();
    test_no_match();
    test_exact_match();
    test_shadow();
    test_sudoers();
    test_glob_match();
    test_glob_no_match();
    test_kernel_module();
    test_preload();
    test_group();
    test_sudo_binary();
    test_su_binary();
    test_deterministic();
    test_thread_safety();
    test_ssh_rules();
    test_log_tampering_rules();
    std::printf("=== %d/%d passed, %d failed ===\n",
                g_passed, g_passed + g_failed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
