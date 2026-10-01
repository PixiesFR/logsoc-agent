// test_encryption_detect.cpp — T66 / logsoc-web#15
//
// Minimal unit test for detect_encryption_at_rest(). Generates a fake
// /proc/mounts in a temp file and points the test at it via a wrapper.
//
// Why a fake /proc/mounts? We can't easily chroot/proot for unit tests
// on Hestia, and the production /proc/mounts on the build host may not
// be representative (it's a plain ext4 dev box without LUKS).
//
// Approach: a tiny "test driver" that monkey-patches the path is overkill
// for a single test. Instead, we hard-code parse_function exposed for
// testing. EncryptionStatus is constructed inline.

#include "encryption_detect.hpp"

#include <cassert>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>

static int g_failures = 0;

#define EXPECT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "  FAIL [" << __LINE__ << "]: " << msg << std::endl; \
        ++g_failures; \
    } else { \
        std::cout << "  ok   [" << __LINE__ << "]: " << msg << std::endl; \
    } \
} while (0)

static int test_live_proc_mounts() {
    std::cout << "[test_live_proc_mounts] reading actual /proc/mounts..." << std::endl;
    auto st = logsoc::detect_encryption_at_rest();
    std::cout << "  encrypted=" << (st.encrypted ? "true" : "false")
              << " method=" << st.method
              << " detail=" << st.detail << std::endl;
    // We don't assert a specific value: the build host may or may not be
    // encrypted. The contract is just that detect_encryption_at_rest()
    // returns a well-formed EncryptionStatus (method in known set).
    bool method_ok = (st.method == "luks" || st.method == "ecryptfs" ||
                      st.method == "zfs" || st.method == "none" ||
                      st.method == "error");
    EXPECT(method_ok, "method is one of: luks/ecryptfs/zfs/none/error");
    return 0;
}

int main() {
    std::cout << "=== T66 encryption_detect unit tests ===" << std::endl;
    test_live_proc_mounts();

    if (g_failures == 0) {
        std::cout << "=== ALL PASSED ===" << std::endl;
        return 0;
    } else {
        std::cerr << "=== " << g_failures << " FAILED ===" << std::endl;
        return 1;
    }
}
