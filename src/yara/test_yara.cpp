// yara/test_yara.cpp — Standalone test of YaraEngine
// Usage: ./test_yara [EICAR_TEST_FILE]
//
// Compiles a YARA rule, scans a file (default: this binary's own bytes
// to test the negative case), and a synthetic EICAR file to test
// the positive case. Prints the results to stdout.

#include "yara_engine.hpp"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    using namespace logsoc;

    YaraConfig cfg;
    cfg.enabled = true;
    cfg.scan_flags = 1;  // file only
    cfg.central_url = "";
    cfg.agent_id = "test-agent";
    cfg.hmac_token = "test-token";

    YaraEngine engine(cfg);
    if (!engine.init()) {
        std::cerr << "init failed\n";
        return 1;
    }

    // Compile a real EICAR rule
    std::vector<std::pair<std::string, std::string>> rules = {
        {"eicar01", "rule eicar_test { strings: $a = \"X5O!P%@AP[4\" condition: $a }"},
        {"clean01", "rule clean_test { strings: $a = \"this_string_does_not_exist_in_eicar\" condition: $a }"},
    };
    size_t compiled = engine.compile_rules(rules);
    std::cout << "compiled " << compiled << "/" << rules.size() << " rules" << std::endl;

    if (compiled == 0) {
        std::cerr << "no rules compiled, aborting\n";
        return 1;
    }

    // Create EICAR test file
    std::string eicar_path = "/tmp/eicar_test.com";
    {
        // Full EICAR signature: 68 bytes
        const char* eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        std::ofstream f(eicar_path, std::ios::binary);
        f << eicar;
    }
    std::cout << "EICAR test file: " << eicar_path << " (68 bytes)" << std::endl;

    // Test 1: scan EICAR file (should match)
    std::cout << "\n=== Test 1: scan EICAR file (expected MATCH) ===" << std::endl;
    engine.scan_file(eicar_path, "file");

    // Test 2: scan /etc/hostname (should NOT match)
    std::cout << "=== Test 2: scan /etc/hostname (expected NO MATCH) ===" << std::endl;
    engine.scan_file("/etc/hostname", "file");

    // Test 3: scan non-existent file (should be silently skipped)
    std::cout << "=== Test 3: scan /nonexistent (expected SKIP) ===" << std::endl;
    engine.scan_file("/nonexistent_file_zzz", "file");

    // Stats
    std::cout << "\n=== Stats ===" << std::endl;
    std::cout << "rules loaded: " << engine.rule_count() << std::endl;
    std::cout << "total scans: " << engine.total_scans() << std::endl;
    std::cout << "total matches: " << engine.total_matches() << std::endl;
    std::cout << "compile errors: " << engine.total_compile_errors() << std::endl;

    if (engine.total_matches() != 1) {
        std::cerr << "FAIL: expected 1 match, got " << engine.total_matches() << std::endl;
        return 1;
    }

    std::cout << "\n✓ all tests passed" << std::endl;

    // Cleanup
    std::remove(eicar_path.c_str());
    return 0;
}
