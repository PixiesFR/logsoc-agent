// compile_yara_rule.cpp — T77_eicar helper
//
// Compile a YARA rule from a source string and write the .yarac
// blob to a file. Used by T77_eicar E2E test to push a real
// EICAR ruleset via PUT /api/v1/yara/ruleset.
//
// Usage: ./compile_yara_rule <rule.yar> <out.yarac>
//   <rule.yar>     YARA source file (one rule, or a small set)
//   <out.yarac>    Output path for the compiled blob
//
// Also writes <out.yarac>.sha256 with the hex SHA256 of the blob,
// matching the format the backend uses for integrity checks.
//
// Build:
//   g++ -std=c++17 -O2 -o compile_yara_rule compile_yara_rule.cpp
//       $(pkg-config --cflags --libs yara) -lcrypto
//
// (See src/tools/Makefile for the canonical build command.)
//
// Pattern is the same as test_yara_blob_load.cpp (T77/v3.21.0):
//   yr_compiler_create → yr_compiler_add_string →
//   yr_compiler_get_rules → yr_rules_save_stream.

#include <yara.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// yr_rules_save_stream callback: write chunk to vector
// Signature: YR_STREAM_WRITE_FUNC = size_t (*)(const void*, size_t, size_t, void*)
// Returns count of items written (1 if size==chunk size, 0 on error).
static size_t save_stream_cb(const void* data, size_t size, size_t count, void* user_data) {
    auto* buf = static_cast<std::vector<uint8_t>*>(user_data);
    size_t bytes = size * count;
    buf->insert(buf->end(), static_cast<const uint8_t*>(data),
                static_cast<const uint8_t*>(data) + bytes);
    return count;
}

static std::string sha256_hex(const std::vector<uint8_t>& blob) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, blob.data(), blob.size());
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (unsigned int i = 0; i < len; i++) {
        std::sprintf(hex + 2 * i, "%02x", digest[i]);
    }
    hex[len * 2] = '\0';
    return std::string(hex);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <rule.yar> <out.yarac>\n", argv[0]);
        return 2;
    }

    const char* rule_path = argv[1];
    const char* out_path = argv[2];

    // Read rule source
    std::ifstream in(rule_path);
    if (!in) {
        std::fprintf(stderr, "Cannot read rule file: %s\n", rule_path);
        return 1;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string rule_text = ss.str();

    if (rule_text.empty()) {
        std::fprintf(stderr, "Rule file is empty: %s\n", rule_path);
        return 1;
    }

    // Init libyara
    if (yr_initialize() != ERROR_SUCCESS) {
        std::fprintf(stderr, "yr_initialize failed\n");
        return 1;
    }

    int exit_code = 0;
    YR_COMPILER* compiler = nullptr;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::fprintf(stderr, "yr_compiler_create failed\n");
        yr_finalize();
        return 1;
    }

    int add_rc = yr_compiler_add_string(compiler, rule_text.c_str(), nullptr);
    if (add_rc != 0) {
        std::fprintf(stderr, "yr_compiler_add_string failed with %d errors\n", add_rc);
        exit_code = 1;
        goto cleanup;
    }

    {
        YR_RULES* rules = nullptr;
        if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS || !rules) {
            std::fprintf(stderr, "yr_compiler_get_rules failed\n");
            exit_code = 1;
            goto cleanup;
        }

        std::vector<uint8_t> blob;
        YR_STREAM stream = { &blob, nullptr, save_stream_cb };
        if (yr_rules_save_stream(rules, &stream) != ERROR_SUCCESS) {
            std::fprintf(stderr, "yr_rules_save_stream failed\n");
            yr_rules_destroy(rules);
            exit_code = 1;
            goto cleanup;
        }
        yr_rules_destroy(rules);

        // Write blob
        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            std::fprintf(stderr, "Cannot write output: %s\n", out_path);
            exit_code = 1;
            goto cleanup;
        }
        out.write(reinterpret_cast<const char*>(blob.data()),
                  static_cast<std::streamsize>(blob.size()));
        out.close();

        // Write .sha256 sidecar
        std::string sha = sha256_hex(blob);
        std::string sha_path = std::string(out_path) + ".sha256";
        std::ofstream sha_out(sha_path);
        if (sha_out) {
            sha_out << sha << "\n";
            sha_out.close();
        }

        std::printf("blob_bytes=%zu sha256=%s\n", blob.size(), sha.c_str());
    }

cleanup:
    yr_compiler_destroy(compiler);
    yr_finalize();
    return exit_code;
}
