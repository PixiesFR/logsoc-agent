#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <sstream>
#include <fstream>
#include <limits>
#include <mutex>

namespace crypto {

/* ── PBKDF2-HMAC-SHA256 ── */
std::vector<uint8_t> derive_key(const std::string& secret,
                                  const std::vector<uint8_t>& salt,
                                  size_t keylen) {
    std::vector<uint8_t> key(keylen);
    int ok = PKCS5_PBKDF2_HMAC(secret.c_str(), (int)secret.size(),
                               salt.data(), (int)salt.size(),
                               600000, EVP_sha256(), (int)keylen, key.data());
    if (!ok) throw std::runtime_error("PBKDF2 failed");
    return key;
}

/* ── Random bytes ── */
std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), (int)n) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return buf;
}

/* ── AES-256-GCM ── */
AesGcmResult aes_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                             const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::runtime_error("AES key must be 32 bytes");
    // T12 audit fix #17: guard against silent int overflow on 2GB+ inputs.
    // OpenSSL's EVP_EncryptUpdate takes an int length. If plaintext exceeds
    // INT_MAX (2^31-1 ≈ 2GB) the cast wraps to a negative length, which
    // OpenSSL will then either reject (good) or process wrongly (bad).
    // Our events are <1MB so this is theoretical, but defending in depth.
    if (plaintext.size() > (size_t)std::numeric_limits<int>::max()) {
        throw std::runtime_error("AES-GCM: plaintext too large (>2GB)");
    }
    AesGcmResult result;
    result.nonce = random_bytes(12);
    result.ciphertext.resize(plaintext.size());
    result.tag.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)result.nonce.size(), nullptr) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.nonce.data()) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1) goto err;
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &final_len) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data()) != 1) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return result;
err:
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("AES-GCM encryption failed");
}

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& nonce,
                                     const std::vector<uint8_t>& tag,
                                     const std::vector<uint8_t>& key) {
    if (key.size() != 32) throw std::runtime_error("AES key must be 32 bytes");
    if (tag.size() != 16) throw std::runtime_error("AES tag must be 16 bytes");
    std::vector<uint8_t> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) != 1) goto err;
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM authentication failed (bad key or tampered)");
    }
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(len + final_len);
    return plaintext;
err:
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("AES-GCM decryption failed");
}

/* ── HMAC-SHA256 ── */
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& data,
                                  const std::vector<uint8_t>& key) {
    unsigned int len = 32;
    std::vector<uint8_t> result(32);
    if (!HMAC(EVP_sha256(), key.data(), (int)key.size(),
              data.data(), data.size(), result.data(), &len)) {
        throw std::runtime_error("HMAC failed");
    }
    result.resize(len);
    return result;
}

std::vector<uint8_t> hmac_sha256_str(const std::string& data,
                                      const std::vector<uint8_t>& key) {
    return hmac_sha256(std::vector<uint8_t>(data.begin(), data.end()), key);
}

/* ── Base64 ── */
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(B64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(B64[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::vector<uint8_t> base64_decode(const std::string& b64) {
    // T12.13 (audit Nova L-01): the previous version did `if (idx < 0)
    // continue;` which silently ate every non-base64 character (typos,
    // binary noise, non-ASCII). An attacker who can inject characters
    // into a base64 stream (e.g. via a logged payload) could create
    // ambigous decodes. We now allow only the standard base64 alphabet
    // plus common whitespace (\n, \r, \t, space) for PEM-style
    // multi-line input. Anything else throws.
    std::vector<uint8_t> out;
    int val = 0, valb = -8;
    for (uint8_t c : b64) {
        if (c == '=') break;
        int idx = -1;
        if (c >= 'A' && c <= 'Z') idx = c - 'A';
        else if (c >= 'a' && c <= 'z') idx = c - 'a' + 26;
        else if (c >= '0' && c <= '9') idx = c - '0' + 52;
        else if (c == '+') idx = 62;
        else if (c == '/') idx = 63;
        else if (c == '\n' || c == '\r' || c == '\t' || c == ' ') continue;
        else {
            throw std::runtime_error(
                std::string("base64_decode: invalid character 0x") +
                [&]{
                    char h[3] = {0};
                    std::snprintf(h, sizeof(h), "%02x", c);
                    return std::string(h);
                }());
        }
        val = (val << 6) + idx;
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

/* ── Hex encode ── */
std::string hex_encode(const std::vector<uint8_t>& data) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(H[b >> 4]);
        out.push_back(H[b & 0x0F]);
    }
    return out;
}

/* ── CRC32 ── */
// T12 audit fix #16: the table init is now wrapped in a std::once_flag
// instead of a plain bool check. Two threads calling crc32() at the
// same time could BOTH pass `if (crc_table_ready) return;` and race
// on the table initialization. With std::call_once this is impossible
// — the second thread blocks until the first finishes (and std::call_once
// guarantees the init function is called exactly once even under contention).
//
// We keep the bool for a tiny fast-path optimization (skip the
// once_flag atomic op after the first init), so the hot path is
// unchanged.
static uint32_t crc_table[256];
static std::once_flag crc_table_once;
static bool crc_table_ready = false;
static void init_crc_table_impl() {
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i;
        for (int j = 0; j < 8; j++) {
            c = (c >> 1) ^ (0xEDB88320 & -(c & 1));
        }
        crc_table[i] = c;
    }
    crc_table_ready = true;
}
static void init_crc_table() {
    if (crc_table_ready) return;  // fast path (relaxed read; once_flag is the real guard)
    std::call_once(crc_table_once, init_crc_table_impl);
}

uint32_t crc32(const uint8_t* data, size_t len) {
    init_crc_table();
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        c = crc_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

} // namespace crypto

/* -- SHA-256 hex -- */
namespace crypto {
std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(mdctx);
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out.push_back(H[hash[i] >> 4]);
        out.push_back(H[hash[i] & 0x0F]);
    }
    return out;
}

/* ── SHA-256 of a file ── */
std::string sha256_file(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file for SHA-256: " + filepath);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit failed");
    }

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buf, static_cast<size_t>(f.gcount())) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal failed");
    }
    EVP_MD_CTX_free(mdctx);

    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out.push_back(H[hash[i] >> 4]);
        out.push_back(H[hash[i] & 0x0F]);
    }
    return out;
}

} // namespace crypto
