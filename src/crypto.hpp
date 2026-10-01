#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <string>

namespace crypto {

// Derive une cle symetrique depuis un secret + sel (PBKDF2-HMAC-SHA256)
std::vector<uint8_t> derive_key(const std::string& secret,
                                  const std::vector<uint8_t>& salt,
                                  size_t keylen = 32);

// Octets aleatoires
std::vector<uint8_t> random_bytes(size_t n);

// AES-256-GCM
struct AesGcmResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce; // 12 bytes
    std::vector<uint8_t> tag;   // 16 bytes
};
AesGcmResult aes_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                             const std::vector<uint8_t>& key);
std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& nonce,
                                     const std::vector<uint8_t>& tag,
                                     const std::vector<uint8_t>& key);

// HMAC-SHA256
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& data,
                                  const std::vector<uint8_t>& key);
std::vector<uint8_t> hmac_sha256_str(const std::string& data,
                                      const std::vector<uint8_t>& key);

// Base64
std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& b64);

// Hex encode
std::string hex_encode(const std::vector<uint8_t>& data);

// CRC32 (IEEE 802.3 standard polynomial)
uint32_t crc32(const uint8_t* data, size_t len);

// SHA-256 hex (raw hash, not HMAC)
std::string sha256_hex(const std::string& data);

// SHA-256 hex of a file (self-integrity check)
std::string sha256_file(const std::string& filepath);

} // namespace crypto
