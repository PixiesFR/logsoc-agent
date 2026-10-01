#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "crypto.hpp"

namespace uuid {

// Generate UUID v4 (random) without libuuid dependency
inline std::string generate() {
    auto bytes = crypto::random_bytes(16);
    // Version 4: bits 12-15 of time_hi_and_version = 0b0100
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Variant 1: bits 6-7 of clock_seq_hi_and_reserved = 0b10
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(H[bytes[i] >> 4]);
        out.push_back(H[bytes[i] & 0x0F]);
    }
    return out;
}

} // namespace uuid
