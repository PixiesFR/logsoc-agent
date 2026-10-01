#pragma once
// network/redact.hpp — T4.8.9: payload redaction helper, lifted from
// pcap_collector.cpp into a header so unit tests can link it without
// dragging in libpcap. Behaviour MUST stay in sync with the original
// implementation in pcap_collector.cpp (compute_redact_ranges).
//
// Replaces password=, token=, etc. in payload previews with [REDACTED:Nb]
// markers. Critical security primitive: SOC product must NEVER leak
// creds via its own log channel.

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace logsoc {

inline std::vector<std::pair<size_t, size_t>>
compute_redact_ranges(const uint8_t* payload, size_t preview_len) {
    static const char* kRedactPatterns[] = {
        "password=", "passwd=", "pwd=", "secret=",
        "token=", "api_key=", "apikey=", "auth=",
        "authorization: ", "bearer "
    };
    std::vector<std::pair<size_t, size_t>> ranges;
    for (size_t i = 0; i < preview_len; ) {
        bool matched = false;
        for (const char* pat : kRedactPatterns) {
            size_t patlen = std::strlen(pat);
            if (i + patlen > preview_len) continue;
            bool match = true;
            for (size_t k = 0; k < patlen; ++k) {
                char pc = static_cast<char>(payload[i + k]);
                if (pc >= 'A' && pc <= 'Z') pc = pc - 'A' + 'a';
                if (pc != pat[k]) { match = false; break; }
            }
            if (match) {
                size_t re_len = std::min(patlen + 64, preview_len - i);
                ranges.emplace_back(i, i + re_len);
                i += re_len;
                matched = true;
                break;
            }
        }
        if (!matched) ++i;
    }
    return ranges;
}

inline std::string hex_with_redactions(
    const uint8_t* payload, size_t preview_len,
    const std::vector<std::pair<size_t, size_t>>& ranges) {
    std::ostringstream oss;
    // T4.8.9 bug fix: was using std::hex which printed the redaction
    // length in hex (e.g. "10" for 16 bytes). The [REDACTED:Nb] marker
    // is meant to be human-readable, so the count must be DECIMAL.
    bool in_redact = false;
    size_t redact_end = 0, ri = 0;
    for (size_t i = 0; i < preview_len; ++i) {
        if (ri < ranges.size() && i == ranges[ri].first) {
            in_redact = true;
            redact_end = ranges[ri].second;
            // Use a local oss for the marker so we don't pollute the
            // outer stream's std::hex mode for the rest of the payload.
            std::ostringstream marker;
            marker << "[REDACTED:" << (redact_end - ranges[ri].first) << "B]";
            oss << marker.str();
        }
        if (!in_redact) {
            // Switch to hex for the payload bytes themselves
            std::ostringstream byte_str;
            byte_str << std::hex << std::setfill('0')
                     << std::setw(2) << static_cast<int>(payload[i]);
            oss << byte_str.str();
        }
        if (in_redact && i + 1 == redact_end) {
            in_redact = false;
            ++ri;
        }
    }
    return oss.str();
}

} // namespace logsoc
