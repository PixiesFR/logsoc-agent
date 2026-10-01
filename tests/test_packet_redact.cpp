// tests/test_packet_redact.cpp — T4.8.9
// Unit tests for the compute_redact_ranges helper used in
// NetworkCollector::build_event_json to mask sensitive payload bytes
// (password=, token=, Bearer, etc.) before they are shipped to
// the central. Critical security primitive: a SOC product must NEVER
// exfiltrate creds via its own log channel.
//
// Behaviour note: the algorithm is GREEDY FIRST MATCH. Once a redact
// range starts at index i, the scanner jumps to i+re_len and looks
// for the next pattern from there. It does NOT find overlapping
// patterns within a redacted range. This is by design (the [REDACTED]
// marker replaces the bytes including any following pattern).

#include "../src/network/packet_parser.hpp"
#include "../src/network/redact.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <utility>
#include <string>

static int total_passed = 0;
static int total_failed = 0;

#define OK(cond) do { \
    if (cond) { ++total_passed; printf("  ok: %s\n", #cond); } \
    else      { ++total_failed; printf("  FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while(0)

int main() {
    printf("=== packet redaction tests (T4.8.9, T4.8.22) ===\n");

    // 1. No sensitive pattern → no ranges
    {
        std::string p = "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n";
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        OK(r.empty());
    }

    // 2. password= in middle of payload → 1 range
    {
        std::string p = "user=alice&password=hunter2&next=/";
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        OK(r.size() == 1);
        if (!r.empty()) {
            // "user=alice&" = 11 chars → password= starts at 11
            OK(r[0].first == 11);
            // re_len = 9 (password=) + min(64, 14) = 9+14 = 23
            OK(r[0].second == 11 + 9 + 14);
        }
    }

    // 3. Authorization: Bearer — case-insensitive match
    {
        // 25 chars
        std::string p = "Authorization: Bearer ***";
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        OK(r.size() == 1);
        if (!r.empty()) {
            // "authorization: " matches at 0, re_len = min(15+64, 25-0) = 25
            OK(r[0].first == 0);
            OK(r[0].second == 25);
        }
    }

    // 4. token= in middle (single match, greedy)
    {
        std::string p = "user=alice&token=abc123&next=/";  // 30 chars
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        OK(r.size() == 1);
        if (!r.empty()) {
            // "user=alice&" = 11 chars → token= starts at 11
            // re_len = 6 (token=) + min(64, 30-11=19) = 6+19 = 25
            // range = [11, 11+25=36) → truncated to 30
            OK(r[0].first == 11);
            OK(r[0].second == 30);
        }
    }

    // 5. Pattern at end of preview (truncation)
    {
        std::string p = "data=ok&token=";  // 14 chars
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        OK(r.size() == 1);
        if (!r.empty()) {
            // token= at 8, re_len = 6 + min(64, 6) = 6+6 = 12
            // range = [8, 20) → truncated to 14
            OK(r[0].first == 8);
            OK(r[0].second == 14);
        }
    }

    // 6. Two separated patterns
    {
        // "token=abc" (9) + 70 x's + "secret=value" (12) = 91 chars
        std::string p = "token=abc" + std::string(70, 'x') + "secret=value";
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        // token= at 0, re_len = 6+min(64, 91)=70 → [0, 70)
        // Then "secret=" at 79, re_len = 7+min(64, 12)=19 → [79, 98)→[79, 91)
        OK(r.size() == 2);
        if (r.size() == 2) {
            OK(r[0].first == 0);
            OK(r[0].second == 70);
            OK(r[1].first == 79);
            OK(r[1].second == 91);
        }
    }

    // 7. hex_with_redactions: verify [REDACTED:Nb] markers
    {
        std::string p = "password=hunter2";  // 16 chars
        auto r = logsoc::compute_redact_ranges((const uint8_t*)p.data(), p.size());
        std::string hex = logsoc::hex_with_redactions(
            (const uint8_t*)p.data(), p.size(), r);
        // re_len = 9 + min(64, 16-0=16) = 9+16 = 25 → truncated to 16
        // marker says [REDACTED:16B] (decimal, not hex — bug fix T4.8.9)
        OK(hex.find("[REDACTED:16B]") != std::string::npos);
        // The marker alone is 14 chars, no hex bytes outside (all redacted)
        OK(hex.size() == std::string("[REDACTED:16B]").size());
    }

    // 8. Parse a real Ethernet/IPv4/TCP packet
    {
        uint8_t frame[14 + 20 + 20 + 16] = {};
        frame[12] = 0x08; frame[13] = 0x00;
        frame[14] = 0x45;
        frame[16] = 0x00; frame[17] = 56;
        frame[23] = 6;
        frame[26] = 10; frame[27] = 0; frame[28] = 0; frame[29] = 1;
        frame[30] = 10; frame[31] = 0; frame[32] = 0; frame[33] = 2;
        frame[34] = 0x30; frame[35] = 0x39;  // 12345
        frame[36] = 0x00; frame[37] = 0x50;  // 80
        frame[34 + 12] = 0x50;
        const char* payload = "GET / HTTP/1.1\r\n";
        std::memcpy(frame + 14 + 20 + 20, payload, 16);

        logsoc::parsed_packet p = logsoc::parse_packet(frame, sizeof(frame), 1000);
        OK(p.valid);
        OK(p.is_ipv4);
        OK(p.proto == 6);
        OK(p.src_port == 12345);
        OK(p.dst_port == 80);
        OK(std::string(p.src_ip) == "10.0.0.1");
        OK(std::string(p.dst_ip) == "10.0.0.2");
        OK(p.payload_len == 16);
        OK(p.payload_start != nullptr);
    }

    // 9. Malformed IP header rejected
    {
        uint8_t frame[14 + 20 + 20] = {};
        frame[12] = 0x08; frame[13] = 0x00;
        frame[14] = 0x40;  // ihl=0 (invalid)
        logsoc::parsed_packet p = logsoc::parse_packet(frame, sizeof(frame), 1000);
        OK(!p.valid);
    }

    // 10. Non-IP frame
    {
        uint8_t frame[14] = {};
        frame[12] = 0x12; frame[13] = 0x34;
        logsoc::parsed_packet p = logsoc::parse_packet(frame, sizeof(frame), 1000);
        OK(!p.valid);
    }

    // 11. UDP packet
    {
        uint8_t frame[14 + 20 + 8 + 8] = {};
        frame[12] = 0x08; frame[13] = 0x00;
        frame[14] = 0x45;
        frame[16] = 0x00; frame[17] = 36;
        frame[23] = 17;
        frame[26] = 10; frame[27] = 0; frame[28] = 0; frame[29] = 1;
        frame[30] = 10; frame[31] = 0; frame[32] = 0; frame[33] = 2;
        frame[34] = 0x00; frame[35] = 0x35;
        frame[36] = 0x04; frame[37] = 0xD2;
        std::memcpy(frame + 14 + 20 + 8, "PINGDATA", 8);

        logsoc::parsed_packet p = logsoc::parse_packet(frame, sizeof(frame), 1000);
        OK(p.valid);
        OK(p.proto == 17);
        OK(p.src_port == 53);
        OK(p.dst_port == 1234);
        OK(p.payload_len == 8);
    }

    // 12. ICMP packet
    {
        uint8_t frame[14 + 20 + 8 + 8] = {};
        frame[12] = 0x08; frame[13] = 0x00;
        frame[14] = 0x45;
        frame[16] = 0x00; frame[17] = 36;
        frame[23] = 1;
        frame[26] = 10; frame[27] = 0; frame[28] = 0; frame[29] = 1;
        frame[30] = 10; frame[31] = 0; frame[32] = 0; frame[33] = 2;

        logsoc::parsed_packet p = logsoc::parse_packet(frame, sizeof(frame), 1000);
        OK(p.valid);
        OK(p.proto == 1);
        OK(p.src_port == 0);
        OK(p.dst_port == 0);
        OK(p.payload_len == 16);
    }

    printf("=== %d passed, %d failed ===\n", total_passed, total_failed);
    return total_failed == 0 ? 0 : 1;
}
