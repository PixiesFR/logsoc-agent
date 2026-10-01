// tests/test_network_detector.cpp — T4.8.24
//
// Unit tests for the local network threat detector. We exercise each rule
// (port scan, DNS tunnel, cleartext creds, exfil, beacon) with synthetic
// events, then verify the detection result, severity, rule_id, and MITRE
// tags. The tests are deterministic — no real network, no real time.

#include "../src/network/network_detector.hpp"
#include <cstdio>
#include <cstring>
#include <string>

#define OK(cond) do { \
    if (!(cond)) { \
        std::printf("  FAIL: %s (line %d)\n", #cond, __LINE__); \
        ++failed; \
    } else { \
        ++passed; \
    } \
} while (0)

int main() {
    int passed = 0, failed = 0;

    // ─── Config ────────────────────────────────────────────────────────────
    // Use relaxed thresholds for testing: small windows, few events
    // needed, so each rule can fire in a few iterations.
    logsoc::net::detect::DetectionConfig cfg;
    cfg.port_scan_threshold = 5;          // 5 distinct ports
    cfg.port_scan_window_sec = 60;        // 60s window
    cfg.port_scan_min_syn_only = 5;       // OR 5 SYN-only packets
    cfg.dns_tunnel_query_len = 30;        // 30 char label
    cfg.dns_tunnel_entropy = 3.5;         // entropy threshold
    cfg.dns_tunnel_min_queries = 5;       // 5 queries
    cfg.cleartext_creds_enabled = true;
    cfg.exfil_bytes_threshold = 50000;    // 50KB
    cfg.exfil_window_sec = 60;
    cfg.beacon_min_connections = 5;       // 5 connections
    cfg.beacon_window_sec = 300;          // 5 min window
    cfg.beacon_jitter_max = 0.20;         // < 20% jitter
    cfg.sample_rate = 100;
    cfg.always_ship_alerts = true;

    logsoc::net::detect::NetworkDetector det(cfg);

    uint64_t T0 = 1'700'000'000'000'000ULL;  // µs epoch

    // ─── 1. Port scan: 5 SYN packets on different ports → alert ──────────
    {
        // Reset to clean state
        det.reset();
        uint16_t ports[] = {22, 80, 443, 3306, 8080};
        bool alerted = false;
        for (int i = 0; i < 5; ++i) {
            auto r = det.analyze(
                T0 + i * 100'000,  // 100ms apart
                "10.0.0.5", 33333 + i,
                "192.168.1.100", ports[i],
                6 /* TCP */,
                logsoc::net::detect::TCP_SYN,
                64, nullptr, 0);
            if (r.is_alert) {
                alerted = true;
                OK(r.rule_id == "port_scan");
                OK(r.severity == logsoc::net::detect::Severity::HIGH);
                OK(r.mitre.size() >= 1);
                bool has_t1046 = false;
                for (auto m : r.mitre) if (m == "T1046") has_t1046 = true;
                OK(has_t1046);
            }
        }
        OK(alerted);
        if (alerted) {
            auto& st = det.stats();
            OK(st.port_scans_detected.load() >= 1);
        }
    }

    // ─── 2. Port scan: SYN+ACK (full handshake) → NO alert ───────────────
    {
        det.reset();
        uint16_t ports[] = {22, 80, 443, 3306, 8080, 9000};
        bool alerted = false;
        for (int i = 0; i < 6; ++i) {
            auto r = det.analyze(
                T0 + i * 100'000,
                "10.0.0.5", 33333,
                "192.168.1.100", ports[i],
                6,
                logsoc::net::detect::TCP_SYN | logsoc::net::detect::TCP_ACK,
                64, nullptr, 0);
            if (r.is_alert) { alerted = true; break; }
        }
        OK(!alerted);  // SYN+ACK is established, not a scan
    }

    // ─── 3. DNS tunnel: long encoded subdomain, repeated → alert ──────────
    {
        det.reset();
        // Long, high-entropy subdomain (base32-style) repeated 5 times.
        // DNS label format: only a-z, 0-9, hyphens.
        std::string long_label =
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567";
        bool alerted = false;
        for (int i = 0; i < 5; ++i) {
            auto r = det.analyze(
                T0 + i * 200'000,  // 200ms apart
                "10.0.0.5", 12345,
                "8.8.8.8", 53,
                17 /* UDP */, 0, 100,
                (const uint8_t*)long_label.data(), long_label.size());
            if (r.is_alert) {
                alerted = true;
                OK(r.rule_id == "dns_tunnel");
                OK(r.severity == logsoc::net::detect::Severity::HIGH);
                bool has_t1071 = false;
                for (auto m : r.mitre) if (m == "T1071.004") has_t1071 = true;
                OK(has_t1071);
            }
        }
        OK(alerted);
    }

    // ─── 4. DNS tunnel: short normal domain, no alert ──────────────────────
    {
        det.reset();
        std::string normal = "www.google.com";
        bool alerted = false;
        for (int i = 0; i < 10; ++i) {
            auto r = det.analyze(
                T0 + i * 100'000,
                "10.0.0.5", 12345,
                "8.8.8.8", 53,
                17, 0, 30,
                (const uint8_t*)normal.data(), normal.size());
            if (r.is_alert) { alerted = true; break; }
        }
        OK(!alerted);
    }

    // ─── 5. Cleartext creds: HTTP POST with password= → CRITICAL alert ────
    {
        det.reset();
        std::string http_post =
            "POST /login HTTP/1.1\r\nHost: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            "username=alice&password=hunter2&submit=1";
        auto r = det.analyze(
            T0,
            "10.0.0.5", 54321,
            "93.184.216.34", 80,  // public IP
            6, 0, http_post.size(),
            (const uint8_t*)http_post.data(), http_post.size());
        OK(r.is_alert);
        OK(r.rule_id == "cleartext_creds");
        OK(r.severity == logsoc::net::detect::Severity::CRITICAL);
    }

    // ─── 6. Cleartext creds: HTTPS (no payload to inspect) → no alert ─────
    {
        det.reset();
        std::string encrypted_blob(256, 'x');  // pretend TLS-encrypted
        auto r = det.analyze(
            T0,
            "10.0.0.5", 54321,
            "93.184.216.34", 443,  // HTTPS
            6, 0, encrypted_blob.size(),
            (const uint8_t*)encrypted_blob.data(), encrypted_blob.size());
        OK(!r.is_alert);
    }

    // ─── 7. Exfil: 5 large uploads to public IP, total > 50KB → alert ────
    {
        det.reset();
        std::string payload(5000, 'A');  // 5KB
        bool alerted = false;
        for (int i = 0; i < 20; ++i) {  // 20 * 5KB = 100KB
            auto r = det.analyze(
                T0 + i * 100'000,
                "10.0.0.5", 33333,
                "203.0.113.42", 443,  // public IP
                6, 0, payload.size(),
                (const uint8_t*)payload.data(), payload.size());
            if (r.is_alert) {
                alerted = true;
                OK(r.rule_id == "exfil");
                OK(r.severity == logsoc::net::detect::Severity::HIGH);
                bool has_t1041 = false;
                for (auto m : r.mitre) if (m == "T1041") has_t1041 = true;
                OK(has_t1041);
            }
        }
        OK(alerted);
    }

    // ─── 8. Exfil: large upload to RFC1918 → no alert (internal backup) ──
    {
        det.reset();
        std::string payload(5000, 'A');
        bool alerted = false;
        for (int i = 0; i < 20; ++i) {
            auto r = det.analyze(
                T0 + i * 100'000,
                "10.0.0.5", 33333,
                "192.168.1.100", 443,  // RFC1918
                6, 0, payload.size(),
                (const uint8_t*)payload.data(), payload.size());
            if (r.is_alert) { alerted = true; break; }
        }
        OK(!alerted);
    }

    // ─── 9. Beacon: 10 connections to same dst, perfectly periodic ───────
    {
        det.reset();
        // Connections every 30 seconds exactly (jitter = 0)
        bool alerted = false;
        for (int i = 0; i < 10; ++i) {
            auto r = det.analyze(
                T0 + (uint64_t)i * 30 * 1'000'000ULL,  // exactly 30s apart
                "10.0.0.5", 33333,
                "203.0.113.42", 443,
                6, 0, 100,
                nullptr, 0);
            if (r.is_alert) {
                alerted = true;
                OK(r.rule_id == "beacon");
                OK(r.severity == logsoc::net::detect::Severity::MEDIUM);
                bool has_t1071 = false;
                for (auto m : r.mitre) if (m == "T1071.001") has_t1071 = true;
                OK(has_t1071);
            }
        }
        OK(alerted);
    }

    // ─── 10. Beacon: random intervals → no alert (jitter too high) ───────
    {
        det.reset();
        // 10 connections but with very irregular intervals
        uint64_t offsets[] = {0, 1, 7, 11, 18, 22, 35, 40, 50, 100};  // seconds
        bool alerted = false;
        for (int i = 0; i < 10; ++i) {
            auto r = det.analyze(
                T0 + offsets[i] * 1'000'000ULL,
                "10.0.0.5", 33333,
                "203.0.113.42", 443,
                6, 0, 100,
                nullptr, 0);
            if (r.is_alert) { alerted = true; break; }
        }
        OK(!alerted);
    }

    // ─── 11. Benign HTTP GET → no alert ───────────────────────────────────
    {
        det.reset();
        std::string http_get =
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        auto r = det.analyze(
            T0,
            "10.0.0.5", 54321,
            "93.184.216.34", 80,
            6, 0, http_get.size(),
            (const uint8_t*)http_get.data(), http_get.size());
        OK(!r.is_alert);
    }

    // ─── 12. Stats: counters increment correctly ──────────────────────────
    {
        // Fresh detector (don't reuse the shared one — its state may
        // trigger a rule on the 50 events we send here, depending on the
        // previous test's leftover).
        logsoc::net::detect::NetworkDetector det2(cfg);
        std::string benign_payload = "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n";
        for (int i = 0; i < 50; ++i) {
            det2.analyze(
                T0 + i * 100'000,
                "10.0.0.5", 12345 + i,
                "192.168.1.1", 80,
                6,
                logsoc::net::detect::TCP_SYN | logsoc::net::detect::TCP_ACK,
                benign_payload.size(),
                (const uint8_t*)benign_payload.data(), benign_payload.size());
        }
        auto& st = det2.stats();
        OK(st.total_benign.load() == 50);
        OK(st.total_alerts.load() == 0);
    }

    // ─── 13. sample_rate() returns config value ──────────────────────────
    {
        logsoc::net::detect::DetectionConfig cfg2;
        cfg2.sample_rate = 250;
        logsoc::net::detect::NetworkDetector d2(cfg2);
        OK(d2.sample_rate() == 250);
    }

    // ─── 14. MITRE tags are non-empty strings ─────────────────────────────
    {
        OK(logsoc::net::detect::NETWORK_MITRE.size() == 12);
        for (auto& tag : logsoc::net::detect::NETWORK_MITRE) {
            OK(!tag.id.empty());
            OK(!tag.tactic.empty());
        }
    }

    // ─── 15. rfc1918 check ────────────────────────────────────────────────
    // Indirect test via exfil: dst=10.x is private, no exfil alert
    {
        det.reset();
        std::string payload(5000, 'A');
        auto r = det.analyze(
            T0,
            "10.0.0.5", 33333,
            "10.0.0.99", 443,  // RFC1918
            6, 0, payload.size(),
            (const uint8_t*)payload.data(), payload.size());
        OK(!r.is_alert);
    }

    std::printf("\n=== test_network_detector: %d passed, %d failed ===\n",
                passed, failed);
    return failed == 0 ? 0 : 1;
}
