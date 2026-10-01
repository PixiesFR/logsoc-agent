// network/network_detector.hpp — T4.8.24 — Local network threat detection
//
// Real alerting on top of the data plane. Without this, the pcap collector
// is a passive logger that floods the backend with raw packets. With this,
// the agent raises LOCAL ALERTS (severity-tagged, MITRE-mapped) before
// shipping, and uses those alerts to:
//   1. Drive the sample_rate (always ship alerts, sample the rest)
//   2. Add `severity` + `mitre` fields to the JSON event
//   3. Trigger an immediate flush (don't wait 5s for a critical alert)
//
// Design: stateful sliding windows per src_ip / (src,dst) / etc.
//   - Port scan detector:   N distinct dst_ports from same src in W seconds
//   - DNS tunnel detector:  long DNS query OR high entropy subdomain
//   - Cleartext creds:      pattern match in payload (already in redact.hpp)
//   - Exfil detector:       large upload (>1MB) to non-RFC1918 dst
//   - Beacon detector:      same (src,dst) contacted with low jitter, periodic
//
// All thresholds configurable via the `network.detection` config block.
// Default thresholds tuned for a 1Gbps link with 1000-5000 events/s.
//
// Threading: detector methods called from the flush_thread (single thread),
// so no internal locking needed. State is per-instance and reset on init().
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace logsoc::net::detect {

// ─── Severity ────────────────────────────────────────────────────────────
// Aligned with the FIM eBPF severity levels for UI consistency.
enum class Severity : uint8_t {
    INFO     = 0,   // benign event, just observation
    LOW      = 1,   // anomaly, no clear malicious intent
    MEDIUM   = 2,   // suspicious activity
    HIGH     = 3,   // likely attack
    CRITICAL = 4,   // active intrusion (creds in cleartext, etc.)
};

// ─── MITRE technique (network-relevant subset) ───────────────────────────
// Keep this in sync with src/agent/mitre_mapping.hpp technique IDs.
struct MitreTag {
    std::string_view id;       // e.g. "T1046"
    std::string_view tactic;   // e.g. "Discovery"
    std::string_view name;     // human-readable
};

inline constexpr std::array<MitreTag, 12> NETWORK_MITRE = {{
    {"T1046",  "Discovery",         "Network Service Scanning"},
    {"T1018",  "Discovery",         "Remote System Discovery"},
    {"T1071",  "Command and Control","Application Layer Protocol"},
    {"T1071.004","Command and Control","DNS"},
    {"T1071.001","Command and Control","Web Protocols"},
    {"T1041",  "Exfiltration",      "Exfiltration Over C2 Channel"},
    {"T1048",  "Exfiltration",      "Exfiltration Over Alternative Protocol"},
    {"T1573",  "Command and Control","Encrypted Channel"},
    {"T1572",  "Command and Control","Protocol Tunneling"},
    {"T1059",  "Execution",         "Command and Scripting Interpreter"},
    {"T1110",  "Credential Access", "Brute Force"},
    {"T1530",  "Collection",        "Data from Cloud Storage"},
}};

// ─── Detection result (per packet) ───────────────────────────────────────
struct DetectionResult {
    bool is_alert = false;                  // true if this event is an alert
    Severity severity = Severity::INFO;
    std::string rule_id;                    // e.g. "port_scan", "dns_tunnel"
    std::string description;                // human-readable
    std::vector<std::string_view> mitre;    // technique IDs (1-2)
};

// ─── Detection config (loaded from central policy or local) ──────────────
struct DetectionConfig {
    // Port scan
    bool   port_scan_enabled = true;
    int    port_scan_threshold = 15;        // distinct ports in window
    int    port_scan_window_sec = 10;       // sliding window
    int    port_scan_min_syn_only = 10;     // OR many SYN-only packets

    // DNS tunnel
    bool   dns_tunnel_enabled = true;
    int    dns_tunnel_query_len = 60;       // query label > N chars
    double dns_tunnel_entropy = 4.0;        // subdomain entropy threshold
    int    dns_tunnel_min_queries = 20;     // N queries in window to alert

    // Cleartext credentials
    bool   cleartext_creds_enabled = true;
    // Patterns inherited from redact.hpp (no re-declare)

    // Exfiltration (large upload to public IP)
    bool   exfil_enabled = true;
    int    exfil_bytes_threshold = 1'000'000;  // 1MB total in window
    int    exfil_window_sec = 60;

    // Beacon (periodic C2)
    bool   beacon_enabled = true;
    int    beacon_min_connections = 10;     // N connections in window
    int    beacon_window_sec = 300;         // 5 min sliding window
    double beacon_jitter_max = 0.15;        // max stddev/mean (low = beacon)

    // Sampling
    int    sample_rate = 100;               // 1/N for benign events (100=1%)
    bool   always_ship_alerts = true;       // alerts bypass sampling
};

// ─── Detector class ──────────────────────────────────────────────────────
// Single-threaded (called from flush_thread). No internal locking.
class NetworkDetector {
public:
    explicit NetworkDetector(const DetectionConfig& cfg = {});

    // Re-initialize state (e.g. on config reload). Resets all windows.
    void reset();
    void update_config(const DetectionConfig& cfg);

    // Returns detection result for a single packet event.
    // The packet is identified by the parsed_packet fields plus the payload
    // preview (first N bytes for pattern matching).
    //
    // IMPORTANT: this method is called once per event in the flush thread,
    // so the state mutations are safe (no concurrent calls).
    DetectionResult analyze(
        uint64_t       ts_us,
        const char*    src_ip,         // dotted IPv4 string
        uint16_t       src_port,
        const char*    dst_ip,
        uint16_t       dst_port,
        uint8_t        proto,          // 6=TCP, 17=UDP, 1=ICMP
        uint8_t        tcp_flags,      // TCP_SYN, TCP_ACK, etc.
        uint32_t       frame_size,
        const uint8_t* payload,
        size_t         payload_len);

    // Per-rule stats for observability / E2E validation.
    struct DetectorStats {
        std::atomic<uint64_t> port_scans_detected{0};
        std::atomic<uint64_t> dns_tunnels_detected{0};
        std::atomic<uint64_t> cleartext_creds_detected{0};
        std::atomic<uint64_t> exfils_detected{0};
        std::atomic<uint64_t> beacons_detected{0};
        std::atomic<uint64_t> total_alerts{0};
        std::atomic<uint64_t> total_benign{0};
        std::atomic<uint64_t> sampled_shipped{0};
    };
    const DetectorStats& stats() const { return stats_; }

    // For testability: peek at internal state (read-only).
    size_t tracked_src_ips() const;
    size_t tracked_beacons() const;

    // T4.8.24: read current sample_rate so pcap_collector flush loop can
    // honor it. Returns 0 = sample nothing (ship all), 1 = ship all,
    // 100 = ship 1 in 100, etc.
    int sample_rate() const { return cfg_.sample_rate; }

private:
    DetectionConfig cfg_;
    DetectorStats   stats_;

    // ─── Port scan state ──────────────────────────────────────────────────
    struct PortScanState {
        std::deque<std::pair<uint64_t, uint16_t>> events;  // (ts_us, dst_port)
        std::deque<uint64_t> syn_only_events;              // ts_us of SYN-only
    };
    std::unordered_map<std::string, PortScanState> port_scan_;

    // ─── DNS tunnel state ─────────────────────────────────────────────────
    struct DnsTunnelState {
        std::deque<std::pair<uint64_t, size_t>> events;  // (ts_us, query_len)
    };
    std::unordered_map<std::string, DnsTunnelState> dns_tunnel_;  // keyed by src_ip

    // ─── Exfil state (per (src, dst) pair) ────────────────────────────────
    struct ExfilState {
        std::deque<std::pair<uint64_t, uint64_t>> events;  // (ts_us, bytes)
    };
    std::unordered_map<std::string, ExfilState> exfil_;
    std::unordered_map<std::string, std::deque<uint64_t>> exfil_dst_pub_;

    // ─── Beacon state (per (src, dst) pair) ───────────────────────────────
    struct BeaconState {
        std::deque<uint64_t> connect_ts;  // ts of each connection
    };
    std::unordered_map<std::string, BeaconState> beacon_;

    // ─── Helpers ──────────────────────────────────────────────────────────
    static double shannon_entropy(const uint8_t* data, size_t len);
    static std::string make_pair_key(const char* src, const char* dst);
    static bool is_rfc1918(const char* ip);
    static bool has_credentials(const uint8_t* payload, size_t len);

    // Generic sliding-window helper: drop events older than (now - window_sec)
    // and return the count of events within the window.
    template <typename T>
    static size_t prune_and_count(std::deque<T>& dq, uint64_t now_us,
                                  int window_sec);
};

// ─── TCP flag constants (mirror packet_parser.hpp) ───────────────────────
inline constexpr uint8_t TCP_FIN = 0x01;
inline constexpr uint8_t TCP_SYN = 0x02;
inline constexpr uint8_t TCP_RST = 0x04;
inline constexpr uint8_t TCP_PSH = 0x08;
inline constexpr uint8_t TCP_ACK = 0x10;
inline constexpr uint8_t TCP_URG = 0x20;

}  // namespace logsoc::net::detect
