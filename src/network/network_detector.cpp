// network/network_detector.cpp — T4.8.24
#include "network_detector.hpp"
#include "redact.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdio>

namespace logsoc::net::detect {

// ─── ctor / dtor / reset ─────────────────────────────────────────────────

NetworkDetector::NetworkDetector(const DetectionConfig& cfg) : cfg_(cfg) {}

void NetworkDetector::reset() {
    port_scan_.clear();
    dns_tunnel_.clear();
    exfil_.clear();
    exfil_dst_pub_.clear();
    beacon_.clear();
    // Don't reset stats_ — those are cumulative for observability.
}

void NetworkDetector::update_config(const DetectionConfig& cfg) {
    cfg_ = cfg;
}

// ─── Helpers ─────────────────────────────────────────────────────────────

double NetworkDetector::shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    std::array<size_t, 256> freq{};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    double h = 0.0;
    for (size_t c : freq) {
        if (c == 0) continue;
        double p = static_cast<double>(c) / static_cast<double>(len);
        h -= p * std::log2(p);
    }
    return h;
}

std::string NetworkDetector::make_pair_key(const char* src, const char* dst) {
    std::string k;
    k.reserve(64);
    k += src ? src : "";
    k += "->";
    k += dst ? dst : "";
    return k;
}

bool NetworkDetector::is_rfc1918(const char* ip) {
    if (!ip) return false;
    // 10.0.0.0/8
    if (std::strncmp(ip, "10.", 3) == 0) return true;
    // 172.16.0.0/12
    if (std::strncmp(ip, "172.", 4) == 0) {
        int second = 0;
        std::sscanf(ip + 4, "%d", &second);
        if (second >= 16 && second <= 31) return true;
    }
    // 192.168.0.0/16
    if (std::strncmp(ip, "192.168.", 8) == 0) return true;
    // 127.0.0.0/8
    if (std::strncmp(ip, "127.", 4) == 0) return true;
    return false;
}

bool NetworkDetector::has_credentials(const uint8_t* payload, size_t len) {
    if (!payload || len == 0) return false;
    // Reuse the same patterns as redact.hpp: any pattern match = cleartext creds.
    // We don't need the ranges, just a yes/no.
    auto ranges = compute_redact_ranges(payload, len);
    return !ranges.empty();
}

template <typename T>
size_t NetworkDetector::prune_and_count(std::deque<T>& dq, uint64_t now_us,
                                        int window_sec) {
    const uint64_t cutoff = now_us - static_cast<uint64_t>(window_sec) * 1'000'000ULL;
    while (!dq.empty() && dq.front().first < cutoff) dq.pop_front();
    return dq.size();
}

// Note: template prune_and_count<T> is defined in the header and
// implicitly instantiated at the call site. No explicit instantiation
// needed here (the previous version caused "duplicate explicit
// instantiation" errors at link time).

// ─── Main analysis ───────────────────────────────────────────────────────

DetectionResult NetworkDetector::analyze(
    uint64_t       ts_us,
    const char*    src_ip,
    uint16_t       src_port,
    const char*    dst_ip,
    uint16_t       dst_port,
    uint8_t        proto,
    uint8_t        tcp_flags,
    uint32_t       frame_size,
    const uint8_t* payload,
    size_t         payload_len) {

    DetectionResult r;
    if (!src_ip || !dst_ip) {
        stats_.total_benign.fetch_add(1, std::memory_order_relaxed);
        return r;  // can't analyze without IPs
    }

    std::string src(src_ip);
    std::string dst(dst_ip);

    // ─── 1. Port scan detection ───────────────────────────────────────────
    // Heuristic: N distinct dst_ports from same src_ip in window, OR many
    // SYN-only packets (no ACK) → likely scan.
    if (cfg_.port_scan_enabled && proto == 6 /* TCP */) {
        bool syn_only = (tcp_flags & TCP_SYN) && !(tcp_flags & TCP_ACK);

        if (syn_only) {
            // SYN-only: track in both per-port map and a separate SYN-only map
            auto& ps = port_scan_[src];
            ps.events.emplace_back(ts_us, dst_port);
            ps.syn_only_events.push_back(ts_us);

            // Prune both
            const uint64_t cutoff = ts_us -
                static_cast<uint64_t>(cfg_.port_scan_window_sec) * 1'000'000ULL;
            while (!ps.events.empty() && ps.events.front().first < cutoff)
                ps.events.pop_front();
            while (!ps.syn_only_events.empty() && ps.syn_only_events.front() < cutoff)
                ps.syn_only_events.pop_front();

            // Count distinct dst_ports in window
            std::sort(ps.events.begin(), ps.events.end(),
                      [](auto& a, auto& b) { return a.second < b.second; });
            size_t distinct_ports = 0;
            uint16_t last = 0;
            for (auto& e : ps.events) {
                if (distinct_ports == 0 || e.second != last) {
                    ++distinct_ports;
                    last = e.second;
                }
            }

            if (distinct_ports >= static_cast<size_t>(cfg_.port_scan_threshold) ||
                ps.syn_only_events.size() >= static_cast<size_t>(cfg_.port_scan_min_syn_only)) {
                r.is_alert = true;
                r.severity = Severity::HIGH;
                r.rule_id = "port_scan";
                r.description = "port_scan: src=" + src +
                                " distinct_ports=" + std::to_string(distinct_ports) +
                                " syn_only=" + std::to_string(ps.syn_only_events.size()) +
                                " window=" + std::to_string(cfg_.port_scan_window_sec) + "s";
                r.mitre = {"T1046", "T1018"};
                stats_.port_scans_detected.fetch_add(1, std::memory_order_relaxed);
                stats_.total_alerts.fetch_add(1, std::memory_order_relaxed);
                return r;
            }
        }
    }

    // ─── 2. DNS tunnel detection ──────────────────────────────────────────
    // Heuristic: long DNS query label or high entropy subdomain, repeated
    // N times from same src.
    if (cfg_.dns_tunnel_enabled && proto == 17 /* UDP */ && dst_port == 53) {
        // Find the DNS query: scan for the longest printable label in payload
        size_t max_label_len = 0;
        double max_entropy = 0.0;
        size_t cur_label = 0;
        for (size_t i = 0; i < payload_len; ++i) {
            uint8_t c = payload[i];
            // DNS labels: a-z, A-Z, 0-9, hyphen
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-') {
                ++cur_label;
            } else {
                if (cur_label > max_label_len) {
                    max_label_len = cur_label;
                    // Compute entropy of the label
                    max_entropy = shannon_entropy(payload + i - cur_label, cur_label);
                }
                cur_label = 0;
            }
        }
        if (cur_label > max_label_len) {
            max_label_len = cur_label;
            max_entropy = shannon_entropy(payload + payload_len - cur_label,
                                          cur_label);
        }

        if (max_label_len > static_cast<size_t>(cfg_.dns_tunnel_query_len) ||
            max_entropy > cfg_.dns_tunnel_entropy) {
            auto& dt = dns_tunnel_[src];
            dt.events.emplace_back(ts_us, max_label_len);
            const uint64_t cutoff = ts_us -
                static_cast<uint64_t>(60) * 1'000'000ULL;  // 60s window
            while (!dt.events.empty() && dt.events.front().first < cutoff)
                dt.events.pop_front();
            if (dt.events.size() >= static_cast<size_t>(cfg_.dns_tunnel_min_queries)) {
                r.is_alert = true;
                r.severity = Severity::HIGH;
                r.rule_id = "dns_tunnel";
                r.description = "dns_tunnel: src=" + src +
                                " label_len=" + std::to_string(max_label_len) +
                                " entropy=" + std::to_string(max_entropy).substr(0, 4) +
                                " queries=" + std::to_string(dt.events.size());
                r.mitre = {"T1071.004", "T1572"};
                stats_.dns_tunnels_detected.fetch_add(1, std::memory_order_relaxed);
                stats_.total_alerts.fetch_add(1, std::memory_order_relaxed);
                return r;
            }
        }
    }

    // ─── 3. Cleartext credentials ─────────────────────────────────────────
    if (cfg_.cleartext_creds_enabled &&
        (proto == 6 /* TCP */ || proto == 17 /* UDP */) &&
        has_credentials(payload, payload_len)) {
        r.is_alert = true;
        r.severity = Severity::CRITICAL;
        r.rule_id = "cleartext_creds";
        r.description = "cleartext_creds: " + src + ":" + std::to_string(src_port) +
                        " -> " + dst + ":" + std::to_string(dst_port);
        r.mitre = {"T1071", "T1059"};
        stats_.cleartext_creds_detected.fetch_add(1, std::memory_order_relaxed);
        stats_.total_alerts.fetch_add(1, std::memory_order_relaxed);
        return r;
    }

    // ─── 4. Exfiltration detection ─────────────────────────────────────────
    // Heuristic: src uploads > 1MB to non-RFC1918 dst in 60s window.
    if (cfg_.exfil_enabled && proto == 6 /* TCP */) {
        if (!is_rfc1918(dst.c_str())) {
            std::string pair = make_pair_key(src.c_str(), dst.c_str());
            auto& ex = exfil_[pair];
            ex.events.emplace_back(ts_us, frame_size);
            const uint64_t cutoff = ts_us -
                static_cast<uint64_t>(cfg_.exfil_window_sec) * 1'000'000ULL;
            uint64_t total = 0;
            while (!ex.events.empty() && ex.events.front().first < cutoff) {
                ex.events.pop_front();
            }
            for (auto& e : ex.events) total += e.second;
            if (total >= static_cast<uint64_t>(cfg_.exfil_bytes_threshold)) {
                r.is_alert = true;
                r.severity = Severity::HIGH;
                r.rule_id = "exfil";
                r.description = "exfil: " + src + " -> " + dst +
                                " bytes=" + std::to_string(total) +
                                " window=" + std::to_string(cfg_.exfil_window_sec) + "s";
                r.mitre = {"T1041", "T1048"};
                stats_.exfils_detected.fetch_add(1, std::memory_order_relaxed);
                stats_.total_alerts.fetch_add(1, std::memory_order_relaxed);
                return r;
            }
        }
    }

    // ─── 5. Beacon detection ──────────────────────────────────────────────
    // Heuristic: same (src, dst, dst_port) connected many times with
    // periodic timestamps and low jitter. Compute intervals and check
    // coefficient of variation (stddev/mean).
    if (cfg_.beacon_enabled && proto == 6 /* TCP */) {
        std::string beacon_key = make_pair_key(src.c_str(), dst.c_str());
        beacon_key += ":";
        beacon_key += std::to_string(dst_port);
        auto& bc = beacon_[beacon_key];
        bc.connect_ts.push_back(ts_us);

        // Prune old
        const uint64_t cutoff = ts_us -
            static_cast<uint64_t>(cfg_.beacon_window_sec) * 1'000'000ULL;
        while (!bc.connect_ts.empty() && bc.connect_ts.front() < cutoff)
            bc.connect_ts.pop_front();

        if (bc.connect_ts.size() >= static_cast<size_t>(cfg_.beacon_min_connections)) {
            // Compute intervals in seconds
            std::vector<double> intervals;
            intervals.reserve(bc.connect_ts.size() - 1);
            for (size_t i = 1; i < bc.connect_ts.size(); ++i) {
                double dt = static_cast<double>(bc.connect_ts[i] - bc.connect_ts[i-1])
                            / 1'000'000.0;
                if (dt > 0) intervals.push_back(dt);
            }
            if (intervals.size() >= 3) {
                double mean = 0;
                for (double d : intervals) mean += d;
                mean /= intervals.size();
                double var = 0;
                for (double d : intervals) var += (d - mean) * (d - mean);
                var /= intervals.size();
                double stddev = std::sqrt(var);
                double cv = (mean > 0) ? (stddev / mean) : 999.0;
                if (cv <= cfg_.beacon_jitter_max && mean >= 1.0 && mean <= 600.0) {
                    r.is_alert = true;
                    r.severity = Severity::MEDIUM;
                    r.rule_id = "beacon";
                    r.description = "beacon: " + src + " -> " + dst + ":" +
                                    std::to_string(dst_port) +
                                    " period=" + std::to_string(mean).substr(0, 6) + "s" +
                                    " jitter=" + std::to_string(cv).substr(0, 4) +
                                    " conns=" + std::to_string(bc.connect_ts.size());
                    r.mitre = {"T1071.001", "T1573"};
                    stats_.beacons_detected.fetch_add(1, std::memory_order_relaxed);
                    stats_.total_alerts.fetch_add(1, std::memory_order_relaxed);
                    return r;
                }
            }
        }
    }

    // ─── 6. Sampling for benign events ────────────────────────────────────
    // If we reach here, no alert. Track benign count, sample for shipping.
    stats_.total_benign.fetch_add(1, std::memory_order_relaxed);
    return r;
}

size_t NetworkDetector::tracked_src_ips() const {
    return port_scan_.size() + dns_tunnel_.size();
}

size_t NetworkDetector::tracked_beacons() const {
    return beacon_.size();
}

}  // namespace logsoc::net::detect
