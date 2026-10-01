#include "pcap_collector.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <utility>
#include <cstring>
#include <cstdio>
#include <openssl/sha.h>
#include "ring_buffer.hpp"
#include "packet_parser.hpp"
#include "in_memory_buffer.hpp"
#include "redact.hpp"  // T4.8.9: lifted to header for testability

extern "C" {
#include <unistd.h>
}

namespace logsoc {

// ─── helpers ────────────────────────────────────────────────────────────

static std::string sha256_hex(const uint8_t* data, size_t len) {
    unsigned char hash[32];
    SHA256(data, len, hash);
    char hex[65];
    for (int i = 0; i < 32; ++i)
        snprintf(hex + 2*i, 3, "%02x", hash[i]);
    hex[64] = '\0';
    return std::string(hex);
}

// ─── ctor / dtor ────────────────────────────────────────────────────────

NetworkCollector::NetworkCollector() = default;

NetworkCollector::~NetworkCollector() {
    stop();
    if (ring_) { delete ring_; ring_ = nullptr; }
}

// ─── init ───────────────────────────────────────────────────────────────

bool NetworkCollector::check_root() {
    return true;  // capabilities grant privs
}

bool NetworkCollector::init(const NetworkConfig& cfg) {
    if (!check_root()) {
        std::cerr << "[NET] ERROR: root required for packet capture\n";
        return false;
    }
    if (cfg.interfaces.empty()) {
        std::cerr << "[NET] No interfaces configured\n";
        return false;
    }
    cfg_ = cfg;

    // T4.8.9: alloc ring buffer (SPSC, 4096 events)
    if (!ring_) {
        ring_ = new RingBuffer();
    }

    const std::string& iface = cfg_.interfaces[0];

    handle_ = pcap_open_live(iface.c_str(), cfg_.snaplen,
                              cfg_.promiscuous ? 1 : 0,
                              10, errbuf_);
    if (!handle_) {
        std::cerr << "[NET] pcap_open_live(" << iface << ") failed: " << errbuf_ << "\n";
        return false;
    }

    if (cfg_.buffer_mb > 0)
        pcap_set_buffer_size(handle_, cfg_.buffer_mb * 1024 * 1024);

    if (!cfg_.bpf_filter.empty()) {
        bpf_program prog;
        if (pcap_compile(handle_, &prog, cfg_.bpf_filter.c_str(),
                         1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[NET] BPF compile: " << pcap_geterr(handle_) << "\n";
            pcap_close(handle_); handle_ = nullptr;
            return false;
        }
        if (pcap_setfilter(handle_, &prog) == -1) {
            std::cerr << "[NET] BPF setfilter: " << pcap_geterr(handle_) << "\n";
            pcap_freecode(&prog);
            pcap_close(handle_); handle_ = nullptr;
            return false;
        }
        pcap_freecode(&prog);
        std::cerr << "[NET] BPF: " << cfg_.bpf_filter << "\n";
    }

    initialized_.store(true, std::memory_order_release);
    std::cerr << "[NET] Interface " << iface << " opened (ring=4096, "
              << (shared_buf_ ? "shared_buf=set" : "shared_buf=NULL") << ")\n";
    return true;
}

// ─── pcap handler (hot path) ────────────────────────────────────────────

void NetworkCollector::pcap_handler_wrapper(u_char* user,
                                              const struct pcap_pkthdr* hdr,
                                              const u_char* data) {
    auto* self = reinterpret_cast<NetworkCollector*>(user);

    uint64_t ts = static_cast<uint64_t>(hdr->ts.tv_sec) * 1000000ULL
                + static_cast<uint64_t>(hdr->ts.tv_usec);

    parsed_packet pkt = parse_packet(data, hdr->caplen, ts);
    if (!pkt.valid) {
        self->stats_.packets_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    self->stats_.packets_captured.fetch_add(1, std::memory_order_relaxed);

    if (!self->ring_) return;  // init not called

    // T4.8.9: push vers ring SPSC (zero alloc, lock-free).
    // Le flush_thread pop et fait le formatting JSON lourd hors hot path.
    ring_event_t ev{};
    ev.timestamp_us = ts;
    // T12 audit fix #21: the previous code used strncpy without forcing
    // a null terminator. The buffer sizes (src_ip[46], dst_ip[46]) match
    // INET6_ADDRSTRLEN+1, so a full-length IPv6 (45 chars + null) would
    // be written with the null at position 45. But strncpy doesn't write
    // the null if the source is exactly the buffer length. The subsequent
    // std::string(ev.src_ip) in build_event_json would then read past the
    // buffer boundary until it hit a null in adjacent memory.
    //
    // Fix: use snprintf which always null-terminates, or memset+memcpy
    // with explicit null. We use snprintf here because pkt.src_ip is
    // already a C string (null-terminated by packet_parser).
    std::snprintf(ev.src_ip, sizeof(ev.src_ip), "%s", pkt.src_ip);
    std::snprintf(ev.dst_ip, sizeof(ev.dst_ip), "%s", pkt.dst_ip);
    ev.src_port = pkt.src_port;
    ev.dst_port = pkt.dst_port;
    ev.proto = pkt.proto;
    ev.tcp_flags = pkt.tcp_flags;
    ev.payload_len_frame = pkt.payload_len;
    ev.payload_preview_len = std::min<size_t>(
        pkt.payload_len, sizeof(ev.payload_preview));
    if (pkt.payload_start && ev.payload_preview_len > 0) {
        std::memcpy(ev.payload_preview, pkt.payload_start, ev.payload_preview_len);
    }
    // hash du payload total (pas juste le preview) pour YARA central
    if (pkt.payload_start && pkt.payload_len > 0) {
        std::string h = sha256_hex(pkt.payload_start, pkt.payload_len);
        std::snprintf(ev.payload_hash, sizeof(ev.payload_hash), "%s", h.c_str());
    }
    std::snprintf(ev.iface, sizeof(ev.iface), "%s", self->cfg_.interfaces[0].c_str());

    if (!self->ring_->push(ev)) {
        // Ring full → backpressure observability (T4.8.22 fix from silent drop)
        self->stats_.ring_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

// ─── build JSON from ring_event_t (called in flush thread) ──────────────
//
// T4.8.24: threat detection hook. If a detector is wired, run it on the
// event before serialization. The detection result is embedded in the JSON
// (`severity`, `rule_id`, `mitre`) so the backend can render alerts in the
// UI without re-running detection on already-shipped events.
std::string NetworkCollector::build_event_json(const ring_event_t& ev) const {
    json j;
    j["type"]      = "network";
    j["ts"]        = ev.timestamp_us / 1000;
    j["iface"]     = std::string(ev.iface);
    j["src"]       = json{{"ip", std::string(ev.src_ip)}, {"port", ev.src_port}};
    j["dst"]       = json{{"ip", std::string(ev.dst_ip)}, {"port", ev.dst_port}};
    j["proto"]     = (ev.proto == 6) ? "TCP" :
                     (ev.proto == 17) ? "UDP" :
                     (ev.proto == 1) ? "ICMP" : std::to_string(ev.proto);
    if (ev.tcp_flags) {
        std::string flags;
        if (ev.tcp_flags & TCP_SYN) flags += "SYN,";
        if (ev.tcp_flags & TCP_ACK) flags += "ACK,";
        if (ev.tcp_flags & TCP_PSH) flags += "PSH,";
        if (ev.tcp_flags & TCP_FIN) flags += "FIN,";
        if (ev.tcp_flags & TCP_RST) flags += "RST,";
        if (ev.tcp_flags & TCP_URG) flags += "URG,";
        if (!flags.empty()) flags.pop_back();
        j["flags"] = flags;
    }
    j["frame_size"] = ev.payload_len_frame;

    if (ev.payload_preview_len > 0) {
        auto ranges = compute_redact_ranges(ev.payload_preview, ev.payload_preview_len);
        j["payload_preview"] = hex_with_redactions(ev.payload_preview,
                                                    ev.payload_preview_len, ranges);
        j["payload_redacted"] = !ranges.empty();
        j["payload_hash"] = std::string(ev.payload_hash);
    }

    // T4.8.24: run local threat detection. If an alert fires, tag the event
    // with severity + rule + MITRE techniques so the backend can treat it as
    // a real SOC alert (not just a data-plane log).
    if (detector_) {
        auto det = detector_->analyze(
            ev.timestamp_us,
            ev.src_ip, ev.src_port,
            ev.dst_ip, ev.dst_port,
            ev.proto, ev.tcp_flags,
            ev.payload_len_frame,
            ev.payload_preview, ev.payload_preview_len);
        if (det.is_alert) {
            const char* sev = "info";
            switch (det.severity) {
                case ::logsoc::net::detect::Severity::INFO:     sev = "info"; break;
                case ::logsoc::net::detect::Severity::LOW:      sev = "low"; break;
                case ::logsoc::net::detect::Severity::MEDIUM:   sev = "medium"; break;
                case ::logsoc::net::detect::Severity::HIGH:     sev = "high"; break;
                case ::logsoc::net::detect::Severity::CRITICAL: sev = "critical"; break;
            }
            j["severity"] = sev;
            j["rule_id"]  = det.rule_id;
            j["alert_description"] = det.description;
            j["mitre"]    = json::array();
            for (auto m : det.mitre) j["mitre"].push_back(std::string(m));
            j["is_alert"] = true;
        } else {
            j["severity"] = "info";
            j["is_alert"] = false;
        }
    }

    return j.dump();
}

// ─── capture thread (pcap_loop) ─────────────────────────────────────────

void NetworkCollector::capture_loop() {
    if (!handle_) return;
    pcap_loop(handle_, 0, pcap_handler_wrapper,
              reinterpret_cast<u_char*>(this));
}

// ─── flush thread (ring → shared buffer) ────────────────────────────────
//
// T4.8.24: sampling for benign events. Alerts always pass through (and
// trigger a hint to the Sender to flush immediately). Benign events are
// sample_rate=100: 1 in 100 are shipped, 99 are dropped at the agent to
// avoid drowning ClickHouse at 1Gbps.
//
// Implementation note: we serialize the JSON first (cheap), then check the
// `is_alert` field, then decide to push or drop. This costs one parse per
// event, but it's in the flush thread (not the pcap hot path), and the
// cost is dwarfed by the SHA256 + hex formatting that already happened
// inside build_event_json. The 99% we drop are pure savings on the
// Sender/SSL/HMAC work.
void NetworkCollector::flush_loop() {
    using clock = std::chrono::steady_clock;
    auto last_log = clock::now();
    // T4.8.24: monotonic counter for sampling. Use a per-flush loop counter
    // to make the sample rate deterministic without depending on rand().
    uint64_t benign_counter = 0;
    int      sample_rate = 100;  // default, refreshed from detector config

    while (running_.load(std::memory_order_acquire)) {
        ring_event_t ev;
        size_t popped = 0;
        size_t sampled_out = 0;  // T4.8.24: benign events dropped by sampling
        size_t alerts_shipped = 0;
        while (ring_ && ring_->pop(ev) && popped < 64) {
            std::string body = build_event_json(ev);

            // T4.8.24: decision to ship or drop. Parse `is_alert` cheaply.
            // The JSON is small (~500 bytes typical), so this is fast.
            bool is_alert = false;
            try {
                json parsed = json::parse(body);
                is_alert = parsed.value("is_alert", false);
            } catch (...) {
                // Malformed JSON: treat as alert to avoid silent loss
                is_alert = true;
            }

            bool ship = false;
            if (is_alert) {
                ship = true;            // alerts always pass through
                ++alerts_shipped;
            } else {
                ++benign_counter;
                if (sample_rate > 0 && (benign_counter % sample_rate) == 0) {
                    ship = true;        // 1/N benign event for observability
                }
            }

            if (ship && shared_buf_) {
                if (shared_buf_->drop_oldest_if_full(body)) {
                    stats_.flush_errors.fetch_add(1, std::memory_order_relaxed);
                }
                stats_.events_pushed.fetch_add(1, std::memory_order_relaxed);
            } else if (!ship) {
                ++sampled_out;
            } else {
                (void)body;  // no shared_buf_ wired
            }
            ++popped;
        }

        // Heartbeat every 30s for observability
        auto now = clock::now();
        if (now - last_log >= std::chrono::seconds(30)) {
            // Refresh sample_rate from detector config (T4.8.24: config reload)
            if (detector_) sample_rate = detector_->sample_rate();

            uint64_t cap, drop, push, rdrop, err;
            get_stats_v2(&cap, &drop, &push, &rdrop, &err);
            std::cerr << "[NET-Flush] alive: popped=" << popped
                      << " alerts_shipped=" << alerts_shipped
                      << " sampled_out=" << sampled_out
                      << " sample_rate=1/" << sample_rate
                      << " ring_count=" << (ring_ ? ring_->count() : 0)
                      << " ring_dropped=" << rdrop
                      << " total: captured=" << cap
                      << " dropped=" << drop
                      << " pushed=" << push
                      << " flush_errors=" << err << "\n";
            last_log = now;
        }

        // Sleep 200ms when idle to avoid 100% CPU
        if (popped == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

// ─── start / stop ───────────────────────────────────────────────────────

bool NetworkCollector::start() {
    if (!initialized_.load(std::memory_order_acquire)) return false;
    running_.store(true, std::memory_order_release);
    capture_thread_ = std::thread(&NetworkCollector::capture_loop, this);
    flush_thread_ = std::thread(&NetworkCollector::flush_loop, this);
    std::cerr << "[NET] Capture started on " << cfg_.interfaces[0]
              << " (T4.8.9 ring+flush_thread)\n";
    return true;
}

void NetworkCollector::stop() {
    running_.store(false, std::memory_order_release);
    if (handle_) pcap_breakloop(handle_);
    if (capture_thread_.joinable()) capture_thread_.join();
    if (flush_thread_.joinable()) flush_thread_.join();
    if (handle_) { pcap_close(handle_); handle_ = nullptr; }
    std::cerr << "[NET] Stopped\n";
}

bool NetworkCollector::is_running() const {
    return running_.load(std::memory_order_acquire);
}

void NetworkCollector::get_stats(uint64_t* captured, uint64_t* dropped,
                                  uint64_t* pushed, uint64_t* errors) const {
    if (captured) *captured = stats_.packets_captured.load(std::memory_order_relaxed);
    if (dropped)  *dropped  = stats_.packets_dropped.load(std::memory_order_relaxed);
    if (pushed)   *pushed   = stats_.events_pushed.load(std::memory_order_relaxed);
    if (errors)   *errors   = stats_.flush_errors.load(std::memory_order_relaxed);
}

void NetworkCollector::get_stats_v2(uint64_t* captured, uint64_t* dropped,
                                     uint64_t* pushed, uint64_t* ring_dropped,
                                     uint64_t* errors) const {
    if (captured)     *captured     = stats_.packets_captured.load(::std::memory_order_relaxed);
    if (dropped)      *dropped      = stats_.packets_dropped.load(::std::memory_order_relaxed);
    if (pushed)       *pushed       = stats_.events_pushed.load(::std::memory_order_relaxed);
    if (ring_dropped) *ring_dropped = stats_.ring_dropped.load(::std::memory_order_relaxed);
    if (errors)       *errors       = stats_.flush_errors.load(::std::memory_order_relaxed);
}

} // namespace logsoc
