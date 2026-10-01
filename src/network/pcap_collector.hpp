#pragma once
/**
 * network/pcap_collector.hpp — Capture pcap intégré agent C++ v3.1 → T4.8.9
 *
 * v3.1 : MVP, flush_cb_ HTTP synchrone depuis pcap handler.
 * T4.8.9 (current) : refactor pour utiliser un RingBuffer SPSC partagé.
 *                    Le pcap handler push (zero-copy, lock-free) le ring,
 *                    un flush_thread dédié pop le ring, build JSON, et
 *                    push dans le InMemoryBuffer partagé (même Sender que
 *                    FIM/eBPF/Fanotify). Plus de HTTP inline dans le hot
 *                    path pcap.
 *
 * Config (merged depuis central):
 *   {
 *     "module_network": true,
 *     "network": {
 *       "interfaces": ["eth0"],
 *       "bpf_filter": "port 443 or port 80",
 *       "snaplen": 65535,
 *       "batch_interval_ms": 5000,
 *       "batch_max_events": 1000,
 *       "payload_preview_bytes": 256
 *     }
 *   }
 */
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include "json.hpp"
#include "ring_buffer.hpp"
#include "network_detector.hpp"   // T4.8.24: local threat detection

extern "C" {
#include <pcap.h>
}

namespace logsoc {

using json = nlohmann::json;

struct NetworkConfig {
    std::vector<std::string> interfaces;
    std::string bpf_filter = "";
    bool promiscuous = true;
    int snaplen = 65535;
    int buffer_mb = 8;
    int batch_interval_ms = 5000;
    int batch_max_events = 1000;
    int payload_preview_bytes = 256;
};

struct NetworkStats {
    std::atomic<uint64_t> packets_captured{0};
    std::atomic<uint64_t> packets_dropped{0};
    std::atomic<uint64_t> events_pushed{0};
    std::atomic<uint64_t> ring_dropped{0};   // T4.8.9: ring full drops
    std::atomic<uint64_t> flush_errors{0};
};

} // namespace logsoc

// T4.8.9: forward decl pour éviter include cycle. InMemoryBuffer vit dans
// in_memory_buffer.hpp dans le namespace GLOBAL (template class, pas
// namespaced). On stocke un pointeur vers le buffer partagé
// (même buffer que FIM) pour réutiliser le Sender/HMAC/queue existants.
template <typename T>
class InMemoryBuffer;

namespace logsoc {

class NetworkCollector {
public:
    NetworkCollector();
    ~NetworkCollector();

    bool init(const NetworkConfig& cfg);
    bool start();
    void stop();

    // T4.8.9: wire du buffer partagé (FIM sender).
    // Le flush_thread pop le ring, build JSON, push dans buf_.
    // Le Sender (déjà wire dans agent.cpp) lit buf_ et POST.
    void set_shared_buffer(InMemoryBuffer<std::string>* buf) { shared_buf_ = buf; }

    // Stats par pointeur (pas de copie de std::atomic)
    void get_stats(uint64_t* captured, uint64_t* dropped,
                   uint64_t* pushed, uint64_t* errors) const;

    // T4.8.9: ring + flush_error
    void get_stats_v2(uint64_t* captured, uint64_t* dropped,
                      uint64_t* pushed, uint64_t* ring_dropped,
                      uint64_t* errors) const;

    // v3.2: eBPF awareness
    void set_ebpf_active(bool active) { ebpf_active_ = active; }
    bool ebpf_active() const { return ebpf_active_; }

    // T4.8.24: wire the threat detector (T4.8.24). The detector is owned
    // externally (config reload-friendly) and used in the flush thread to
    // score every event before shipping. Detector pointer is non-owning.
    void set_detector(::logsoc::net::detect::NetworkDetector* det) {
        detector_ = det;
    }

    bool is_running() const;

    static bool check_root();

private:
    NetworkConfig cfg_;
    pcap_t* handle_ = nullptr;
    char errbuf_[PCAP_ERRBUF_SIZE] = {};
    NetworkStats stats_;

    // T4.8.9: ring buffer SPSC + flush thread + shared buffer
    RingBuffer* ring_ = nullptr;            // owned, heap alloc
    InMemoryBuffer<std::string>* shared_buf_ = nullptr;  // not owned
    std::thread capture_thread_;
    std::thread flush_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    bool ebpf_active_ = false;
    // T4.8.24: detector pointer (non-owning). Called in flush thread.
    ::logsoc::net::detect::NetworkDetector* detector_ = nullptr;

    void capture_loop();
    void flush_loop();
    std::string build_event_json(const ring_event_t& ev) const;

    static void pcap_handler_wrapper(u_char* user,
                                       const struct pcap_pkthdr* hdr,
                                       const u_char* data);
};

} // namespace logsoc
