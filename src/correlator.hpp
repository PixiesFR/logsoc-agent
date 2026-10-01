/* correlator.hpp — v3.7 eBPF ↔ journald cross-validation
 *
 * Spec: corrélation par vérification croisée entre les deux sources d'observation.
 *
 * - Buffer circulaire des derniers events eBPF (par pid, ts, event, comm)
 * - Buffer circulaire des dernières entrées journald (par pid, ts, comm)
 * - Pour chaque event eBPF: chercher match journald dans fenêtre ±2s
 * - Pour chaque event journald: chercher match eBPF dans fenêtre ±2s
 * - Pousser champs journald_match (bool) + journald_content (string) sur events eBPF
 * - Pousser champs ebpf_match (bool) + ebpf_event (string) sur events journald
 *
 * Thread-safe (mutex sur le buffer).
 */
#ifndef LOGSOC_CORRELATOR_HPP
#define LOGSOC_CORRELATOR_HPP

#include <atomic>
#include <chrono>
#include <ctime>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace logsoc {

// Fenêtre de corrélation en millisecondes
inline constexpr int kCorrelationWindowMs = 2000;  // ±2s

// Capacité max des buffers circulaires
inline constexpr std::size_t kMaxBufferEntries = 4096;

struct EbpfEntry {
    std::time_t ts;          // unix seconds
    uint64_t ts_ms;          // unix millis (précis)
    uint32_t pid;
    std::string event;       // "execve" | "fim" | "open" | "unlink" | "tcp_connect" | "write"
    std::string comm;        // nom du process
    std::string filename;    // pour fim/open/unlink
};

struct JournaldEntry {
    std::time_t ts;
    uint64_t ts_ms;
    uint32_t pid;
    std::string comm;
    std::string syslog_id;
    std::string message;
    std::string unit;
};

// Résultat de corrélation (du point de vue d'un event eBPF)
struct CorrelationResult {
    bool matched = false;
    std::string journald_message;   // message journald (tronqué)
    std::string journald_unit;      // systemd unit
    std::string journald_identifier;
    int64_t correlation_window_ms = 0;  // delta entre les 2 events
};

// Singleton thread-safe
class Correlator {
public:
    static Correlator& instance() {
        static Correlator inst;
        return inst;
    }

    // ── API appelée par eBPF collector ──────────────────
    void record_ebpf(const EbpfEntry& e) {
        std::lock_guard<std::mutex> lk(mtx_);
        ebpf_buf_.push_back(e);
        if (ebpf_buf_.size() > kMaxBufferEntries) {
            ebpf_buf_.pop_front();
        }
    }

    // Cherche une entrée journald qui matche cet event eBPF (pid + ts ±2s)
    // L'appelant doit fournir un event eBPF pour calculer la fenêtre.
    // On retourne TOUTES les entrées journald qui matchent (en pratique 0 ou 1).
    std::optional<JournaldEntry> find_journald_for_ebpf(const EbpfEntry& e) const {
        std::lock_guard<std::mutex> lk(mtx_);
        int64_t best_delta = std::numeric_limits<int64_t>::max();
        std::optional<JournaldEntry> best;
        for (const auto& j : journald_buf_) {
            if (j.pid != e.pid) continue;
            int64_t delta_ms = (int64_t)e.ts_ms - (int64_t)j.ts_ms;
            if (delta_ms < 0) delta_ms = -delta_ms;
            if (delta_ms > kCorrelationWindowMs) continue;
            if (delta_ms < best_delta) {
                best_delta = delta_ms;
                best = j;
            }
        }
        return best;
    }

    // ── API appelée par journald collector ──────────────
    void record_journald(const JournaldEntry& j) {
        std::lock_guard<std::mutex> lk(mtx_);
        journald_buf_.push_back(j);
        if (journald_buf_.size() > kMaxBufferEntries) {
            journald_buf_.pop_front();
        }
    }

    // Cherche un event eBPF qui matche cette entrée journald
    std::optional<EbpfEntry> find_ebpf_for_journald(const JournaldEntry& j) const {
        std::lock_guard<std::mutex> lk(mtx_);
        int64_t best_delta = std::numeric_limits<int64_t>::max();
        std::optional<EbpfEntry> best;
        for (const auto& e : ebpf_buf_) {
            if (e.pid != j.pid) continue;
            int64_t delta_ms = (int64_t)e.ts_ms - (int64_t)j.ts_ms;
            if (delta_ms < 0) delta_ms = -delta_ms;
            if (delta_ms > kCorrelationWindowMs) continue;
            if (delta_ms < best_delta) {
                best_delta = delta_ms;
                best = e;
            }
        }
        return best;
    }

    // Stats
    struct Stats {
        std::size_t ebpf_buf_size = 0;
        std::size_t journald_buf_size = 0;
        uint64_t ebpf_total = 0;
        uint64_t journald_total = 0;
        uint64_t ebpf_matched = 0;
        uint64_t journald_matched = 0;
    };
    Stats get_stats() const {
        std::lock_guard<std::mutex> lk(mtx_);
        Stats s;
        s.ebpf_buf_size = ebpf_buf_.size();
        s.journald_buf_size = journald_buf_.size();
        s.ebpf_total = ebpf_total_.load();
        s.journald_total = journald_total_.load();
        s.ebpf_matched = ebpf_matched_.load();
        s.journald_matched = journald_matched_.load();
        return s;
    }

    void inc_ebpf_total() { ebpf_total_++; }
    void inc_ebpf_matched() { ebpf_matched_++; }
    void inc_journald_total() { journald_total_++; }
    void inc_journald_matched() { journald_matched_++; }

    // Helper: génère un timestamp ms courant
    static uint64_t now_ms() {
        using namespace std::chrono;
        return (uint64_t)duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();
    }

    // Helper: tronque un message pour stockage compact
    static std::string truncate(const std::string& s, std::size_t n = 256) {
        if (s.size() <= n) return s;
        return s.substr(0, n) + "...";
    }

private:
    Correlator() = default;
    mutable std::mutex mtx_;
    std::deque<EbpfEntry> ebpf_buf_;
    std::deque<JournaldEntry> journald_buf_;
    std::atomic<uint64_t> ebpf_total_{0};
    std::atomic<uint64_t> journald_total_{0};
    std::atomic<uint64_t> ebpf_matched_{0};
    std::atomic<uint64_t> journald_matched_{0};
};

} // namespace logsoc

#endif // LOGSOC_CORRELATOR_HPP
