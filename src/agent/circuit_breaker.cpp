// circuit_breaker.cpp — T4.8.4 — Anti-stampede circuit breaker (impl)
#include "circuit_breaker.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace logsoc::agent::cb {

const char* state_name(State s) {
    switch (s) {
        case State::CLOSED:    return "CLOSED";
        case State::OPEN:      return "OPEN";
        case State::HALF_OPEN: return "HALF_OPEN";
    }
    return "UNKNOWN";
}

CircuitBreaker::CircuitBreaker(const Config& cfg)
    : cfg_(cfg), window_(cfg.window_size, false) {
    // v4.8.0 (T4.8 hotfix): ensure the state file exists with a sensible
    // default (CLOSED, 0 trips) before load_state() runs. Without this, a
    // fresh install has no file → no observability of CB state across
    // restarts, and the first transition_to() may race with a missing
    // parent directory. KISS: write a tiny stub if the file is absent.
    if (!cfg_.state_file.empty()) {
        std::ifstream test(cfg_.state_file);
        if (!test) {
            // Parent dir must exist (create if needed, best-effort)
            std::string p = cfg_.state_file;
            auto slash = p.find_last_of('/');
            if (slash != std::string::npos && slash > 0) {
                std::string dir = p.substr(0, slash);
                ::mkdir(dir.c_str(), 0755);  // ignore EEXIST
            }
            std::ofstream stub(cfg_.state_file);
            if (stub) {
                stub << "{\"state\":\"CLOSED\",\"trips\":0}\n";
                std::fprintf(stderr, "[CircuitBreaker] initialized state file %s\n",
                             cfg_.state_file.c_str());
            }
        }
    }
    load_state();
}

bool CircuitBreaker::allow() {
    State s = state_.load(std::memory_order_acquire);
    if (s == State::CLOSED) return true;
    if (s == State::HALF_OPEN) return true;  // probe call
    // OPEN: check if recovery timer expired
    std::lock_guard<std::mutex> lock(mtx_);
    if (s == State::OPEN) {
        auto now = std::chrono::steady_clock::now();
        if (now - opened_at_ >= cfg_.open_duration) {
            // T4.8.14 (PHASE 2 hotfix): reset directly to CLOSED instead
            // of HALF_OPEN. Previous design relied on a "probe" call from
            // the FdResolver worker, but in our case the worker only
            // processes requests when allow() returns true, and once the
            // FIM pipeline is in CB_OPEN state NO requests flow through
            // → HALF_OPEN is never reached → CB is stuck forever.
            //
            // KISS: assume /proc lookup recovers instantly. Reset the
            // failure window too so a single new failure doesn't
            // immediately re-trip. This matches our use case
            // (systemd-managed agent, /proc always available after boot).
            //
            // The trade-off: one request that fails immediately after
            // recovery will count as a fresh failure. Acceptable
            // because the next open_duration window (default 60s)
            // will give plenty of time to gather evidence.
            std::fill(window_.begin(), window_.end(), false);
            window_idx_ = 0;
            window_filled_ = 0;
            transition_to(State::CLOSED);
            return true;
        }
    }
    return false;
}

void CircuitBreaker::on_success() {
    State s = state_.load(std::memory_order_acquire);
    if (s == State::HALF_OPEN) {
        // Probe succeeded → CLOSE
        std::lock_guard<std::mutex> lock(mtx_);
        transition_to(State::CLOSED);
        return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    if (window_idx_ >= window_.size()) window_idx_ = 0;
    window_[window_idx_++] = false;  // success
    if (window_filled_ < (int)window_.size()) window_filled_++;
}

void CircuitBreaker::on_failure() {
    State s = state_.load(std::memory_order_acquire);
    if (s == State::HALF_OPEN) {
        // Probe failed → back to OPEN (reset timer)
        std::lock_guard<std::mutex> lock(mtx_);
        opened_at_ = std::chrono::steady_clock::now();
        transition_to(State::OPEN);
        return;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    if (window_idx_ >= window_.size()) window_idx_ = 0;
    window_[window_idx_++] = true;  // failure
    if (window_filled_ < (int)window_.size()) window_filled_++;
    if (current_failure_count() >= cfg_.failure_threshold) {
        opened_at_ = std::chrono::steady_clock::now();
        transition_to(State::OPEN);
    }
}

void CircuitBreaker::trip() {
    // T4.8.22 BUGFIX: previous trip() only set state=OPEN + reset timer,
    // but did NOT increment trips_total_ if called when state was not
    // CLOSED (HALF_OPEN→OPEN bypassed the counter), and did NOT mark
    // the failure window. This made trip() inconsistent with on_failure().
    //
    // Fix: behave exactly like on_failure() except we force OPEN
    // unconditionally. This guarantees trips_total_ is always
    // incremented on a fresh CLOSED→OPEN transition.
    State s = state_.load(std::memory_order_acquire);
    if (s == State::OPEN) return;  // already open — no-op
    std::lock_guard<std::mutex> lock(mtx_);
    // Mark one synthetic failure in the window so failure_threshold
    // accounting stays consistent (a manual trip should not appear to
    // have zero failures).
    if (window_idx_ >= window_.size()) window_idx_ = 0;
    window_[window_idx_++] = true;  // synthetic failure
    if (window_filled_ < (int)window_.size()) window_filled_++;
    opened_at_ = std::chrono::steady_clock::now();
    transition_to(State::OPEN);
}

int CircuitBreaker::current_failure_count() const {
    int n = 0;
    for (int i = 0; i < window_filled_; ++i) {
        if (window_[i]) n++;
    }
    return n;
}

void CircuitBreaker::transition_to(State new_state) {
    State old = state_.load(std::memory_order_relaxed);
    if (old == new_state) return;
    state_.store(new_state, std::memory_order_release);
    if (old == State::CLOSED && new_state == State::OPEN) {
        trips_total_.fetch_add(1, std::memory_order_relaxed);
    }
    std::fprintf(stderr, "[CircuitBreaker] %s → %s (failures=%d/%d)\n",
                 state_name(old), state_name(new_state),
                 current_failure_count(), cfg_.failure_threshold);
    persist_state();
}

void CircuitBreaker::persist_state() {
    if (cfg_.state_file.empty()) return;
    // Atomic write: tmp file → rename
    std::string tmp = cfg_.state_file + ".tmp";
    std::ofstream out(tmp);
    if (!out) {
        std::fprintf(stderr, "[CircuitBreaker] persist: cannot open %s\n", tmp.c_str());
        return;
    }
    State s = state_.load(std::memory_order_relaxed);
    uint64_t trips = trips_total_.load(std::memory_order_relaxed);
    out << "{\"state\":\"" << state_name(s) << "\",\"trips\":" << trips << "}\n";
    out.close();
    if (std::rename(tmp.c_str(), cfg_.state_file.c_str()) != 0) {
        std::fprintf(stderr, "[CircuitBreaker] persist: rename failed: %s\n",
                     std::strerror(errno));
    }
}

void CircuitBreaker::load_state() {
    if (cfg_.state_file.empty()) return;
    std::ifstream in(cfg_.state_file);
    if (!in) {
        // No state file → CLOSED (safe default)
        return;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string body = ss.str();
    // T4.8.16 (PHASE 2 hotfix v2): unconditionally start CLOSED at boot.
    //
    // Previous logic restored a persisted OPEN, which could deadlock the
    // agent if the previous run died before the recovery timer could
    // trigger. Reasoning: the FdResolver worker only calls allow() when
    // there is work to do. While the CB is OPEN, no work flows. So
    // allow() is never called → the recovery timer never fires. The
    // only safe state at boot is CLOSED.
    //
    // We still restore the trips counter (for metrics) but reset the
    // state and the failure window. If /proc is genuinely broken, the
    // CB will re-trip within seconds based on fresh failures.
    //
    // The mtime stale check from t4.8.15 is gone: it was unreliable
    // because persist_state() rewrites the file on every transition,
    // so a persisted OPEN always looks "fresh" by mtime.
    // T4.8.22 BUGFIX: the previous code did
    //   uint64_t t = std::stoull(body.substr(pos + 8));
    // which is fragile: it depends on the exact 8-character prefix
    // "\"trips\":" and will throw if the format changes (extra space,
    // trailing characters, etc). The catch (...) swallowed the error
    // silently. New code parses the integer at the position, stopping
    // at the first non-digit, and bounds-checks the result.
    auto pos = body.find("\"trips\":");
    if (pos != std::string::npos) {
        pos += 8;  // skip past the prefix
        // Skip optional whitespace
        while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) {
            ++pos;
        }
        // Find the end of the integer
        auto end = pos;
        while (end < body.size() && body[end] >= '0' && body[end] <= '9') {
            ++end;
        }
        if (end > pos) {
            try {
                uint64_t t = std::stoull(body.substr(pos, end - pos));
                trips_total_.store(t, std::memory_order_relaxed);
                std::fprintf(stderr,
                    "[CircuitBreaker] boot: starting CLOSED, restored trips=%llu from %s\n",
                    (unsigned long long)t, cfg_.state_file.c_str());
            } catch (...) {
                // best-effort: leave trips_total_ at 0
            }
        }
    }
    // No transition_to() here → state stays at the constructor's default
    // (CLOSED) and persist_state() will rewrite the file on the next
    // transition with the current state.
}

}  // namespace logsoc::agent::cb
