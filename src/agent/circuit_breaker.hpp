// circuit_breaker.hpp — T4.8.4 — Anti-stampede circuit breaker
//
// Thread-safe circuit breaker with 3 states: CLOSED → OPEN → HALF_OPEN.
// Sliding window of calls, threshold-based failure detection, automatic
// recovery. State persisted to disk on every transition (atomic rename)
// for crash-resilience.
//
// V4.8 usage: gates FdResolver calls. If /proc/<pid>/fd lookups fail
// repeatedly (timeout, eperm), the CB opens and the resolver skips
// the readlink, publishing with resolution='cb_open'.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace logsoc::agent::cb {

enum class State : int {
    CLOSED = 0,     // normal operation, all calls allowed
    OPEN = 1,       // tripped, all calls rejected
    HALF_OPEN = 2,  // testing recovery, 1 call allowed
};

const char* state_name(State s);

struct Config {
    int window_size = 100;            // last N calls considered
    // T4.8.18: increased default from 5 to 50. See fd_resolver.hpp for
    // the rationale (production workload on Hestia has high fd churn).
    int failure_threshold = 50;        // failures in window to trip
    std::chrono::milliseconds open_duration{60000};  // 60s OPEN
    // Persistence
    std::string state_file;           // e.g. /var/lib/logsoc-agent/fim_state.json
};

class CircuitBreaker {
public:
    explicit CircuitBreaker(const Config& cfg);

    // Returns true if the call is allowed (CLOSED or HALF_OPEN).
    // Returns false if OPEN.
    bool allow();

    // Report a successful call. Resets failure counter if HALF_OPEN.
    void on_success();

    // Report a failed call. Counts toward threshold; may trip.
    void on_failure();

    // Force OPEN (admin override).
    void trip();

    // Read current state (atomic).
    State state() const {
        return state_.load(std::memory_order_acquire);
    }

    // Metrics: number of times the CB has tripped (CLOSED→OPEN transitions).
    uint64_t trips_total() const {
        return trips_total_.load(std::memory_order_relaxed);
    }

    // Persist current state to disk (atomic via rename). Called on every
    // transition. Best-effort: errors are logged but not fatal.
    void persist_state();

    // Load state from disk on startup. If file is missing or corrupt,
    // returns CLOSED (safe default) and logs a warning.
    void load_state();

private:
    Config cfg_;
    std::atomic<State> state_{State::CLOSED};
    std::atomic<uint64_t> trips_total_{0};
    // Sliding window: ring buffer of {success, failure}
    std::vector<bool> window_;  // true = failure, false = success
    size_t window_idx_ = 0;
    int window_filled_ = 0;     // 0..window_size
    std::chrono::steady_clock::time_point opened_at_{};
    mutable std::mutex mtx_;

    void transition_to(State new_state);
    int current_failure_count() const;
};

}  // namespace logsoc::agent::cb
