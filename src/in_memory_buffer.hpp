#pragma once
// in_memory_buffer.hpp — Thread-safe ring buffer for LogSOC Agent v3.8.0
//
// Normal path: collectors → InMemoryBuffer → Sender → API
// Fallback path (API down): Sender → FallbackWAL (encrypted disk)
//
// InMemoryBuffer<T> is a bounded ring buffer with blocking push and
// non-blocking pop.  Specialised for std::string (raw event JSON).

#include <mutex>
#include <condition_variable>
#include <deque>
#include <optional>
#include <chrono>
#include <atomic>
#include <string>
#include <vector>      // T14.0 — H-03: needed for pop_batch() return type
#include <algorithm>   // T14.0 — H-03: needed for std::min in pop_batch()

template<typename T>
class InMemoryBuffer {
public:
    explicit InMemoryBuffer(size_t capacity = 10000)
        : capacity_(capacity), dropped_total_(0) {}

    // Blocking push with timeout. Returns false if timed out.
    bool push(const T& item, int timeout_ms = 5000) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (buf_.size() >= capacity_) {
            // Wait for space or timeout
            auto ok = not_full_.wait_for(lock,
                std::chrono::milliseconds(timeout_ms),
                [this] { return buf_.size() < capacity_ || !running_; });
            if (!ok || buf_.size() >= capacity_) return false;
        }
        buf_.push_back(item);
        not_empty_.notify_one();
        return true;
    }

    // Non-blocking push: if full, drop oldest and push (force).
    // Returns true if an item was dropped.
    bool drop_oldest_if_full(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool dropped = false;
        if (buf_.size() >= capacity_) {
            buf_.pop_front();
            ++dropped_total_;
            dropped = true;
        }
        buf_.push_back(item);
        not_empty_.notify_one();
        return dropped;
    }

    // T4.8.27.15 / 27C.1.6: Force push for critical security events.
    // Bypasses the capacity cap (deque grows dynamically) and never drops
    // the incoming event. Used for events that must NEVER be lost
    // (modload, execve, unlink, ptrace, bpf, accept, vfs_open).
    // Returns true if the buffer was over capacity (i.e. a soft cap breach).
    //
    // T12.14 (audit Nova H-11): an unbounded force_push() lets a fork
    // bomb (or any attacker spamming execve) OOM the agent, since
    // critical events are by design never dropped. We add a HARD cap
    // at 10x the soft capacity. Above the hard cap we drop the event
    // (better than dying) and increment a counter so the central
    // / heartbeat sees the breach. The hard cap is checked INSIDE
    // the lock so concurrent force_push callers can't race past it.
    bool force_push(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool over_cap_soft = buf_.size() >= capacity_;
        const size_t hard_cap = capacity_ * 10;
        if (buf_.size() >= hard_cap) {
            // Hard cap reached: drop the event, count it. We never
            // drop a critical event under normal load — reaching
            // hard_cap means we're under sustained attack or the
            // sender is wedged.
            force_push_hard_drops_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        buf_.push_back(item);
        not_empty_.notify_one();
        return over_cap_soft;
    }
    std::atomic<uint64_t> force_push_hard_drops_{0};

    // Non-blocking pop. Returns empty optional if buffer is empty.
    std::optional<T> pop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (buf_.empty()) return std::nullopt;
        T item = std::move(buf_.front());
        buf_.pop_front();
        not_full_.notify_one();
        return item;
    }

    // T14.0 — H-03 sender batcher POC: drain up to `max` events in a
    // SINGLE lock+unlock cycle, instead of calling pop() in a while loop
    // (which acquires the mutex once per event and serializes concurrent
    // senders/poppers under high load). The old code worked correctly but
    // was throughput-capped at ~1 event per mutex-acquire window. The new
    // API is symmetric with FallbackWAL::pop_batch (which already drained
    // N events in 1 syscall) — closing that asymmetry was the H-03 fix.
    //
    // Non-blocking: returns whatever is available right now (could be 0).
    // Caller's contract: pass a small `max` (e.g. batch_max_lines) to bound
    // the size of the returned vector.
    std::vector<T> pop_batch(size_t max) {
        std::vector<T> out;
        if (max == 0) return out;
        std::lock_guard<std::mutex> lock(mutex_);
        size_t n = std::min(max, buf_.size());
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            out.push_back(std::move(buf_.front()));
            buf_.pop_front();
        }
        if (n > 0) not_full_.notify_all();
        return out;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return buf_.size();
    }

    size_t capacity() const { return capacity_; }

    uint64_t dropped_total() const { return dropped_total_.load(); }

    void stop() {
        running_ = false;
        not_full_.notify_all();
        not_empty_.notify_all();
    }

private:
    std::deque<T> buf_;
    size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
    std::atomic<bool> running_{true};
    std::atomic<uint64_t> dropped_total_{0};
};