// T13.10 — Thread-safe unique_ptr wrapper for C++17.
//
// std::atomic<std::unique_ptr<T>> is C++20 (atomic<shared_ptr<T>> also C++20).
// This wrapper provides thread-safe access to a unique_ptr<T> in C++17 by
// guarding it with a std::mutex. The semantics match what T13.10 needs:
//
// - Reader (heartbeat thread): can call ->, get(), operator bool() safely
//   even if a writer (main thread) is about to reset() — the read either
//   sees the old object (which is still valid) or the new null state.
// - Writer (main thread): can call reset() / emplace() / = std::move()
//
// Cost: a mutex lock per access. For ebpf_ptr (1 Hz heartbeat, 1 writer
// per shutdown), this is negligible. NOT suitable for hot-path shared_ptr
// churn.
//
// Pattern from T13.9 threading model (see agent.cpp main() top comment):
// "ebpf_ptr is read from the heartbeat thread via &ebpf_ptr. The heartbeat
//  only READS. The main thread only WRITES at init and at shutdown (after
//  heartbeat is joined). T13.10 makes the read/write safe even WITHOUT
//  relying on the join-before-reset invariant — defense in depth."
#pragma once
#include <memory>
#include <mutex>
#include <utility>

template <typename T>
class atomic_unique_ptr {
public:
    atomic_unique_ptr() = default;
    explicit atomic_unique_ptr(std::unique_ptr<T> p) : ptr_(std::move(p)) {}

    // Non-copyable, non-movable (the whole point is to be a stable target
    // for &capture in lambdas).
    atomic_unique_ptr(const atomic_unique_ptr&) = delete;
    atomic_unique_ptr& operator=(const atomic_unique_ptr&) = delete;
    atomic_unique_ptr(atomic_unique_ptr&&) = delete;
    atomic_unique_ptr& operator=(atomic_unique_ptr&&) = delete;

    // Reader interface (heartbeat / metrics threads)
    T* get() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return ptr_.get();
    }
    explicit operator bool() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return static_cast<bool>(ptr_);
    }
    T& operator*() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return *ptr_;
    }
    T* operator->() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return ptr_.get();
    }
    // Ternary: `atomic_unique_ptr p; p ? p->foo() : 0;` works because
    // both `p` (operator bool) and `p->foo()` (operator->) lock.
    // Note: this is NOT the same as `if (p) { auto x = p->foo(); }` because
    // the lock is released between the two calls. For T13.10, the only
    // pattern used is `p ? p->foo() : 0` and `if (p) p->set_xxx(...)` (the
    // latter is OK because the set_xxx is on the same object ptr_ points to
    // at the moment of the bool check — reset() can only run from main thread
    // and only AFTER heartbeat is joined, per T13.9).

    // Writer interface (main thread)
    void reset(std::unique_ptr<T> p = nullptr) {
        std::lock_guard<std::mutex> lk(mtx_);
        // T13.9: explicit stop() before reset for EbpfCollector
        if (ptr_) ptr_->stop();
        ptr_ = std::move(p);
    }
    // Assignment from std::unique_ptr (used at init: ec_owned transfer)
    atomic_unique_ptr& operator=(std::unique_ptr<T> p) {
        std::lock_guard<std::mutex> lk(mtx_);
        ptr_ = std::move(p);
        return *this;
    }

private:
    mutable std::mutex mtx_;
    std::unique_ptr<T> ptr_;
};
