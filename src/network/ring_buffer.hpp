#pragma once
/**
 * network/ring_buffer.hpp — Lock-free SPSC ring buffer
 */
#include <cstdint>
#include <atomic>
#include <string>

namespace logsoc {

typedef struct {
    uint64_t timestamp_us;
    char     src_ip[46];
    char     dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint16_t payload_len_frame;
    uint16_t payload_preview_len;
    uint8_t  payload_preview[256];
    char     payload_hash[65];
    char     iface[16];
    uint8_t  tcp_flags;
} ring_event_t;

class RingBuffer {
public:
    static constexpr size_t SIZE = 4096;
    static_assert((SIZE & (SIZE - 1)) == 0, "SIZE must be power of 2");

private:
    ring_event_t events_[SIZE];
    std::atomic<size_t> write_idx_{0};
    std::atomic<size_t> read_idx_{0};
    // T4.8.22: explicit dropped counter for observability. The previous
    // push() returned false silently when full — now we also count drops
    // so the operator can detect backpressure. The counter is a
    // best-effort atomic, exact count is not required for observability.
    std::atomic<uint64_t> dropped_{0};

public:
    bool push(const ring_event_t& ev) {
        size_t wr = write_idx_.load(std::memory_order_relaxed);
        size_t rd = read_idx_.load(std::memory_order_acquire);
        if ((wr - rd) >= SIZE) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        events_[wr & (SIZE - 1)] = ev;
        write_idx_.store(wr + 1, std::memory_order_release);
        return true;
    }
    bool pop(ring_event_t& out) {
        size_t rd = read_idx_.load(std::memory_order_relaxed);
        size_t wr = write_idx_.load(std::memory_order_acquire);
        if (rd >= wr) return false;
        out = events_[rd & (SIZE - 1)];
        read_idx_.store(rd + 1, std::memory_order_release);
        return true;
    }
    size_t count() const {
        size_t wr = write_idx_.load(std::memory_order_relaxed);
        size_t rd = read_idx_.load(std::memory_order_relaxed);
        return wr > rd ? wr - rd : 0;
    }
    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
};

} // namespace logsoc
