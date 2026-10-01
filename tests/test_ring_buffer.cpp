// tests/test_ring_buffer.cpp — T4.8.9
// Unit tests for the lock-free SPSC ring buffer used by NetworkCollector.
// Coverage:
//   1. push/pop single element
//   2. push/pop until full, then full
//   3. pop on empty returns false
//   4. FIFO ordering
//   5. dropped counter increments on full
//   6. wrap-around (SIZE power of 2, test with >SIZE pushes/pops)
//   7. concurrent stress (1 producer + 1 consumer, no data loss)

#include "../src/network/ring_buffer.hpp"
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>
#include <atomic>

using namespace logsoc;

static int total_passed = 0;
static int total_failed = 0;

#define OK(cond) do { \
    if (cond) { ++total_passed; printf("  ok: %s\n", #cond); } \
    else      { ++total_failed; printf("  FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while(0)

static ring_event_t make_event(uint32_t magic) {
    ring_event_t e{};
    e.timestamp_us = 1000ULL * magic;
    e.src_port = 1000 + magic;
    e.dst_port = 80;
    e.proto = 6;
    e.payload_len_frame = 100;
    e.payload_preview_len = 16;
    for (int i = 0; i < 16; ++i) e.payload_preview[i] = (uint8_t)(magic + i);
    snprintf(e.src_ip, sizeof(e.src_ip), "10.0.0.%d", magic & 0xFF);
    snprintf(e.dst_ip, sizeof(e.dst_ip), "10.0.0.%d", (magic+1) & 0xFF);
    return e;
}

int main() {
    printf("=== RingBuffer SPSC tests (T4.8.9) ===\n");

    // 1. push/pop single
    {
        RingBuffer rb;
        ring_event_t e = make_event(1);
        OK(rb.push(e) == true);
        ring_event_t out;
        OK(rb.pop(out) == true);
        OK(out.src_port == 1001);
        OK(out.payload_preview[0] == 1);
        OK(out.payload_preview[15] == 16);
        OK(rb.count() == 0);
    }

    // 2. pop on empty returns false
    {
        RingBuffer rb;
        ring_event_t out;
        OK(rb.pop(out) == false);
        OK(rb.count() == 0);
    }

    // 3. fill to SIZE then next push drops
    {
        RingBuffer rb;
        size_t pushed = 0;
        for (size_t i = 0; i < RingBuffer::SIZE; ++i) {
            if (rb.push(make_event((uint32_t)i))) ++pushed;
        }
        OK(pushed == RingBuffer::SIZE);
        OK(rb.count() == RingBuffer::SIZE);
        OK(rb.dropped() == 0);  // not dropped yet, just full

        // Next push must drop
        ring_event_t overflow = make_event(99999);
        OK(rb.push(overflow) == false);
        OK(rb.dropped() == 1);
    }

    // 4. FIFO order
    {
        RingBuffer rb;
        for (int i = 0; i < 100; ++i) {
            OK(rb.push(make_event((uint32_t)i)));
        }
        for (int i = 0; i < 100; ++i) {
            ring_event_t out;
            OK(rb.pop(out));
            OK(out.src_port == (uint16_t)(1000 + i));
        }
    }

    // 5. wrap-around (push 2*SIZE, drain in order)
    {
        RingBuffer rb;
        const size_t N = RingBuffer::SIZE * 2 + 17;
        for (size_t i = 0; i < N; ++i) {
            rb.push(make_event((uint32_t)(i & 0xFFFF)));
        }
        // N events were pushed, but ring holds last SIZE
        // We pushed 2*SIZE+17, so after wrap, the last SIZE are in the ring
        // (the first SIZE+17 were dropped silently as we didn't check return)
        // We can pop exactly SIZE events:
        size_t popped = 0;
        ring_event_t out;
        while (rb.pop(out)) ++popped;
        OK(popped == RingBuffer::SIZE);
        // First popped should be the (N - SIZE)th event, i.e. event N-SIZE
        // We had dropped counter on overflow → check it
        OK(rb.dropped() == (N - RingBuffer::SIZE));
    }

    // 6. dropped counter
    {
        RingBuffer rb;
        for (size_t i = 0; i < RingBuffer::SIZE; ++i) rb.push(make_event((uint32_t)i));
        // Force 5 drops
        for (int i = 0; i < 5; ++i) rb.push(make_event(99));
        OK(rb.dropped() == 5);
    }

    // 7. concurrent SPSC stress test (1 producer + 1 consumer)
    {
        RingBuffer rb;
        const size_t N = 100000;
        std::atomic<bool> producer_done{false};
        std::atomic<size_t> received{0};
        std::atomic<size_t> mismatches{0};

        std::thread producer([&](){
            for (size_t i = 0; i < N; ++i) {
                while (!rb.push(make_event((uint32_t)(i & 0xFFFF)))) {
                    // ring full → busy-spin (real-world: flush_thread drains)
                    std::this_thread::yield();
                }
            }
            producer_done.store(true);
        });
        std::thread consumer([&](){
            size_t expected = 0;
            ring_event_t out;
            while (!producer_done.load() || rb.count() > 0) {
                if (rb.pop(out)) {
                    if (out.src_port != (uint16_t)(1000 + (expected & 0xFFFF))) {
                        mismatches.fetch_add(1);
                    }
                    ++expected;
                    received.fetch_add(1);
                } else {
                    std::this_thread::yield();
                }
            }
        });
        producer.join();
        consumer.join();
        OK(received.load() == N);  // no loss
        OK(mismatches.load() == 0);  // strict FIFO
        OK(rb.count() == 0);
    }

    // 8. size assertion (power of 2, required for mask)
    OK((RingBuffer::SIZE & (RingBuffer::SIZE - 1)) == 0);

    printf("=== %d passed, %d failed ===\n", total_passed, total_failed);
    return total_failed == 0 ? 0 : 1;
}
