// t13_4_xdp.bpf.c — T13.4 FINAL: XDP program with SYN scan detection
// and ring buffer alerts.
//
// Evolution from the T13.4 POC:
//   - Added BPF_MAP_TYPE_LRU_HASH for per-source-IP SYN counters
//   - Added BPF_MAP_TYPE_RINGBUF for emitting alert events to userspace
//   - TCP SYN (without ACK) increments src_ip counter; if > threshold
//     within a 10s window, emit a SCAN_DETECTED event
//   - Per-CPU pkt_counters still incremented for total protocol stats
//
// This is the COMPLETE T13.4 kernel-side. It compiles to a single
// .bpf.o and gets loaded by the userspace loader (t13_4_xdp_loader.cpp).
//
// The 10s scan window is implemented in the userspace loader (it
// periodically clears the SYN counter map). This is a KISS approach
// for a POC — production would use a BPF timer (BPF_PROG_ATTACH_TYPE
// for timers, kernel 5.15+) or a sliding window map.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Total packet counts per protocol (per-CPU for perf).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key,   __u32);
    __type(value, __u64);
} pkt_counters SEC(".maps");

// SYN count per source IPv4. LRU_HASH auto-evicts old entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);  // src IPv4 (network byte order)
    __type(value, __u64);  // SYN count
} syn_per_src SEC(".maps");

// Ring buffer for emitting events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} alerts SEC(".maps");

// Alert event structure emitted to userspace.
struct alert_event {
    __u32 src_ip;        // network byte order
    __u32 dst_ip;        // network byte order
    __u16 dst_port;      // host byte order
    __u16 pad;
    __u64 syn_count;     // # of SYNs seen from this src in the window
    __u64 timestamp_ns;  // bpf_ktime_get_ns() at detection time
};

#define SCAN_THRESHOLD 50  // >50 SYNs from one src = potential scan

SEC("xdp")
int xdp_scan_detect(struct xdp_md* ctx) {
    void* data     = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // Bounds check the Ethernet header
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    // Only count IPv4
    if (eth->h_proto != 0x0800) return XDP_PASS;

    // Bounds check the IP header
    struct iphdr* ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    // Update total protocol counters
    __u32 idx;
    switch (ip->protocol) {
        case IPPROTO_TCP:  idx = 0; break;
        case IPPROTO_UDP:  idx = 1; break;
        case IPPROTO_ICMP: idx = 2; break;
        default:           idx = 3; break;
    }
    __u64* counter = bpf_map_lookup_elem(&pkt_counters, &idx);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }

    // Only TCP from here on
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // Bounds check the TCP header
    // ihl is in 32-bit words, so ip header length = ihl * 4
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20) return XDP_PASS;  // malformed
    struct tcphdr* tcp = (void*)((__u8*)ip + ip_hdr_len);
    if ((void*)(tcp + 1) > data_end) return XDP_PASS;

    // Check for SYN (SYN=1, ACK=0)
    // tcp->syn is at bit 1 of tcp->fin..syn bits. We can't access
    // bitfields in BPF reliably, so we use the byte representation.
    // TCP header byte 13 (0-indexed) has the flags:
    //   bit 0: FIN, bit 1: SYN, bit 2: RST, bit 3: PSH,
    //   bit 4: ACK, bit 5: URG, bit 6: ECE, bit 7: CWR
    // We need SYN set and ACK clear. Access the flag byte at offset 13.
    __u8* tcp_flags = (__u8*)tcp + 13;
    if ((void*)(tcp_flags + 1) > data_end) return XDP_PASS;
    __u8 flags = *tcp_flags;
    bool is_syn = (flags & 0x02) && !(flags & 0x10);  // SYN && !ACK

    if (!is_syn) return XDP_PASS;

    // Increment per-src SYN counter
    __u32 src_ip = ip->saddr;  // network byte order
    __u64* syn_count = bpf_map_lookup_elem(&syn_per_src, &src_ip);
    if (!syn_count) {
        __u64 one = 1;
        bpf_map_update_elem(&syn_per_src, &src_ip, &one, BPF_ANY);
    } else {
        __sync_fetch_and_add(syn_count, 1);
    }

    // Check threshold
    __u64 count = syn_count ? *syn_count : 1;
    if (count >= SCAN_THRESHOLD) {
        // Emit a ring buffer event
        struct alert_event* e = bpf_ringbuf_reserve(&alerts, sizeof(*e), 0);
        if (e) {
            e->src_ip      = src_ip;
            e->dst_ip      = ip->daddr;
            e->dst_port    = tcp->dest;  // host byte order in TCP header
            e->pad         = 0;
            e->syn_count   = count;
            e->timestamp_ns = bpf_ktime_get_ns();
            bpf_ringbuf_submit(e, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
