// t13_4_xdp_loader.hpp — T13.4 FINAL: public API for the in-kernel
// SYN scan detection (XDP-based).
//
// Functions exported from src/ebpf/t13_4_xdp_loader.cpp:
//   t13_4_xdp_init(): load and attach the embedded XDP program
//   t13_4_xdp_poll(): consume ring buffer events (call periodically)
//   t13_4_xdp_get_counters(): read protocol-level packet counters
//   t13_4_xdp_stop(): detach and unload
//
// Architecture: secondary observability program. Runs in parallel
// with the existing skel_soc FIM/execve/unlinkat probes. It does
// NOT replace pcap_collector — that refactor is T13.4'.
#pragma once
#include <cstdint>
#include <string>

namespace ebpf {

// Initialize. ifname = the interface to attach XDP to (typically
// "eth0" or "ens3" — NOT lo, XDP doesn't see loopback).
// scan_event_cb = called on every SCAN_DETECTED event from the kernel.
//
// Both args are required. Returns true on success.
bool t13_4_xdp_init(const std::string& ifname,
                    void (*scan_event_cb)(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t dst_port, uint64_t syn_count));

// Poll ring buffer for new scan events. Returns number consumed.
// Should be called every 100-500ms from the agent's main event loop.
int t13_4_xdp_poll(int timeout_ms = 100);

// Read per-protocol packet counters. Returns false if not initialized.
bool t13_4_xdp_get_counters(uint64_t* out_tcp, uint64_t* out_udp,
                            uint64_t* out_icmp, uint64_t* out_other);

// Stop + detach. Safe to call from a signal handler context.
void t13_4_xdp_stop();

} // namespace ebpf
