/* loader.hpp — Static C++ BPF loader header */
#ifndef __EBPF_LOADER_H__
#define __EBPF_LOADER_H__

#include <cstddef>
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>

namespace ebpf {

// Return true if kernel >= 5.8 and bpf syscall is available.
bool kernel_ok();

// Return "ok" or reason string.
const char* kernel_reason();

// Load 6 BPF programs and create ringbuf + maps.
bool init();

// Stop and cleanup all BPF fds.
void stop();

// Poll the ringbuf into buf (up to len bytes).
int poll(char* buf, size_t len);

// Return ringbuf map fd for select/poll, or -1 if not ready.
int get_fd();

// --- Configuration (set before or after init) ---
void set_rate_limit(uint32_t events_per_sec);
void set_filter_connect_ports(const std::vector<std::string> &ports);
void set_filter_execve_comm(const std::vector<std::string> &comms);
void set_filter_open_paths(const std::vector<std::string> &paths);
void set_filter_unlink_paths(const std::vector<std::string> &paths);
void set_filter_ignore_rdonly(bool yes);
void set_filter_connect_ips(const std::vector<std::string> &ips);
void set_redact_patterns(const std::vector<std::string> &patterns);

// --- Enabled probes (set BEFORE init): map probe_name→enabled ---
// Valid probe names: "write", "execve", "tcp_connect", "fim", "open", "unlink"
void set_enabled_probes(const std::unordered_map<std::string, bool> &probes);

// T13.8 A-17: check if eBPF has been successfully initialized.
// Returns false before init() succeeds or after stop() is called.
// Used by apply_config_update() to guard rebuild_ebpf_probes() calls.
bool is_initialized();

// T30.3: rebuild eBPF links to reflect the current enabled_probes map.
// Hot-reloadable: destroys existing bpf_link objects and reattaches
// only the enabled ones. Safe to call after init(). The ringbuf is
// preserved (same map, just the link objects are recreated). Returns
// the number of links successfully attached, or -1 on fatal error.
int rebuild_ebpf_probes();

// --- Stats ---
uint64_t get_drop_stats();

// T30.2: ringbuf loss tracking. Returns the cumulative count of
// events produced by the kernel that were never consumed (overwritten
// in the ring buffer because the drain rate was too slow). The
// counter starts at 0 after init() and is monotonic until stop().
uint64_t get_ringbuf_lost_events();

// T30.2: total events consumed from the ringbuf since boot.
// Useful as a denominator when computing loss rate (% lost = lost/total).
uint64_t get_ringbuf_total_events();

} // namespace ebpf

#endif
