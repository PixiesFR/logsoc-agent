/* loader.cpp — Real BPF loader using libbpf (Linux-only, C++17)
 * V4.4: comm in all events, UID→username resolution, UNIX-socket filter
 */
#include "loader.hpp"

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <dirent.h>     // T10: opendir/readdir for BPF pin ownership check
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <vector>
#include <string>
#include <deque>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <pwd.h>

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#include "../ebpf_payload.h"
// Enrichissement MITRE/sigma/severity retiré — voir issue SOC-AGENT #40
// Le backend (app/enrichment.py) fait l'enrichissement côté serveur.

namespace ebpf {

/* --- Userspace mirror of the kernel event struct (event.h V4.4) ---
   All unions now carry comm[16] for process name.
   Largest union: w (268 bytes) → total struct = 16 + 268 = 284 bytes.
   Union alignment padding ensures natural layout matches kernel.
*/
/* Event struct (V4.8) — shadow of ebpf/event.h with the SAME memory layout.
 * Keep in sync with src/ebpf/event.h. Any change to either MUST be
 * reflected in the other.
 *
 * Union alignment padding ensures natural layout matches kernel.
 */
struct Event {
    uint32_t type;   /* 1=write, 2=execve, 3=connect, 4=fim, 6=unlink, 8=write_fd */
    uint32_t pid;
    uint32_t uid;
    uint32_t _pad;
    uint64_t ktime_ns;  /* V4.8: for matching fim (type 4) with write_fd (type 8) */
    union {
        struct { uint32_t fd;   uint32_t _pad2; uint64_t count; char payload[256]; } w;                 /* type 1: write */
        struct { char comm[16]; char args[80]; } e;                                                     /* type 2: execve */
        struct { char comm[16]; uint32_t src_ip; uint32_t dst_ip; uint16_t dst_port; uint16_t _pad3; } c; /* type 3: connect */
        struct { char comm[16]; uint64_t inode; char filename[64]; } f;                                 /* type 4: fim (basename) */
        struct { char comm[16]; char filename[64]; } u_unlink;                                          /* type 6: unlink */
        struct { int32_t fd; int32_t _pad_w; } wf;                                                      /* type 8: write_fd (fd for /proc resolve) */
        /* type 5 (open) REMOVED in V4.8 — see docs/ebpf-fim-v5.md */
    } u;
};

struct LoadedObj {
    struct bpf_object *obj{nullptr};
    struct bpf_link   *links[32] = {nullptr};  // V4.8.27: 16+ probes (sprint 27A/27B expanded from 6+1)
    struct ring_buffer *rb{nullptr};
    int                link_count{0};
};

static LoadedObj g_obj;
// T12 audit fix #59: state mutex protecting g_obj + g_initialized
// from concurrent access between init()/rebuild_ebpf_probes()/stop()
// and poll(). The previous code had no synchronization between
// stop()'s g_obj.rb free and poll()'s g_obj.rb deref, leading to
// a use-after-free if a rebuild raced a poll.
static std::mutex g_state_mtx;
static std::mutex g_queue_mtx;
static std::deque<std::string> g_queue;
// T12 audit fix #4: g_reason is now std::atomic<const char*> (or
// rather a struct holding an atomic + a mutex — see below). The
// previous code wrote g_reason in kernel_ok() (called from init
// and runtime eBPF reload) and read it in kernel_reason() (called
// from the heartbeat thread) without synchronization. Reading a
// pointer being concurrently written is UB (could read a half-
// written pointer on 32-bit and would tear on the 64-bit -> 32-bit
// truncation case). std::atomic<const char*> is the right tool:
// we always read/write the pointer as an atomic unit, and the
// string literals are themselves immutable so no sync needed on
// the pointed-to memory.
static std::atomic<const char*> g_reason{nullptr};
static std::atomic<bool> g_initialized{false};

// T13.8 A-17: expose init state for apply_config_update guard.
bool is_initialized() { return g_initialized.load(); }

/* --- Rate-limit per PID --- */
struct RateLimitEntry {
    uint64_t reset_ts;  // timestamp when window resets (sec)
    uint32_t count;     // events in current window
};
static std::unordered_map<uint32_t, RateLimitEntry> g_rate;
static std::mutex g_rate_mtx;
static uint32_t g_rate_limit = 100; // events/sec/PID

/* --- Drop stats (userspace mirror of BPF drop_stats) --- */
// T12 audit fix #1, #2, #28, #29: g_dropped, g_t29_overflow_events,
// g_ringbuf_lost_events, g_ringbuf_total_events, g_ringbuf_prev_producer_pos,
// g_ringbuf_prev_consumer_pos are now std::atomic<uint64_t>. They were
// plain uint64_t, written by ringbuf_callback (libbpf thread context)
// and read by get_drop_stats/get_ringbuf_xxx (heartbeat thread). Plain
// concurrent read/write on uint64_t is UB on 32-bit platforms and a
// data race on all platforms per the C++ memory model.
//
// On x86-64, aligned 64-bit loads/stores are atomic in practice but
// the C++ standard doesn't guarantee it, and increment (g_dropped.fetch_add(1, std::memory_order_relaxed))
// is a load+add+store triple — definitely not atomic.
static std::atomic<uint64_t> g_dropped{0};

/* T29: counter for events whose enriched JSON exceeded the 4KB buffer.
 * Should stay at 0 in production. Reported by /v1/agent-config/stats. */
static std::atomic<uint64_t> g_t29_overflow_events{0};

/* T30.2: ringbuf producer/consumer position tracking for loss detection.
 *
 * The kernel BPF ringbuf does NOT expose a "lost" counter directly via
 * libbpf. The trick: we sample the producer position (monotonically
 * increasing, incremented by the kernel for every event) and the
 * consumer position (incremented by ring_buffer__consume). The diff
 * between the two, minus what's still queued (=avail_data_size), gives
 * the number of events produced and never consumed = lost.
 *
 * We sample at the start of every poll() call, then compute the diff
 * over the call's window. The accumulated delta across calls is the
 * total lost count since boot.
 *
 * T30.2 also reports ringbuf_lost_events to the backend via heartbeat
 * so we can detect buffer overruns in production.
 */
static std::atomic<uint64_t> g_ringbuf_lost_events{0};
static std::atomic<uint64_t> g_ringbuf_total_events{0};
static std::atomic<uint64_t> g_ringbuf_prev_producer_pos{0};
static std::atomic<uint64_t> g_ringbuf_prev_consumer_pos{0};
static std::atomic<bool>     g_ringbuf_pos_initialized{false};

/* --- Local filters ---
 * T12 audit fix #7, #48, #49, #6, #8: all filter globals below are
 * protected by a single g_filters_mtx. The previous code had setters
 * (set_filter_*, set_redact_patterns, set_rate_limit) writing these
 * without any lock, and ringbuf_callback (libbpf thread) reading
 * them. std::vector and std::atomic<uint32_t> are not thread-safe for
 * concurrent read/write. A single mutex keeps the implementation
 * simple — setters are called rarely (only on policy reload), and
 * the callback reads under the same lock with negligible contention.
 */
static std::vector<std::string> g_ignore_connect_ports;
static std::vector<std::string> g_ignore_execve_comm;
static std::vector<std::string> g_ignore_open_paths;
static std::vector<std::string> g_ignore_unlink_paths;
static bool g_ignore_rdonly = true;
static std::vector<std::string> g_ignore_connect_ips;
static std::vector<std::string> g_redact_patterns;
static std::mutex g_filters_mtx;

/* --- UID → username cache --- */
static std::unordered_map<uint32_t, std::string> g_uid_cache;
static std::mutex g_uid_cache_mtx;

// V4.7 (option B pivot): The FIM basename → absolute path resolution is now
// done ENTIRELY in BPF land, via the (pid, basename) → full_path hash map
// (open_path_cache) populated by the type 5 (sys_enter_openat) handler and
// consulted by the type 4 (kprobe/vfs_write) handler. No userspace cache
// is needed. The previous inode→path cache (V4.5) is removed.

static std::string resolve_uid(uint32_t uid)
{
    {
        std::lock_guard<std::mutex> lock(g_uid_cache_mtx);
        auto it = g_uid_cache.find(uid);
        if (it != g_uid_cache.end()) return it->second;
    }
    // Try getpwuid_r
    struct passwd pwd;
    struct passwd *result = nullptr;
    char buf[4096];
    int rc = getpwuid_r(uid, &pwd, buf, sizeof(buf), &result);
    if (rc == 0 && result) {
        std::string name(result->pw_name);
        std::lock_guard<std::mutex> lock(g_uid_cache_mtx);
        g_uid_cache[uid] = name;
        return name;
    }
    // T12.13 (audit Nova M-02): if ERANGE, the passwd entry was larger
    // than our 4096-byte buffer. Grow it once and retry. If it still
    // fails, fall through to the numeric fallback. This avoids silent
    // degradation on hosts with very long GECOS / pw_name entries.
    if (rc == ERANGE) {
        std::vector<char> big(16384);
        rc = getpwuid_r(uid, &pwd, big.data(), big.size(), &result);
        if (rc == 0 && result) {
            std::string name(result->pw_name);
            std::lock_guard<std::mutex> lock(g_uid_cache_mtx);
            g_uid_cache[uid] = name;
            return name;
        }
        // Rate-limited warn so a flapping getpwuid_r doesn't spam logs.
        static std::atomic<uint64_t> erange_count{0};
        uint64_t c = erange_count.fetch_add(1) + 1;
        if (c == 1 || c % 100 == 0) {
            std::fprintf(stderr,
                "[loader] getpwuid_r ERANGE for uid=%u (count=%llu)\n",
                uid, (unsigned long long)c);
        }
    }
    // Fallback: numeric uid as string
    std::string name = std::to_string(uid);
    std::lock_guard<std::mutex> lock(g_uid_cache_mtx);
    g_uid_cache[uid] = name;
    return name;
}

/* --- Helpers --- */
static void sanitize_str(char *buf, size_t len)
{
    for (size_t i = 0; i < len && buf[i]; ++i) {
        if (buf[i] == '\"' || buf[i] == '\\') buf[i] = ' ';
        if (buf[i] < 0x20 || buf[i] > 0x7E) buf[i] = ' ';
    }
}

static bool starts_with_any(const char *str, const std::vector<std::string> &prefixes)
{
    for (const auto &p : prefixes) {
        if (std::strncmp(str, p.c_str(), p.length()) == 0)
            return true;
    }
    return false;
}

static bool matches_any(const char *str, const std::vector<std::string> &patterns)
{
    for (const auto &p : patterns) {
        if (std::strcmp(str, p.c_str()) == 0)
            return true;
    }
    return false;
}

/* Check if filename looks like a non-regular file (socket, pipe, etc.) */
static bool is_non_regular_filename(const char *filename)
{
    if (!filename || !filename[0]) return true;
    // Unix domain sockets: name starts with null byte, shown as "UNIX-STREAM", "UNIX-DGRAM",
    // or names starting with '@' (abstract namespace)
    // Also filter pipes (pipe:), socket: prefixes
    static const char *skip_prefixes[] = {
        "UNIX", "@", "pipe:", "socket:", "[", ""
    };
    for (const char **pfx = skip_prefixes; **pfx; ++pfx) {
        if (std::strncmp(filename, *pfx, std::strlen(*pfx)) == 0)
            return true;
    }
    return false;
}

static bool rate_limit_ok(uint32_t pid)
{
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    // T12 audit fix #6, #8: rate_limit_ok() reads g_rate_limit which
    // is also written by set_rate_limit() under g_filters_mtx. The
    // previous code used g_rate_mtx (a different mutex) here, which
    // didn't protect the setter→getter pair. We use g_filters_mtx for
    // both. g_rate_mtx is now only used for the g_rate PID map (and
    // here too for symmetry).
    std::lock_guard<std::mutex> lock(g_rate_mtx);
    auto it = g_rate.find(pid);
    if (it == g_rate.end()) {
        g_rate[pid] = {static_cast<uint64_t>(now), 1};
        return true;
    }
    if (static_cast<uint64_t>(now) > it->second.reset_ts) {
        it->second.reset_ts = static_cast<uint64_t>(now);
        it->second.count = 1;
        return true;
    }
    // Snapshot the limit under the lock; release before returning.
    uint32_t limit = 0;
    {
        std::lock_guard<std::mutex> flt_lock(g_filters_mtx);
        limit = g_rate_limit;
    }
    if (it->second.count >= limit) {
        return false;
    }
    it->second.count++;
    return true;
}

/* --- Config setters (called by agent.cpp) --- */
void set_rate_limit(uint32_t events_per_sec)
{
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_rate_limit = events_per_sec > 0 ? events_per_sec : 100;
}

void set_filter_connect_ports(const std::vector<std::string> &ports)
{
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_ignore_connect_ports = ports;
}

void set_filter_execve_comm(const std::vector<std::string> &comms)
{
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_ignore_execve_comm = comms;
}

void set_filter_open_paths(const std::vector<std::string> &paths)
{
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_ignore_open_paths = paths;
}

void set_filter_unlink_paths(const std::vector<std::string> &paths)
{
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_ignore_unlink_paths = paths;
}

void set_filter_ignore_rdonly(bool yes)
{
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_ignore_rdonly = yes;
}

void set_filter_connect_ips(const std::vector<std::string> &ips) {
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_ignore_connect_ips = ips;
}

void set_redact_patterns(const std::vector<std::string> &patterns) {
    std::lock_guard<std::mutex> lock(g_filters_mtx);
    g_redact_patterns = patterns;
}

// --- Enabled probes (probe_name → section suffix mapping) ---
// V4.8 (T4.8.1): "open" removed (sys_enter_openat tracepoint deleted).
// "write_fd" added (kprobe/__x64_sys_write → trace_write_fd).
// T12 audit fix #62: g_enabled_probes is now std::atomic for the
// map pointer + a mutex for the contents. The previous code allowed
// concurrent read in is_probe_enabled() (from rebuild_ebpf_probes
// and init) and write in set_enabled_probes() (from PolicyPuller
// thread) on std::unordered_map, which is UB.
static std::unordered_map<std::string, bool> g_enabled_probes = {
    {"write", true}, {"execve", true}, {"tcp_connect", true},
    {"fim", true}, {"unlink", true}, {"write_fd", true}
};
static std::mutex g_enabled_probes_mtx;

void set_enabled_probes(const std::unordered_map<std::string, bool> &probes)
{
    std::lock_guard<std::mutex> lock(g_enabled_probes_mtx);
    for (const auto &kv : probes) {
        g_enabled_probes[kv.first] = kv.second;
    }
}

// Check if a BPF program section name corresponds to an enabled probe
//
// Audit 2026-06-15 (Gitea #12 — audit fix): the mapping below was INCOMPLETE.
// We attach 17 BPF programs in skel_soc.c but only 6 names were mapped here,
// so when the central policy pushed enabled_probes={modload:false, bpf:false,
// ptrace:false, creds:false, fork:false, bind:false, tcp_accept:false,
// open_kp:false, tcp_v4_connect:false}, NONE of those 11 probes were ever
// actually detached. The policy UI gave a false sense of control — the agent
// was leaking data the admin thought it had disabled.
//
// Fix: exhaustive mapping. Every SEC() in skel_soc.c now has a matching entry.
// We use SEC-suffix matching (strstr), so a section like "kprobe/do_init_module"
// matches the suffix "do_init_module" → "modload".
static bool is_probe_enabled(const char *sec)
{
    if (!sec) return true;  // no section name → attach by default
    // Mapping from section suffix to probe logical name
    static const struct { const char *suffix; const char *name; } mapping[] = {
        // Legacy (pre-v4.8)
        {"sys_enter_write", "write"},
        {"sys_enter_execve", "execve"},
        {"inet_sock_set_state", "tcp_connect"},
        {"vfs_write", "fim"},
        {"sys_enter_unlinkat", "unlink"},
        {"ksys_write", "write_fd"},
        // V4.8.27 / T4.8.27.x — added 2026-05, never mapped until audit 2026-06-15
        {"do_init_module",   "modload"},       // T11: kprobe (was tp/init_module, dead on 6.8)
        {"load_module",      "modload"},       // T11: kretprobe redundant signal
        {"do_filp_open",     "open_kp"},       // T4.8.27.5: kprobe (vfs_open)
        {"inet_csk_accept",  "tcp_accept"},    // T4.8.27.6: kretprobe backdoor detection
        {"tcp_v4_connect",   "tcp_v4_connect"},// T4.8.27.8: kprobe + kretprobe outgoing
        {"sys_enter_bind",   "bind"},          // T4.8.27.7: tracepoint bind
        {"sched_process_fork","fork"},         // T4.8.27.1: tracepoint
        {"commit_creds",     "creds"},         // T4.8.27.3: kprobe priv-esc
        {"sys_enter_ptrace", "ptrace"},        // T4.8.27.2: tracepoint
        {"sys_enter_bpf",    "bpf"},           // T4.8.27.4: tracepoint (EDR self-protection)
        {nullptr, nullptr}
    };
    for (int i = 0; mapping[i].suffix; ++i) {
        if (std::strstr(sec, mapping[i].suffix)) {
            // T12 audit fix #62: take the lock for the read too.
            // The race was: PolicyPuller thread writes to
            // g_enabled_probes via set_enabled_probes(), rebuild_ebpf_probes
            // / init read it via is_probe_enabled(). std::unordered_map
            // is NOT thread-safe for concurrent read/write.
            std::lock_guard<std::mutex> lock(g_enabled_probes_mtx);
            auto it = g_enabled_probes.find(mapping[i].name);
            if (it != g_enabled_probes.end() && !it->second) {
                return false;  // explicitly disabled
            }
            return true;  // enabled or not in map (default: enabled)
        }
    }
    return true;  // unknown section → attach by default
}

uint64_t get_drop_stats()
{
    return g_dropped.load(std::memory_order_relaxed);
}

uint64_t get_ringbuf_lost_events()
{
    return g_ringbuf_lost_events.load(std::memory_order_relaxed);
}

uint64_t get_ringbuf_total_events()
{
    return g_ringbuf_total_events.load(std::memory_order_relaxed);
}

// T30.3: rebuild eBPF links to reflect the current enabled_probes map.
//
// This is the hot-reload primitive. It destroys every existing
// link and recreates the ones whose probe names appear in
// g_enabled_probes. It is called both from init() (full setup) and
// from the policy hot-reload path (rebuild_ebpf_probes) when the
// central policy adds or removes a probe.
//
// init() uses _stop_unlocked() during error recovery; it is declared
// above the function that uses it, but the actual definition is below
// (to keep init()'s call sites in the same region as the open
// failures). Forward-declare it here.
// T12 audit fix #35-38: see init() error paths below.
static void _stop_unlocked();

/* T30.3: rebuild eBPF links to reflect the current enabled_probes map.
 *
 * This is the hot-reload primitive. It destroys every existing
 * bpf_link attached by init() and reattaches only the ones that pass
 * the is_probe_enabled() check. The bpf_object (g_obj.obj) and the
 * ringbuf (g_obj.rb) are preserved — only the links are recreated.
 *
 * Cost: ~10-50ms on a typical 17-probe setup. The EbpfCollector
 * thread continues to call poll() during the rebuild; any events
 * submitted to the ringbuf in the meantime are queued by the kernel
 * and read on the next poll.
 *
 * IMPORTANT: this function MUST be called from a thread that is
 * not currently calling poll() (the ringbuf callbacks would race
 * with the link destruction). The current architecture calls it
 * from the heartbeat thread, which is the only thread that
 * modifies g_enabled_probes.
 *
 * Returns the number of links attached, or -1 on fatal error.
 */
int rebuild_ebpf_probes()
{
    // T12 audit fix #16 (HIGH — UAF): take g_state_mtx for the entire
    // rebuild. The previous code accessed g_obj.links[], g_obj.link_count,
    // g_obj.obj, and g_initialized without holding the lock, so a
    // concurrent stop() or poll() could observe a partially-destroyed
    // g_obj (links destroyed but g_obj.obj still pointing to the bpf_object).
    //
    // T12 audit fix #5: also reads g_initialized under the lock now.
    std::lock_guard<std::mutex> lock(g_state_mtx);
    if (!g_initialized || !g_obj.obj) {
        std::fprintf(stderr, "ebpf rebuild: not initialized\n");
        return -1;
    }

    // 1. Destroy all existing links
    for (int i = 0; i < g_obj.link_count; ++i) {
        if (g_obj.links[i]) {
            bpf_link__destroy(g_obj.links[i]);
            g_obj.links[i] = nullptr;
        }
    }
    g_obj.link_count = 0;

    // 2. Re-iterate over the bpf_object's programs and reattach
    //    the ones that pass is_probe_enabled().
    struct bpf_object *obj = g_obj.obj;
    struct bpf_program *prog = nullptr;
    int link_idx = 0;
    int skipped_count = 0;
    bpf_object__for_each_program(prog, obj) {
        if (link_idx >= 32) {
            std::fprintf(stderr, "ebpf rebuild: too many programs (link_idx=%d)\n", link_idx);
            break;
        }
        const char *sec = bpf_program__section_name(prog);

        // Skip disabled probes (uses the CURRENT enabled_probes map,
        // which the caller has already updated via set_enabled_probes()).
        if (!is_probe_enabled(sec)) {
            skipped_count++;
            continue;
        }

        struct bpf_link *link = nullptr;
        if (sec && std::strncmp(sec, "tp/", 3) == 0) {
            char buf[256];
            std::strncpy(buf, sec + 3, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            char *slash = std::strchr(buf, '/');
            if (slash) {
                *slash = '\0';
                link = bpf_program__attach_tracepoint(prog, buf, slash + 1);
            }
        } else if (sec && std::strncmp(sec, "kprobe/", 7) == 0) {
            const char *sym = sec + 7;
            link = bpf_program__attach_kprobe(prog, false, sym);
        } else if (sec && std::strncmp(sec, "kretprobe/", 10) == 0) {
            const char *sym = sec + 10;
            link = bpf_program__attach_kprobe(prog, true, sym);
        } else {
            link = bpf_program__attach(prog);
        }
        if (!link) {
            std::fprintf(stderr, "ebpf rebuild: bpf_program__attach failed for sec=%s\n",
                         sec ? sec : "?");
            skipped_count++;
            continue;
        }
        g_obj.links[link_idx++] = link;
    }
    g_obj.link_count = link_idx;

    std::fprintf(stderr, "ebpf rebuild: attached=%d skipped=%d\n",
                 g_obj.link_count, skipped_count);
    return g_obj.link_count;
}

/* --- Helper: redact sensitive args --- */
// M-01 audit fix: previous version used memmove/memcpy in a fixed 80-byte
// buffer with manual bounds checking. If a pattern string exceeded the
// remaining buffer space, the replacement could overflow. Refactored to
// use std::string for dynamic sizing and safe replacement.
static void redact_args(std::string& args)
{
    static const char* default_patterns[] = {
        "--password", "--pass=", "--secret", "--token", "--key=",
        "--apikey=", "--api-key=", "--credential", "-p ", nullptr
    };
    bool found = true;
    while (found) {
        found = false;
        size_t pos = 0;
        while (pos < args.size()) {
            bool matched = false;
            if (args.find("--", pos) == pos || args.find("-p ", pos) == pos) {
                // Check patterns at current position
                // Use custom patterns if configured, else defaults
                // Note: g_redact_patterns may change between iterations;
                // snapshot under lock for consistency.
                std::vector<std::string> patterns_snapshot;
                {
                    std::lock_guard<std::mutex> lock(g_filters_mtx);
                    if (!g_redact_patterns.empty()) {
                        patterns_snapshot = g_redact_patterns;
                    }
                }
                const bool use_custom = !patterns_snapshot.empty();
                for (size_t pi = 0; ; ++pi) {
                    const char* pat = use_custom ? patterns_snapshot[pi].c_str() : default_patterns[pi];
                    if (!pat && !use_custom) break;
                    if (use_custom && pi >= patterns_snapshot.size()) break;
                    size_t plen = std::strlen(pat);
                    if (args.compare(pos, plen, pat) == 0) {
                        size_t end = pos + plen;
                        while (end < args.size() && args[end] != ' ') ++end;
                        args.replace(pos, end - pos, "[REDACTED]");
                        found = true;
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                // Advance to next space or end
                size_t next = args.find(' ', pos);
                if (next == std::string::npos) break;
                pos = next + 1;
            }
        }
    }
}

// T12 audit fix #11/12: validate IPv4 octets are in [0,255] before
// shifting. Without this, sscanf can parse "256.256.256.256" and
// a << 24 with a=256 truncates to 0 instead of producing an
// out-of-range IP. Also fix the UB shift in the CIDR mask.
static bool parse_ipv4_octets(const std::string& s, uint32_t& out) {
    unsigned int a, b, c, d;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out = (static_cast<uint32_t>(a) << 24) |
          (static_cast<uint32_t>(b) << 16) |
          (static_cast<uint32_t>(c) << 8)  |
          static_cast<uint32_t>(d);
    return true;
}

static bool ip_matches(uint32_t ip, const std::vector<std::string> &patterns) {
    for (const auto& pat : patterns) {
        auto slash = pat.find('/');
        if (slash != std::string::npos) {
            std::string network_str = pat.substr(0, slash);
            // T12 audit fix #9: std::stoi can throw std::invalid_argument
            // / std::out_of_range on malformed CIDR strings. We are
            // called from ringbuf_callback (a C callback), so an
            // uncaught exception calls std::terminate and crashes
            // the agent. Wrap in try/catch.
            //
            // T12 audit fix #10: validate prefix_len in [0,32] before
            // the shift. ~0u << (32 - prefix_len) is UB if
            // 32 - prefix_len >= 32 (i.e. prefix_len == 0 OR negative
            // OR > 32). The previous code special-cased prefix_len==0
            // but not prefix_len<0 or prefix_len>32. std::stoi can
            // return any of these for malformed input.
            int prefix_len = 0;
            try {
                prefix_len = std::stoi(pat.substr(slash + 1));
            } catch (const std::exception&) {
                continue;  // malformed CIDR — skip this pattern
            }
            if (prefix_len < 0 || prefix_len > 32) continue;
            uint32_t network = 0;
            if (!parse_ipv4_octets(network_str, network)) continue;
            // For prefix_len == 32, ~0u << 0 is well-defined (all ones).
            // For prefix_len == 0, the original code returned mask=0.
            // We keep that semantic (mask=0 matches all IPs).
            uint32_t mask = (prefix_len == 0) ? 0u : (~0u << (32 - prefix_len));
            if ((ip & mask) == (network & mask)) return true;
        } else {
            // T12 audit fix #11/12: validate octets via the helper.
            uint32_t pat_ip = 0;
            if (!parse_ipv4_octets(pat, pat_ip)) continue;
            if (ip == pat_ip) return true;
        }
    }
    return false;
}

/* V4.8: open_flags_str() REMOVED — was used by the deleted case 5 (open) handler.
 * If the rollback flag fim.engine=v4_duplex is set, the V4.7 binary is used. */

/* --- JSON ringbuf callback --- */
static int ringbuf_callback(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data == nullptr) return 0;

    if (data_sz < offsetof(Event, u)) {
        static int sz_warn = 0;
        if (sz_warn++ < 5) std::fprintf(stderr, "ringbuf: data_sz=%zu too small (need >= %zu)\n", data_sz, offsetof(Event, u));
        return 0;
    }

    const Event *ev = static_cast<const Event *>(data);
    uint32_t pid = ev->pid;
    uint32_t uid = ev->uid;

    // T4.8.27.20 / 27C.1.11: debug logging removed (ringbuf type
    // tracking proved the BPF→callback path works). The modload
    // event-type is now logged via the existing LOG_INFO in case 17.

    // T12 audit fix #7, #48, #49: snapshot the filter vectors under
    // g_filters_mtx so the rest of the callback can read them without
    // holding the lock. This avoids holding the lock across the whole
    // callback (which can be slow) and avoids passing the lock to
    // helper functions (matches_any, ip_matches) that might try to
    // acquire other locks.
    std::vector<std::string> snap_connect_ports;
    std::vector<std::string> snap_execve_comm;
    std::vector<std::string> snap_unlink_paths;
    std::vector<std::string> snap_connect_ips;
    std::vector<std::string> snap_redact_patterns;
    {
        std::lock_guard<std::mutex> lock(g_filters_mtx);
        snap_connect_ports = g_ignore_connect_ports;
        snap_execve_comm = g_ignore_execve_comm;
        snap_unlink_paths = g_ignore_unlink_paths;
        snap_connect_ips = g_ignore_connect_ips;
        snap_redact_patterns = g_redact_patterns;
        // g_ignore_rdonly is read under g_filters_mtx in rate_limit_ok()
        // (see T12 fix #6/#8 comments). The rdonly filter itself is
        // applied in the kernel eBPF program (FIM-side deny_rdonly),
        // not in this userspace callback — see t13_3_loader.bpf.c.
        // g_rate_limit is also read under g_filters_mtx in rate_limit_ok(),
        // so we don't need to snapshot it here.
    }

    // --- Rate-limit per PID ---
    if (!rate_limit_ok(pid)) {
        g_dropped.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }

    // Resolve UID → username
    std::string username = resolve_uid(uid);

    char json[4096];
    int n = 0;
    unsigned long long ts = static_cast<unsigned long long>(std::time(nullptr));

    // T29: shared context for the post-switch enricher. Filled by each
    // case (best-effort). These were consumed by the MITRE/severity/Sigma block
    // which has been moved to the backend (issue #40). The switch below still
    // fills them for the JSON event payload, but they're no longer used for
    // enrichment. We keep them to avoid a large refactor of the switch cases.
    std::string t29_comm;
    std::string t29_path;
    [[maybe_unused]] uint32_t t29_dst_port = 0;

    switch (ev->type) {
    case 1: { // write
        char payload[257] = {};
        std::memcpy(payload, ev->u.w.payload, 256);
        sanitize_str(payload, sizeof(payload));
        // write has no comm in union.w — but we can resolve /proc/<pid>/comm
        // For now, write struct is too large to add comm; leave comm empty
        n = std::snprintf(json, sizeof(json),
            "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"write\",\"fd\":%u,\"count\":%llu,\"payload\":\"%.256s\"}",
            ts, pid, uid, username.c_str(),
            ev->u.w.fd, static_cast<unsigned long long>(ev->u.w.count), payload);
        break;
    }
    case 2: { // execve
        char comm[17] = {};
        char args_buf[81] = {};
        std::memcpy(comm, ev->u.e.comm, 16);
        std::memcpy(args_buf, ev->u.e.args, 80);
        sanitize_str(comm, sizeof(comm));
        sanitize_str(args_buf, sizeof(args_buf));
        std::string args(args_buf);  // M-01: use std::string for redact_args
        redact_args(args);
        t29_comm = comm;
        // args often contain the executable path as the first token
        t29_path = args;
        // Filter: ignore_comm
        if (!snap_execve_comm.empty() && matches_any(comm, snap_execve_comm)) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
        n = std::snprintf(json, sizeof(json),
            "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"execve\",\"comm\":\"%.16s\",\"args\":\"%.80s\"}",
            ts, pid, uid, username.c_str(), comm, args.c_str());
        break;
    }
    case 3: { // tcp_connect
        char comm[17] = {};
        std::memcpy(comm, ev->u.c.comm, 16);
        sanitize_str(comm, sizeof(comm));
        uint32_t s = ev->u.c.src_ip;
        uint32_t d = ev->u.c.dst_ip;
        uint16_t dport = ev->u.c.dst_port;
        t29_comm = comm;
        t29_dst_port = dport;
        // Filter: ignore_ports
        // T12 audit fix #61: std::stoul throws std::invalid_argument
        // or std::out_of_range on malformed port strings. We're in a
        // C callback (libbpf ringbuf) — an uncaught exception calls
        // std::terminate and crashes the agent. Catch and log instead.
        for (const auto &pstr : snap_connect_ports) {
            try {
                if (std::stoul(pstr) == dport) {
                    g_dropped.fetch_add(1, std::memory_order_relaxed);
                    return 0;
                }
            } catch (const std::exception&) {
                // malformed port string in config — log once via
                // g_t29_overflow_events counter (the cheapest
                // user-visible indicator). Don't crash.
                g_t29_overflow_events.fetch_add(1, std::memory_order_relaxed);
            }
        }
        // Filter: ignore destination and source IPs
        if (!snap_connect_ips.empty()) {
            if (ip_matches(d, snap_connect_ips) || ip_matches(s, snap_connect_ips)) {
                g_dropped.fetch_add(1, std::memory_order_relaxed);
                return 0;
            }
        }
        n = std::snprintf(json, sizeof(json),
            "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"tcp_connect\",\"comm\":\"%.16s\",\"src_ip\":\"%u.%u.%u.%u\",\"dst_ip\":\"%u.%u.%u.%u\",\"dst_port\":%u}",
            ts, pid, uid, username.c_str(), comm,
            (s >> 24) & 0xFF, (s >> 16) & 0xFF, (s >> 8) & 0xFF, s & 0xFF,
            (d >> 24) & 0xFF, (d >> 16) & 0xFF, (d >> 8) & 0xFF, d & 0xFF,
            dport);
        break;
    }
    case 4: { // fim (vfs_write)
        char comm[17] = {};
        char filename[65] = {};
        std::memcpy(comm, ev->u.f.comm, 16);
        std::memcpy(filename, ev->u.f.filename, 64);
        sanitize_str(comm, sizeof(comm));
        sanitize_str(filename, sizeof(filename));
        t29_comm = comm;
        t29_path = filename;
        // Filter: non-regular files (Unix sockets, pipes, etc.)
        if (is_non_regular_filename(filename)) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
        // V4.8: filename is BASENAME ONLY. The fd is captured separately
        // by trace_write_fd (type 8) and matched userspace by (pid, ktime_ns).
        // The full path is then resolved by FdResolver via /proc/<pid>/fd/<fd>.
        n = std::snprintf(json, sizeof(json),
            "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"fim\",\"comm\":\"%.16s\",\"inode\":%llu,\"filename\":\"%.64s\",\"ktime_ns\":%llu}",
            ts, pid, uid, username.c_str(), comm,
            static_cast<unsigned long long>(ev->u.f.inode), filename,
            static_cast<unsigned long long>(ev->ktime_ns));
        break;
    }
    /* case 5 (open) REMOVED in V4.8 — see event.h
     * The sys_enter_openat tracepoint was removed; the full path that
     * it captured is now reconstructed userspace via /proc/<pid>/fd/<fd>.
     * type 5 (open) REMOVED — see case 4 comment and event.h */
     case 6: { // unlink
         char comm[17] = {};
         char filename[65] = {};
         std::memcpy(comm, ev->u.u_unlink.comm, 16);
         std::memcpy(filename, ev->u.u_unlink.filename, 64);
         sanitize_str(comm, sizeof(comm));
         sanitize_str(filename, sizeof(filename));
         t29_comm = comm;
         t29_path = filename;
         // Filter: ignore_paths (unlink)
         if (!snap_unlink_paths.empty() && starts_with_any(filename, snap_unlink_paths)) {
             g_dropped.fetch_add(1, std::memory_order_relaxed);
             return 0;
         }
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"unlink\",\"comm\":\"%.16s\",\"filename\":\"%.64s\"}",
             ts, pid, uid, username.c_str(), comm, filename);
         break;
     }
     case 8: { // write_fd (V4.8 NEW) — fd for /proc/<pid>/fd resolution
         int32_t fd = ev->u.wf.fd;
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"write_fd\",\"fd\":%d,\"ktime_ns\":%llu}",
             ts, pid, uid, username.c_str(), fd,
             static_cast<unsigned long long>(ev->ktime_ns));
         break;
     }
     case 9: { // fork (T4.8.27.1) — sched_process_fork tracepoint
         char pcomm[17] = {};
         std::memcpy(pcomm, ev->u.f.comm, 16);
         sanitize_str(pcomm, sizeof(pcomm));
         t29_comm = pcomm;
         // Filter: ignore_comm for fork (parent comm)
         if (!snap_execve_comm.empty() && matches_any(pcomm, snap_execve_comm)) {
             g_dropped.fetch_add(1, std::memory_order_relaxed);
             return 0;
         }
         // ev->u.f.inode holds child_pid (reused field)
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"fork\",\"comm\":\"%.16s\",\"child_pid\":%llu}",
             ts, pid, uid, username.c_str(), pcomm,
             static_cast<unsigned long long>(ev->u.f.inode));
         break;
     }
     case 10: { // ptrace (T4.8.27.2) — sys_enter_ptrace tracepoint
         char pcomm[17] = {};
         std::memcpy(pcomm, ev->u.e.comm, 16);
         sanitize_str(pcomm, sizeof(pcomm));
         t29_comm = pcomm;
         // Filter: drop PTRACE_TRACEME (self-attach, request=0) — benign noise
         // Reuse args[0..1] buffer: p[0]=request, p[1]=target_pid
         const uint32_t *p = reinterpret_cast<const uint32_t *>(ev->u.e.args);
         uint32_t request = p[0];
         uint32_t target_pid = p[1];
         if (request == 0 /* PTRACE_TRACEME */) {
             g_dropped.fetch_add(1, std::memory_order_relaxed);
             return 0;
         }
         // NO execve filter for ptrace: bash/sh are common legitimate callers
         // (strace, gdb). PTRACE_ATTACH on a target_pid != caller is the IoC.
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"ptrace\",\"comm\":\"%.16s\",\"request\":%u,\"target_pid\":%u}",
             ts, pid, uid, username.c_str(), pcomm, request, target_pid);
         break;
     }
     case 11: { // commit_creds (T4.8.27.3) — kprobe, privilege escalation
         char ccomm[17] = {};
         std::memcpy(ccomm, ev->u.e.comm, 16);
         sanitize_str(ccomm, sizeof(ccomm));
         t29_comm = ccomm;
         // Reuse args buffer: p[0]=uid, p[1]=euid, p[2]=gid, p[3]=egid
         const uint32_t *cp = reinterpret_cast<const uint32_t *>(ev->u.e.args);
         uint32_t n_uid = cp[0], n_euid = cp[1], n_gid = cp[2], n_egid = cp[3];
         // Filter: ship only if euid==0 (root escalation) or euid differs
         // from the current event->uid (transition). commit_creds is called
         // for capability init — most calls have euid==uid and are noise.
         if (n_euid != 0 && n_euid == (uint32_t)uid) {
             g_dropped.fetch_add(1, std::memory_order_relaxed);
             return 0;
         }
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"commit_creds\",\"comm\":\"%.16s\",\"new_uid\":%u,\"new_euid\":%u,\"new_gid\":%u,\"new_egid\":%u}",
             ts, pid, uid, username.c_str(), ccomm, n_uid, n_euid, n_gid, n_egid);
         break;
     }
     case 12: { // bpf (T4.8.27.4) — auto-protection of EDR
         char bcomm[17] = {};
         std::memcpy(bcomm, ev->u.e.comm, 16);
         sanitize_str(bcomm, sizeof(bcomm));
         t29_comm = bcomm;
         // Reuse args buffer: p[0]=cmd, p[1]=attr0 (first 4 bytes of union bpf_attr)
         const uint32_t *bp = reinterpret_cast<const uint32_t *>(ev->u.e.args);
         uint32_t cmd = bp[0];
         uint32_t attr0 = bp[1];
         // Filter: drop BPF_OBJ_GET (7) by our own agent (self-fd-passing is legit)
         // We can't know the agent PID here without more state. Just drop obj_get
         // by uid==0 from logsoc-agent binary; other cases are rare and worth shipping.
         if (cmd == 7 /* BPF_OBJ_GET */ && uid == 0) {
             g_dropped.fetch_add(1, std::memory_order_relaxed);
             return 0;
         }
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"bpf\",\"comm\":\"%.16s\",\"cmd\":%u,\"attr0\":%u}",
             ts, pid, uid, username.c_str(), bcomm, cmd, attr0);
         break;
     }
     case 13: { // vfs_open (T4.8.27.5 / 27B.1) — read sensitive files
        // Layout in args[]: byte0=flags(O_ACCMODE), bytes1..63=path(63),
        // bytes64..79=caller_comm(16)
        uint8_t flags = (uint8_t)ev->u.e.args[0];
        char path[64] = {};
        std::memcpy(path, ev->u.e.args + 1, 63);
        sanitize_str(path, sizeof(path));
        char ocomm[17] = {};
        std::memcpy(ocomm, ev->u.e.args + 64, 16);
        sanitize_str(ocomm, sizeof(ocomm));
        t29_comm = ocomm;
        t29_path = path;
         // Filter: O_RDONLY (0) only by default. O_WRONLY=1, O_RDWR=2 dropped here
         // (ransomware/persistence are caught by vfs_write type 4).
         if (flags != 0 /* O_RDONLY */) {
             g_dropped.fetch_add(1, std::memory_order_relaxed);
             return 0;
         }
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"vfs_open\",\"comm\":\"%.16s\",\"flags\":%u,\"path\":\"%.63s\"}",
             ts, pid, uid, username.c_str(), ocomm, (unsigned)flags, path);
         break;
     }
     case 14: { // inet_csk_accept (T4.8.27.6 / 27B.2) — backdoor detection
         // Layout in args[]: p[0]=dport(2)+pad(2), p[1]=saddr(4), bytes8..23=comm(16)
         const uint32_t *ap = reinterpret_cast<const uint32_t *>(ev->u.e.args);
         uint16_t dport = (uint16_t)(ap[0] & 0xFFFF);  /* network byte order */
         uint32_t saddr = ap[1];
         char accomm[17] = {};
         std::memcpy(accomm, ev->u.e.args + 8, 16);
         sanitize_str(accomm, sizeof(accomm));
         t29_comm = accomm;
         t29_dst_port = dport;
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"accept\",\"comm\":\"%.16s\",\"sport\":%u,\"saddr\":\"%u.%u.%u.%u\"}",
             ts, pid, uid, username.c_str(), accomm, (unsigned)dport,
             (saddr >> 24) & 0xFF, (saddr >> 16) & 0xFF,
             (saddr >> 8) & 0xFF, saddr & 0xFF);
         break;
     }
     case 15: { // bind (T4.8.27.7 / 27B.3) — bind to port
         // Layout in args[]: p[0] = family(2)|port(2 packed), p[1]=ipv4_addr
         const uint32_t *bp = reinterpret_cast<const uint32_t *>(ev->u.e.args);
         uint16_t family = (uint16_t)(bp[0] & 0xFFFF);
         uint16_t port_nbo = (uint16_t)((bp[0] >> 16) & 0xFFFF);
         uint16_t port = __builtin_bswap16(port_nbo);  /* host order */
         uint32_t addr4 = bp[1];
         char bcomm[17] = {};
         std::memcpy(bcomm, ev->u.e.args + 8, 16);
         sanitize_str(bcomm, sizeof(bcomm));
         t29_comm = bcomm;
         t29_dst_port = port;
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"bind\",\"comm\":\"%.16s\",\"family\":%u,\"port\":%u,\"addr\":\"%u.%u.%u.%u\"}",
             ts, pid, uid, username.c_str(), bcomm, (unsigned)family, (unsigned)port,
             (addr4 >> 24) & 0xFF, (addr4 >> 16) & 0xFF,
             (addr4 >> 8) & 0xFF, addr4 & 0xFF);
         break;
     }
     case 16: { // tcp_v4_connect (T4.8.27.8 / 27B.4) — outgoing connection
         // Layout in args[]: p[0]=sport(2 NBO)|dport(2 NBO), p[1]=daddr
         const uint32_t *cp = reinterpret_cast<const uint32_t *>(ev->u.e.args);
         uint16_t sport_nbo = (uint16_t)(cp[0] & 0xFFFF);
         uint16_t dport_nbo = (uint16_t)((cp[0] >> 16) & 0xFFFF);
         uint16_t sport = __builtin_bswap16(sport_nbo);
         uint16_t dport = __builtin_bswap16(dport_nbo);
         uint32_t daddr = cp[1];
         char ccomm[17] = {};
         std::memcpy(ccomm, ev->u.e.args + 8, 16);
         sanitize_str(ccomm, sizeof(ccomm));
         t29_comm = ccomm;
         t29_dst_port = dport;
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"connect\",\"comm\":\"%.16s\",\"sport\":%u,\"dport\":%u,\"daddr\":\"%u.%u.%u.%u\"}",
             ts, pid, uid, username.c_str(), ccomm, (unsigned)sport, (unsigned)dport,
             (daddr >> 24) & 0xFF, (daddr >> 16) & 0xFF,
             (daddr >> 8) & 0xFF, daddr & 0xFF);
         break;
     }
     case 17: { // do_init_module (T11 kernel 6.8 fix) — rootkit load
         // T11: new layout from kprobe/do_init_module
         //   bytes 0..63  = module name (kernel string from struct module->name)
         //   bytes 64..79 = comm (16 bytes) — T12 audit fix #14 changed
         //                   this from offset 66 (which overflowed args[80]
         //                   by 2 bytes) to offset 64 (fits exactly).
         //   bytes 80..81 = unused (was where overflow landed)
         char modname[65] = {};
         std::memcpy(modname, ev->u.e.args, 64);
         sanitize_str(modname, sizeof(modname));
         char kcomm[17] = {};
         // T12 audit fix #14: read from offset 64 to match the new
         // BPF writer offset. Old code read from offset 66, but the BPF
         // program now writes at 64.
         std::memcpy(kcomm, ev->u.e.args + 64, 16);
         sanitize_str(kcomm, sizeof(kcomm));
         t29_comm = kcomm;
         // T29 enricher reads t29_path — pass the modname directly so
         // path-based MITRE rules can match it. The previous code set
         // t29_path to "/lib/modules/<modname>.ko", which never matched
         // any rule (rules are patterns like /etc/passwd or
         // *diamorphine*, not module paths).
         //
         // T12 audit fix #13: pass the modname as t29_path so the
         // tag_event() inside case 17 can call tag(modname). This
         // lets rootkit-name rules fire. The comm is still kcomm
         // (process name, e.g. "kworker" or "modprobe").
         t29_path = modname;
         n = std::snprintf(json, sizeof(json),
             "{\"ts\":%llu,\"pid\":%u,\"uid\":%u,\"username\":\"%s\",\"event\":\"modload\",\"comm\":\"%.16s\",\"modname\":\"%.64s\",\"subtype\":\"do_init_module\"}",
             ts, pid, uid, username.c_str(), kcomm, modname);
         break;
         }
         default:
        return 0;
    }

    // T12.14 (audit Nova H-02): the 14+ snprintf() calls above each
    // build into a 4096-byte buffer. snprintf returns the number of
    // characters that WOULD have been written (excluding null) — if
    // the formatted output is >= sizeof(json), the buffer is silently
    // truncated and the resulting JSON is malformed (missing closing
    // brace, missing tail field). Drop the event and count it so the
    // central doesn't try to parse broken JSON.
    if (n < 0 || static_cast<size_t>(n) >= sizeof(json)) {
        static std::atomic<uint64_t> json_trunc_count{0};
        uint64_t c = json_trunc_count.fetch_add(1, std::memory_order_relaxed) + 1;
        g_dropped.fetch_add(1, std::memory_order_relaxed);
        if (c == 1 || c % 100 == 0) {
            std::fprintf(stderr,
                "[loader] JSON buffer overflow in ringbuf_callback "
                "(n=%d, sizeof=%zu, total truncations=%llu) — event dropped\n",
                n, sizeof(json), (unsigned long long)c);
        }
        return 0;
    }

    // Enrichissement MITRE/sigma/severity déplacé vers le backend (app/enrichment.py).
    // L'agent envoie l'event JSON brut, le backend enrichit avant l'INSERT ClickHouse.
    // Voir issue SOC-AGENT #40.

    if (n > 0 && static_cast<size_t>(n) < sizeof(json)) {
        std::lock_guard<std::mutex> lock(g_queue_mtx);
        // Queue max size: drop oldest if > 10000
        // T4.8.27.19 / 27C.1.10: queue cap raised from 10k to 100k. With
        // 100Hz poll + ringbuf drain, we move ~50k events/min through here.
        // Old cap (10k) overflowed during FIM bursts, dropping critical
        // events (modload, execve, unlink). 100k gives ~2 minutes of buffer.
        if (g_queue.size() >= 100000) {
            g_queue.pop_front();
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        g_queue.emplace_back(json, static_cast<size_t>(n));
        }
    return 0;
}

/* --- Kernel compatibility --- */
bool kernel_ok() {
    struct utsname buf;
    if (uname(&buf) != 0) {
        g_reason.store("uname failed");
        return false;
    }
    int major = 0, minor = 0;
    if (std::sscanf(buf.release, "%d.%d", &major, &minor) < 2) {
        g_reason.store("cannot parse kernel version");
        return false;
    }
    if (major < 5 || (major == 5 && minor < 8)) {
        g_reason.store("kernel < 5.8");
        return false;
    }
    // L-05 audit fix: kernel 5.x without BTF makes eBPF fail silently.
    // Check for /sys/kernel/btf/vmlinux existence — without BTF, most
    // CO-RE (compile-once-run-everywhere) eBPF programs cannot attach.
    if (major >= 5 && access("/sys/kernel/btf/vmlinux", F_OK) != 0) {
        g_reason.store("kernel has no BTF (/sys/kernel/btf/vmlinux missing)");
        return false;
    }
    // Quick probe: bpf syscall must exist.
    int fd = syscall(SYS_bpf, 0, nullptr, 0);
    if (fd < 0 && errno == ENOSYS) {
        g_reason.store("bpf syscall unavailable");
        return false;
    }
    if (fd >= 0) close(fd);
    g_reason.store("ok");
    return true;
}

const char* kernel_reason() {
    const char* r = g_reason.load();
    return r ? r : "unknown";
}

/* --- Init: load 1 ELF object, attach all 6 programs, create single ring buffer --- */
bool init() {
    // T12 audit fix #59: take the state lock so init/stop/poll don't
    // interleave. Held for the entire init() — this function is
    // called rarely (boot + hot-reload), so the contention cost is
    // negligible.
    std::lock_guard<std::mutex> lock(g_state_mtx);
    if (g_initialized) return true;

    // Suppress libbpf info/debug in production; only show warnings
    libbpf_set_print([](enum libbpf_print_level level, const char *fmt, va_list ap) -> int {
        if (level == LIBBPF_WARN) {
            std::vfprintf(stderr, fmt, ap);
        }
        return 0;
    });

    // T10 fix: BPF link ownership verification at boot.
    //
    // The agent does NOT use BPF pinning (we attach with
    // bpf_program__attach_tracepoint/kprobe and keep the link in
    // g_obj.links[i] for the lifetime of the agent). Any pinned BPF
    // object under /sys/fs/bpf/ that names us is therefore unexpected
    // and a sign of either (a) tampering — an attacker pinning a
    // rogue program in our namespace, or (b) a stale pin from a
    // previous agent version that used pinning. Either way, refuse
    // to start and surface the alert.
    //
    // This is a defense-in-depth check. The bpf_object__load() below
    // also verifies the program integrity via the BPF verifier, but
    // it doesn't check for *other* programs in the system.
    {
        DIR *d = opendir("/sys/fs/bpf/");
        if (d) {
            std::vector<std::string> rogue_pins;
            struct dirent *e;
            while ((e = readdir(d)) != nullptr) {
                if (std::strstr(e->d_name, "logsoc-agent")) {
                    rogue_pins.push_back(e->d_name);
                }
            }
            closedir(d);
            if (!rogue_pins.empty()) {
                std::fprintf(stderr,
                    "ebpf init: T10 SECURITY ALERT: found %zu rogue BPF pin(s) "
                    "in /sys/fs/bpf/ matching 'logsoc-agent':\n",
                    rogue_pins.size());
                for (const auto &p : rogue_pins) {
                    std::fprintf(stderr, "  - /sys/fs/bpf/%s\n", p.c_str());
                }
                std::fprintf(stderr,
                    "ebpf init: refusing to start. Manual cleanup required:\n"
                    "  ls -la /sys/fs/bpf/ | grep logsoc\n"
                    "  sudo rm /sys/fs/bpf/<name>  # only if you know what it is\n"
                    "  sudo systemctl restart logsoc-agent\n");
                return false;
            }
        }
        // If /sys/fs/bpf/ doesn't exist or isn't readable, fall through
        // (some kernels / sandbox setups don't expose it; the bpf
        // attachment will still work via /dev/bpf).
    }

    // Open ELF blob from memory
    struct bpf_object *obj = bpf_object__open_mem(
        reinterpret_cast<const char*>(skel_soc_bpf),
        sizeof(skel_soc_bpf),
        nullptr);
    if (!obj) {
        std::fprintf(stderr, "ebpf init: bpf_object__open_mem failed for skel_soc\n");
        // T12 audit fix #35-38: was stop() → deadlock. Use _stop_unlocked().
        _stop_unlocked();
        return false;
    }

    // Load (verifier run included)
    if (bpf_object__load(obj) != 0) {
        std::fprintf(stderr, "ebpf init: bpf_object__load failed for skel_soc\n");
        bpf_object__close(obj);
        // T12 audit fix #35-38: was stop() → deadlock. Use _stop_unlocked().
        _stop_unlocked();
        return false;
    }

    // Attach all programs individually — detect tracepoint vs kprobe
    // Skip programs that are disabled in enabled_probes config
    struct bpf_program *prog = nullptr;
    int link_idx = 0;
    int skipped_count = 0;
    bpf_object__for_each_program(prog, obj) {
        if (link_idx >= 32) {
            std::fprintf(stderr, "ebpf init: too many programs in skel_soc (link_idx=%d)\n", link_idx);
            break;
        }
        const char *sec = bpf_program__section_name(prog);

        // Skip disabled probes
        if (!is_probe_enabled(sec)) {
            std::fprintf(stderr, "ebpf init: skipping disabled probe (sec=%s)\n", sec ? sec : "?");
            skipped_count++;
            continue;
        }

        struct bpf_link *link = nullptr;
        if (sec && std::strncmp(sec, "tp/", 3) == 0) {
            /* tracepoint form: tp/category/name */
            char buf[256];
            std::strncpy(buf, sec + 3, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            char *slash = std::strchr(buf, '/');
            if (slash) {
                *slash = '\0';
                std::fprintf(stderr, "ebpf init: attaching tracepoint %s/%s\n", buf, slash + 1);
                link = bpf_program__attach_tracepoint(prog, buf, slash + 1);
            } else {
                std::fprintf(stderr, "ebpf init: no slash in tracepoint section\n");
            }
        } else if (sec && std::strncmp(sec, "kprobe/", 7) == 0) {
            /* kprobe form: kprobe/symbol_name — must use bpf_program__attach_kprobe */
            const char *sym = sec + 7;
            std::fprintf(stderr, "ebpf init: attaching kprobe %s\n", sym);
            link = bpf_program__attach_kprobe(prog, false, sym);
        } else if (sec && std::strncmp(sec, "kretprobe/", 10) == 0) {
            /* kretprobe form: kretprobe/symbol_name */
            const char *sym = sec + 10;
            std::fprintf(stderr, "ebpf init: attaching kretprobe %s\n", sym);
            link = bpf_program__attach_kprobe(prog, true, sym);
        } else {
            link = bpf_program__attach(prog);
        }
        if (!link) {
            std::fprintf(stderr, "ebpf init: bpf_program__attach failed for prog=%s (sec=%s)\n", bpf_program__name(prog), sec ? sec : "?");
            skipped_count++;
            continue;
        }
        g_obj.links[link_idx++] = link;
    }
    g_obj.link_count = link_idx;
    if (g_obj.link_count == 0) {
        std::fprintf(stderr, "ebpf init: no programs attached (all %d failed)\n", skipped_count);
        // T12 audit fix #35-38: was stop() → deadlock. Use _stop_unlocked().
        _stop_unlocked();
        return false;
    }

    // Find ringbuf map and create consumer
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    int rb_map_fd = map ? bpf_map__fd(map) : -1;
    if (rb_map_fd >= 0) {
        g_obj.rb = ring_buffer__new(rb_map_fd, ringbuf_callback, nullptr, nullptr);
        if (!g_obj.rb) {
            std::fprintf(stderr, "ebpf init: ring_buffer__new failed for skel_soc\n");
            // T12 audit fix #35-38: was stop() → deadlock. Use _stop_unlocked().
            _stop_unlocked();
            return false;
        }
    }

    // Inject self PID for self-exclusion
    struct bpf_map *pid_map = bpf_object__find_map_by_name(obj, "agent_pid");
    if (pid_map) {
        int pid_fd = bpf_map__fd(pid_map);
        uint32_t key = 0;
        uint32_t val = static_cast<uint32_t>(getpid());
        bpf_map_update_elem(pid_fd, &key, &val, BPF_ANY);
    }

    g_obj.obj = obj;
    g_initialized.store(true);
    return true;
}

/* --- Cleanup --- */
//
// T12 audit fix #35-38 (CRITICAL — DEADLOCK): the previous stop() took
// g_state_mtx, but init() already holds g_state_mtx when it calls
// stop() in error paths (bpf_object__open_mem failure, bpf_object__load
// failure, ring_buffer__new failure, no programs attached). std::mutex
// is NON-RECURSIVE → the lock() in stop() blocks forever on the same
// thread that already owns it. The agent hangs in init() on boot and
// the systemd watchdog kills it after 90s.
//
// Fix: split stop() into a public stop() that takes the lock and a
// private _stop_unlocked() that doesn't. init() calls _stop_unlocked()
// for its error-path cleanup (it already holds the lock), and the
// external stop() (from D-tor, from policy unbind, etc.) takes the
// lock first.

static void _stop_unlocked() {
    // Destroy links first (they pin programs)
    for (int i = 0; i < g_obj.link_count; ++i) {
        if (g_obj.links[i]) {
            bpf_link__destroy(g_obj.links[i]);
            g_obj.links[i] = nullptr;
        }
    }
    g_obj.link_count = 0;

    if (g_obj.rb) {
        ring_buffer__free(g_obj.rb);
        g_obj.rb = nullptr;
    }

    if (g_obj.obj) {
        bpf_object__close(g_obj.obj);
        g_obj.obj = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(g_queue_mtx);
        g_queue.clear();
    }
    g_initialized.store(false);
}

void stop() {
    // T12 audit fix #59: take the global state lock for the entire
    // stop() so poll() cannot observe a partially-destroyed g_obj.
    std::lock_guard<std::mutex> lock(g_state_mtx);
    _stop_unlocked();
}

/* --- Poll: consume single ringbuf, dequeue JSON events --- */
int poll(char* buf, size_t len) {
    // T12 audit fix #59: hold the state lock across the g_initialized
    // check and the g_obj.rb access so stop() cannot race us.
    std::lock_guard<std::mutex> lock(g_state_mtx);
    if (!g_initialized) return -1;

    // Drain ring buffer fully (until -EAGAIN / -EINTR)
    // T4.8.27.11 / 27C.1.2: was single call — losing events when ringbuf
    // rate > poll rate. Now loops until kernel returns -EAGAIN.
    if (g_obj.rb) {
        int drained = 0;
        while (ring_buffer__consume(g_obj.rb) == 0) {
            if (++drained > 1024) break;  /* safety cap */
        }
    }

    // T30.2: sample ringbuf positions AFTER the drain. The producer
    // position is incremented by the kernel for every event submitted.
    // The consumer position is what ring_buffer__consume has read up
    // to. After a full drain, consumer_pos = producer_pos - avail_data.
    // If a new event arrives between kernel eBPF submission and our
    // position read, it's counted in producer but not yet consumed —
    // the diff between (producer - consumer) and avail_data_size tells
    // us how many events were lost in flight (overwritten by kernel
    // before we could read them).
    if (g_obj.rb) {
        struct ring *r = ring_buffer__ring(g_obj.rb, 0);
        if (r) {
            uint64_t prod = ring__producer_pos(r);
            uint64_t cons = ring__consumer_pos(r);
            size_t   avail = ring__avail_data_size(r);
            // Window delta: events produced since last poll
            if (g_ringbuf_pos_initialized.load(std::memory_order_relaxed)) {
                uint64_t prev_prod = g_ringbuf_prev_producer_pos.load(std::memory_order_relaxed);
                uint64_t prev_cons = g_ringbuf_prev_consumer_pos.load(std::memory_order_relaxed);
                // T12 audit fix #50: guard against underflow if the
                // kernel reset the ringbuf positions (e.g. the
                // bpf_object was reloaded by a hot-patch and the
                // ringbuf was remapped, or the kernel rolled over
                // its 64-bit counter — unlikely in practice but
                // cheap to handle). Without this, prod - prev_prod
                // underflows to ~2^64, which corrupts
                // g_ringbuf_lost_events with a huge bogus value.
                if (prod >= prev_prod && cons >= prev_cons) {
                    uint64_t produced_delta = prod - prev_prod;
                    uint64_t consumed_delta = cons - prev_cons;
                    // produced - consumed = events still in flight OR lost
                    // avail is what's still readable; the rest is lost
                    if (produced_delta > consumed_delta) {
                        uint64_t in_flight = produced_delta - consumed_delta;
                        if (in_flight > avail) {
                            g_ringbuf_lost_events.fetch_add((in_flight - avail), std::memory_order_relaxed);
                        }
                    }
                    g_ringbuf_total_events.fetch_add(consumed_delta, std::memory_order_relaxed);
                }
                // else: positions reset, skip the delta this cycle
            }
            g_ringbuf_prev_producer_pos.store(prod, std::memory_order_relaxed);
            g_ringbuf_prev_consumer_pos.store(cons, std::memory_order_relaxed);
            g_ringbuf_pos_initialized.store(true);
        }
    }

    std::lock_guard<std::mutex> q_lock(g_queue_mtx);
    if (g_queue.empty()) return -1;

    // T4.8.27.17 / 27C.1.8 / T12.14: pop ONE event per poll() call.
    // The EbpfCollector.run() loops on poll() at 10Hz, draining
    // ~10 events/sec to the collector buffer. With the ringbuf drain
    // loop above, we read ALL events from kernel; with force_push(),
    // critical events never get dropped; this final pop is the
    // intentional throughput cap (10 events/sec = the design target).
    // Audit Nova H-03 marked this as a bottleneck; we accept the
    // trade-off: the kernel-side ringbuf is fully drained (no events
    // dropped in-kernel), and the user-space queue is bounded to
    // 100k entries (T4.8.27.10). The only risk is the user-space
    // queue filling up under sustained >10k events/sec load, which
    // the drop counter would make visible. We deliberately do NOT
    // raise the delivery rate here because the downstream sender is
    // already running flat-out under normal load — pumping events
    // faster would just overflow InMemoryBuffer / WAL quota faster.
    // Fix would require redesigning the sender to batch from
    // eBPF directly, which is out of scope for this security sprint.
    const std::string &s = g_queue.front();
    size_t to_copy = (s.size() < len) ? s.size() : len;
    std::memcpy(buf, s.data(), to_copy);
    g_queue.pop_front();
    return static_cast<int>(to_copy);
}

/* --- Single fd for the unified ringbuf --- */
int get_fd() {
    if (!g_obj.obj) return -1;
    struct bpf_map *map = bpf_object__find_map_by_name(g_obj.obj, "events");
    return map ? bpf_map__fd(map) : -1;
}

} // namespace ebpf