// agent_v3.cpp — LogSOC Agent C++ v3.2 (eBPF minimal integration)
//
// Flow v3.2:
//   1. Lire config.json (central_url + options locales)
//   2. Si auth.json existe → charger creds → ACTIVE direct
//   3. Si absent → POST /api/v1/agents/register → pending + request_id
//                 → GET /api/v1/agents/status poll toutes les 10s
//                 → receive agent_token + hmac_secret + wal_secret
//                 → écrire auth.json
//   4. Dériver aes_key + hmac_key depuis wal_secret (PBKDF2)
//   5. Init WalManager
//   6. PRIORITY: test eBPF → si OK, activate module eBPF
//      → sinon fallback fichiers
//   7. Démarrage collecteurs + heartbeat
//   8. Boucle principale Ctrl+C
//
// Compilation: make (g++ -std=c++17, libcurl, OpenSSL)
// Usage: ./soc_agent config.json
//
// Fabrice IT (c) 2026

// T38: Use compiled-in version instead of config.json's version for heartbeat.
// AGENT_VERSION is set by the Makefile (default: 4.8.0, override: make AGENT_VERSION=x.y.z)
#ifndef AGENT_VERSION
#define AGENT_VERSION "unknown"
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include <filesystem>
#include <csignal>
#include <sys/resource.h>  // T31: getrusage for metrics CPU%
#include <cstdlib>
#include <mutex>
#include <deque>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <bitset>
#include <memory>
#include <optional>
#include "uuid.hpp"

#include <atomic>
#include <set>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "json.hpp"
#include "crypto.hpp"
#include "fallback_wal.hpp"
#include "wal_writer_process.hpp"   // T13 (audit 2026-06-16): privilege-separated WAL writer
#include "in_memory_buffer.hpp"
#include "runtime_credentials.hpp"
#include "agent_auth.hpp"           // registre, heartbeat, HMAC
#include "action_executor.hpp"      // T28: defensive action executor (no auto-reaction)
// T13.3': privilege-separated action recommender child (analyst) +
// parent-side validator with 3 safety barriers (rule allowlist,
// PID exclusion, action allowlist). The child is logsoc:logsoc and
// CANNOT execute actions — it sends structured recommendations
// that the parent validates before calling t28::execute().
#include "action_recommender_process.hpp"
#include "action_validator.hpp"
#include "agent/t12_10c_commands.hpp"  // T12.10d: backend → agent command executor
#include "network/pcap_collector.hpp" // v3.1
#include "yara/yara_engine.hpp"        // v3.10.0: YARA HQ (file/memory/network/log scanning)
#include "encryption_detect.hpp"      // v3.21.0 (T66): disk encryption detection
#include "ebpf/loader.hpp"          // v3.2
#include "ebpf/t13_4_xdp_loader.hpp" // T13.4 (XDP SYN scan detection)
// v4.8.0 (T4.8): FIM pipeline rewrite — FimCollector + FdResolver + FimMetrics
#include "agent/fim_collector.hpp"
#include "agent/fim_poller.hpp"
// T13.2c: FimScannerProcess replaces FimPoller for privilege separation.
// The scanner runs as logsoc:logsoc with CAP_DAC_READ_SEARCH, scans
// watch_paths in a child process, and forwards detected changes via
// 2 socketpair channels (event + command). See fim_scanner_process.hpp
// and the ticket at ~/.hermes/tickets/T13.2-fim-scanner-privilege-separation.md
#include "fim_scanner_process.hpp"
#include "agent/fd_resolver.hpp"
#include "agent/fim_metrics.hpp"
// T12.11 (2026-06-16): FimMetricsServer removed — metrics now ship in
// the heartbeat body (T12.10), no inbound port needed.

#ifdef __linux__
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/fanotify.h>    // v3.10.1: FanotifyCollector (FAN_MODIFY/CREATE/DELETE/MOVE)
#include <linux/fanotify.h>  // FAN_EVENT_ON_CHILD, FAN_MARK_ADD
#include <dirent.h>          // v3.10.2: opendir/readdir for /etc walk (POSIX, std::filesystem was broken on Hestia 6.8)
#include <poll.h>            // v3.10.2: poll() on fanotify fd (FAN_NONBLOCK, no more EACCES on blocking read)
#include <pwd.h>
#include <sys/un.h>
#include <systemd/sd-journal.h>
#include <ifaddrs.h>           // v3.6: getifaddrs for IP detection
#include <netinet/in.h>       // v3.6: sockaddr_in, sockaddr_in6
#include <arpa/inet.h>        // v3.6: inet_ntop
#include <sys/utsname.h>     // v3.6: uname for kernel version
#include <net/if.h>           // v3.6: IFF_LOOPBACK
#include <sys/statvfs.h>      // v3.6: statvfs for disk size detection
#include <netpacket/packet.h> // v3.6: sockaddr_ll for MAC detection
#endif

#include <fcntl.h>      // F_SETFL, O_NONBLOCK (for eBPF ringbuf)

#include "correlator.hpp"  // v3.7: eBPF ↔ journald cross-validation

// syslog.h (pulled by sd-journal.h) defines LOG_DEBUG/LOG_INFO/LOG_WARNING/LOG_ERROR
// as integer constants (7/6/4/3), conflicting with our LOG_xxx macros.
// Undef them before including debug.hpp.
#ifdef LOG_DEBUG
#undef LOG_DEBUG
#endif
#ifdef LOG_INFO
#undef LOG_INFO
#endif
#ifdef LOG_WARNING
#undef LOG_WARNING
#endif
#ifdef LOG_ERROR
#undef LOG_ERROR
#endif
#ifdef LOG_WARN
#undef LOG_WARN
#endif

#include "debug.hpp"              // v3.4 runtime debug (MUST be after system headers)

// v3.15 (T59): YARA content fetch (agent → central). MUST come after
// debug.hpp (the yara_shipper.hpp uses LOG_xxx macros that we just
// un-#define'd from syslog.h above, and re-#define'd in debug.hpp).
#include "yara_shipper.hpp"
#include "atomic_unique_ptr.hpp"  // T13.10: thread-safe unique_ptr wrapper (C++17)

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace crypto;
using namespace fallback_wal;

std::atomic<bool> g_running{true};

// v3.11: heartbeat interval made hot-reloadable (SOC-AGENT#4).
//   The thread lambda previously captured this by value (so changes in the
//   config struct had no effect until restart). Reading from the atomic at
//   the top of each sleep makes the change visible on the next iteration.
//   memory_order_relaxed is fine: the value is just a sleep duration.
std::atomic<int> g_hb_interval_sec{60};


/* ─── Agent config (v3.2) ─── */
struct AgentConfig {
    std::string central_url;
    // P1 sec audit fix (M-06, 2026-06-16): was "3.20". The .deb ships
    // 4.8.0-t12.8 and the Git tag history goes well past 3.20 (see
    // CHANGELOG.md and recent commit subjects). This string is
    // surfaced in the heartbeat payload (agent_version), the startup
    // log, the registration request body, and FimMetrics, so it MUST
    // stay in sync with the packaging version. Single source of
    // truth going forward: the VERSION arg passed to
    // packaging/scripts/build-deb.sh. A future patch will move this
    // to a generated version.h to remove the manual sync.
    // T14.5 — fix issue #37 second pass: the eBPF EbpfCollector also
    // drops the enrichment fields (mitre, sigma, severity_score, argv,
    // action, flags, bytes_size, family, source) when re-building its
    // outbound `item` from the parsed raw event. The loader.cpp
    // enricher writes them into the JSON, but the EbpfCollector's
    // per-field propagation didn't include them. Also fixed: sigma is
    // an array of {id, level, techniques} objects, not a string. Also
    // extended the sender's severity whitelist to cover syslog RFC
    // 5424 levels (warning, error, etc.) which were silently dropped.
    // See ~/.hermes/tickets/T14.5.
    std::string version = "4.8.19";  // bump per release; keep aligned with .deb control
    std::string hostname;
    std::vector<std::string> scan_paths;  // v3.7.0: list of log files AppCollector should read
    // v3.7.0: AppCollector is the renamed SyslogCollector. It now READS files (no socket).
    // It is enabled by app_collector_enabled AND a non-empty scan_paths.
    bool app_collector_enabled = false;  // off by default — set to true when scan_paths populated
    // v3.3.11 legacy field, kept for config backward compat but unused:
    std::string syslog_socket_path = "/var/run/logsoc-syslog.sock";
    int batch_interval_sec = 30;
    int batch_max_lines = 500;
    // T12.14 (audit Nova H-06): the 60-second HMAC window allows
    // replay of an intercepted signed request within 60s. A proper
    // fix requires a monotonically-increasing nonce signed with the
    // HMAC payload AND central-side dedup (e.g. Redis SET with TTL
    // 60s). Adding nonce on agent side only would BREAK central
    // signature verification. We deliberately leave this at 60s for
    // now; tracking in T13 backlog. The window matches typical
    // NTP-synced clock skew tolerance.
    int hmac_window_sec = 60;
    // T14.1 — H-06 HMAC nonce opt-in. Default false (preserves current
    // behavior, no X-Nonce header, HMAC payload is f"{ts}.{body_hash}").
    // When the central team lands nonce support (R3-style release of
    // logsoc-web), set this to true in /etc/logsoc-agent/config.json
    // and the agent will start sending X-Nonce + signing with the
    // nonce included. The flag exists so the agent NEVER breaks
    // compatibility with an old central: the operator flips the
    // switch only after confirming the central accepts it. See
    // ~/.hermes/tickets/T14.1-h06-hmac-nonce-central-redis.md.
    bool hmac_nonce_enabled = false;
    // T14.0b — event coalescing opt-in. When true, the Sender groups
    // N events with the same (event_type, path) into a single event
    // with count=N and pids=[...]. Reduces volume on noisy paths
    // (e.g. apt install opening 50 files in /etc). When false (default),
    // no coalescing — every event is sent as-is. The opt-in exists
    // because the merged event has a different JSON shape, which
    // could confuse downstream tools that expect 1 event = 1 record.
    // The central team (or the operator) decides when to enable it.
    bool coalesce_enabled = false;
    // Max number of pids to include in the merged event. If a single
    // (event_type, path) group has more pids than this, the rest are
    // dropped (the merged event still has count=N, but pids only
    // contains the first `max_pids_in_merged` entries). Prevents
    // pathological events with megabyte-sized pid lists.
    size_t coalesce_max_pids = 20;
    // T14.0f — per-event-type priority. When true, the Sender
    // partitions the drained batch into 3 priority tiers and sends
    // high-priority events FIRST (FIM/execve/unlink), then medium
    // (open/tcp_connect), then low (journald/scan). This ensures
    // security-critical events ship before noise even when the
    // central is slow and batches are capped at adaptive_max.
    bool priority_enabled = false;
    // T14.0d — partial-success semantics. When true, the Sender
    // handles HTTP 207 (Multi-Status) responses by parsing the body
    // for failed event_ids and re-pushing ONLY those (not the whole
    // batch). Default OFF because the central doesn't currently
    // emit 207 — it's a future-proofing opt-in. The flag becomes
    // effective when the central team adds Multi-Status support
    // to the events ingestion endpoint.
    bool partial_success_enabled = false;
    std::string fallback_wal_dir;   // v3.8.0: directory for FallbackWAL segments
    size_t in_memory_buffer_capacity = 500000; // v3.9.6: 500k events (was 100k in v3.9.0) — Hestia prod has 8-10 drops/s constant, 100k too small to absorb burst
    // Note: at avg ~500 bytes/event, 500k = ~250 MB max. In practice ring never fills that high.
    // v3.1: options dynamiques (écrasables par le central)
    std::unordered_map<std::string, std::string> extra_options;
    // v3.1: module réseau
    bool module_network = false;
    logsoc::NetworkConfig net_cfg;
    // v3.2: module eBPF
    bool module_ebpf = false;
    // T13.4: optional XDP SYN scan detection (in-kernel).
    //   - enable_xdp_scan = false (default): XDP is NOT attached,
    //     pcap_collector (existing) is the only network path.
    //   - enable_xdp_scan = true: ALSO attach the XDP program
    //     (side-by-side with pcap). The XDP program is independent
    //     and does not affect pcap.
    //   - xdp_interface = "" (default): use the system default
    //     (eth0 on most boxes, or auto-detect if not set).
    //   - T13.4' (future): enable_xdp_scan=true can be used to
    //     REPLACE pcap_collector entirely. Not in this commit.
    bool enable_xdp_scan = false;
    std::string xdp_interface = "";  // empty = use auto-detect
    // v3.10.0: YARA HQ engine (file/memory/network/log scanning via bitmask)
    bool yara_enabled = false;
    int yara_scan_flags = 1;        // default: file only (bit0). Use 15 for all 4 modes.
    int yara_max_scan_file_mb = 10; // skip files larger than this
    int yara_max_rule_size_kb = 64; // skip rules larger than this
    int yara_match_post_interval_sec = 30; // rate-limit match posts to central
    int yara_scan_timeout_ms = 5000;
    int yara_rule_pull_interval_sec = 300;  // 5 min between rule pull from central
    // v3.17.0 (T61.1): bound the compile_rules() wall time when many
    // rules fail. Default 30s. 0 = unbounded (legacy pre-v3.17 behavior).
    int yara_max_compile_ms = 30000;
    std::string yara_hmac_token;     // populated from runtime credentials
    // v3.15 (T59): YARA content fetch (agent → central). When true, the
    // FanotifyCollector ships suspicious file content to POST /api/v1/yara/scan
    // instead of (or in addition to) scanning locally. Off by default.
    bool yara_ship_content = false;
    int yara_ship_max_file_size = 4 * 1024 * 1024;  // 4MB to match central API bound
    int yara_ship_heuristic_threshold = 3;  // 0-10, 3 = light filter (catch obvious cases)
    // T12.16 (audit Nova C-05): yara_ship_metrics_port + fim_metrics_port
    // removed. HTTP metrics servers are gone — metrics are now pushed
    // in the heartbeat payload. Configs that still carry these JSON
    // keys are silently ignored.
    // v3.4: module journald (systemd journal reader via sd_journal)
    bool module_journald = true;  // enabled by default on Linux
    // v3.10.1: FanotifyCollector — userspace FIM via fanotify(7) with absolute
    // paths. Complements/replaces eBPF FIM (kprobe/vfs_write basename-only).
    // Enabled via config "fanotify_enabled": true. Uses cfg.fim.watch_paths
    // as the mark target list.
    bool fanotify_enabled = false;  // off by default — opt-in
    // v4.8.0 (T4.8): FIM engine feature flag.
    //   "v5_simplified" (default) — 1-probe + userspace FdResolver + FimCollector
    //   "v4_duplex"                — old openat+vfs_write+open_path_cache (V4.7 fallback)
    // Used by EbpfCollector to decide whether to route events through FimCollector
    // or send them directly via the legacy path.
    std::string fim_engine = "v5_simplified";
    // v4.8.0 (T4.8): FIM pipeline knobs (only used when fim_engine=v5_simplified)
    int  fim_fd_worker_count = 4;
    int  fim_ship_queue_capacity = 8192;
    int  fim_rate_limit_per_pid_per_sec = 100;
    std::string fim_cb_state_file;  // defaults to /var/lib/logsoc-agent/fim_cb_state.json
    // v4.8.0 (T4.8.8): FimPoller fallback config. Polls fim.watch_paths
    // every N seconds and SHA-256-compares. 0 = disabled.
    int  fim_poll_interval_sec = 5;
    // Hestia kernel 6.8.0-117 only allows FAN_MODIFY on individual files
    // (FAN_CREATE/DELETE/MOVE on files returns EINVAL — they require
    // FAN_EVENT_ON_CHILD on a directory, which is also broken on this
    // kernel). So we restrict ourselves to FAN_MODIFY for now. This still
    // covers the main FIM signal: "file content changed". CREATE/DELETE
    // on a directory can be added later when the kernel issue is fixed.
    int fanotify_file_mask = 0x00000002;  // FAN_MODIFY
    int fanotify_dir_mask  = 0x00000002;  // FAN_MODIFY (placeholder, dir walk uses file_mask)
    // v3.4: journald filters — which SYSLOG_IDENTIFIERs to exclude
    // T12 audit fix (Bug 1 in audit report): journald_exclude_ids is
    // written by the heartbeat thread (apply_config_update) and read
    // by the JournaldCollector thread on every drain (~1s). Without
    // synchronization, std::vector assignment can reallocate and free
    // the old buffer while JournaldCollector is iterating — use-after-
    // free. journald_mtx protects both this vector and the
    // corresponding dirty flag.
    mutable std::mutex journald_mtx;
    std::vector<std::string> journald_exclude_ids = {"logsoc-agent"};
    // v3.4: eBPF probe enable/disable map (probe_name → enabled)
    //
    // Audit 2026-06-15 (Gitea #12): this list was missing 11 names. Any
    // probe not listed here defaults to ENABLED (per is_probe_enabled()
    // in ebpf/loader.cpp), but the local config, central policy, and
    // /api/v1/agents/{id}/config endpoints all iterated over this map.
    // Now exhaustive: every probe skel_soc.c attaches has an entry.
    std::unordered_map<std::string, bool> enabled_probes = {
        // Legacy (pre-v4.8)
        {"write", false},       // disabled: no filename, redundant with fim
        {"execve", true},
        {"tcp_connect", true},
        {"fim", true},
        {"open", true},
        {"unlink", true},
        {"write_fd", true},     // T4.8 hotfix: needed for FIM /proc fd resolution
        // V4.8.27 / T4.8.27.x — added 2026-05, listed here 2026-06-15
        {"modload", true},      // rootkit detection
        {"open_kp", true},      // vfs_open kprobe (separate from legacy "open" tp)
        {"tcp_accept", true},   // backdoor accept() detection
        {"tcp_v4_connect", true},// outgoing C2 detection (redundant with tcp_connect)
        {"bind", true},         // bind-to-port backdoor
        {"fork", true},         // process fork signal
        {"creds", true},        // privilege escalation (commit_creds)
        {"ptrace", true},       // anti-debug, ptrace injection
        {"bpf", true}           // EDR self-protection (other bpf(2) calls)
    };
    // v3.3.10: severity mapping (event type → syslog level string)
    //
    // Audit 2026-06-15 (Gitea #12): same coverage gap as enabled_probes.
    // Events for modload/open_kp/tcp_accept/tcp_v4_connect/bind/fork/creds/
    // ptrace/bpf had no severity entry and fell back to "default" (info).
    // The UI uses severity to decide what to escalate — modload missing
    // its "critical" level was silently downgraded.
    std::unordered_map<std::string, std::string> severity_map = {
        {"write", "info"}, {"execve", "notice"}, {"tcp_connect", "notice"},
        {"fim", "info"}, {"open", "info"}, {"unlink", "warning"},
        {"write_fd", "info"},
        {"modload", "critical"},       // T11 — rootkit
        {"open_kp", "info"},
        {"tcp_accept", "warning"},     // backdoor
        {"tcp_v4_connect", "notice"},  // C2
        {"bind", "warning"},           // backdoor
        {"fork", "info"},
        {"creds", "critical"},         // T4.8.27.3 — priv-esc
        {"ptrace", "warning"},         // T4.8.27.2
        {"bpf", "warning"},            // T4.8.27.4 — EDR tampering
        {"journald", "info"},
        {"default", "info"}
    };
    // v3.5: local filters (spec v4.1: local_filters section)
    struct LocalFilters {
        std::vector<std::string> connect_ignore_ports;
        std::vector<std::string> connect_ignore_ips;
        std::vector<std::string> execve_ignore_comm;
        std::vector<std::string> open_ignore_paths;
        std::vector<std::string> unlink_ignore_paths;
        bool open_ignore_rdonly = true;
    } local_filters;
    // v3.5: FIM configuration (spec v4.1: fim section)
    struct FimConfig {
        std::vector<std::string> watch_paths;
        std::vector<std::string> ignore_paths;
    } fim;
    // v3.5: eBPF rate limit (events/sec per PID, spec: ebpf.rate_limit_per_pid)
    uint32_t ebpf_rate_limit = 100;
    // v3.5: configurable redact patterns (spec: ebpf.redact_patterns)
    std::vector<std::string> redact_patterns;
    // v3.5: heartbeat interval (spec: heartbeat.interval_sec)
    int heartbeat_interval_sec = 60;
    // v3.2: data directory (separate from config_dir for systemd hardening)
    std::string data_dir;
    // v3.6: host context for dashboard display
    std::string os_name;          // e.g. "Ubuntu", "CentOS"
    std::string os_version;       // e.g. "24.04.4 LTS"
    std::string kernel_version;   // e.g. "6.8.0-117-generic"
    std::vector<std::string> ip_addresses;  // all non-loopback IPs
    // Host info fields sent in heartbeat (detected at startup)
    std::string arch;             // e.g. "x86_64", "aarch64"
    std::string mac;              // first non-lo MAC address
    std::string cpu_model;        // from /proc/cpuinfo "model name"
    int memory_mb = 0;            // MemTotal / 1024
    int disk_gb = 0;             // statfs("/") total in GB

    // T64.2.2 (v3.20.0): Policy received from central (/api/v1/agent-config/policy).
    // Single struct so all runtime-tunable knobs are co-located.
    // - Initialized from local config.json in load_config() (fallback).
    // - Overwritten by pull_policy_from_central() every 5 min (T64.2.2).
    // - Read by YaraShipper (threshold), FanotifyCollector
    //   (watch_paths). The metrics_bind_address field was removed
    //   in T12.16 (audit Nova C-05) — HTTP metrics server is gone.
    struct PolicyConfig {
        // T12 audit fix #24: policy_mtx protects all fields below from
        // concurrent access between the PolicyPuller thread (writer)
        // and the main loop (reader, every 30s tick). Without it, the
        // main loop could iterate over a vector that PolicyPuller is
        // mutating (via std::move on assignment) — iterator invalidation
        // and use-after-free crash. The atomic<bool> dirty flags
        // (fim_watch_paths_dirty, enabled_probes_dirty) are still needed
        // to signal the main loop that something changed; the mutex
        // protects the actual data.
        // mutable so const methods (e.g. const AgentConfig& cfg_ in
        // FanotifyCollector) can lock it via std::lock_guard. T12
        // audit fix (Bug 2): the FanotifyCollector snapshots
        // policy.fim_watch_paths under this lock from run().
        mutable std::mutex policy_mtx;
        // T12.16: metrics_bind_address removed (HTTP metrics server gone).
        std::vector<std::string> fim_watch_paths;         // Fanotify targets
        int ship_heuristic_threshold = 3;                 // YaraShipper gate
        // Source tracking (debug / audit)
        std::string source = "default";  // "default" | "local" | "central"
        int64_t last_pulled_at = 0;      // unix timestamp of last successful pull
        // T64.4.2: set to true by pull_policy_once() when fim_watch_paths changed.
        // The main loop polls this every 30s and calls rebuild_fanotify_collector()
        // to apply the new paths (FanotifyCollector doesn't see vector mutations
        // after start(), it captured a reference to cfg but needs to re-mark).
        std::atomic<bool> fim_watch_paths_dirty{false};
        // T30.3: set to true by pull_policy_once() when enabled_probes changed.
        // The main loop polls this every 30s and calls rebuild_ebpf_probes()
        // (destroy + reattach all bpf_links). The map stores the desired
        // state: probe_name → enabled. The local AgentConfig.enabled_probes
        // (declared in the main struct, see above) is the bootstrap fallback
        // and the source of truth when no central override exists.
        std::atomic<bool> enabled_probes_dirty{false};
        std::unordered_map<std::string, bool> enabled_probes;
    } policy;
};

/* ─── apply_config_update: v3.12 hot-reload helper (SOC-AGENT#4)
 *
 * Called from the heartbeat thread when the central response carries a
 * "config" object. Each key is optional and bounded — we never widen the
 * agent's attack surface (no central_url, no token, no yara rules). The
 * runtime-tunable knobs are:
 *
 *   log_level              (int,    0..5)        — atomic store
 *   heartbeat_interval_sec (int,    5..3600)     — atomic store
 *   scan_paths             (string array)        — triggers rebuild_app_collectors
 *   watch_paths            (string array)        — triggers rebuild_fanotify
 *
 * On any parse error or out-of-range value, the field is skipped and a
 * warning is logged. Other fields are still applied.
 *
 * For scan_paths and watch_paths: the function RETURNS a flag indicating
 * that the caller (heartbeat thread) must call the rebuild helpers. The
 * rebuild itself is done OUTSIDE apply_config_update because it needs
 * the cfg, buffer, and the global collector vectors.
 *
 * g_log_level is declared `inline std::atomic<int>` in debug.hpp; we read/write
 * it via load()/exchange() (no operator>= on atomic).
 */
struct ConfigUpdateResult {
    bool log_level_applied = false;
    bool hb_interval_applied = false;
    int  prev_log_level = 0;
    int  prev_hb_interval = 0;
    std::vector<std::string> applied_scan_paths;     // non-empty => rebuild needed
    std::vector<std::string> applied_watch_paths;    // non-empty => rebuild needed
    std::vector<std::string> applied_journald_exclude_ids;  // applied in-place, no rebuild
    std::string error; // non-empty if the whole update was rejected
};

static ConfigUpdateResult apply_config_update(const json& j, AgentConfig& cfg) {
    ConfigUpdateResult r;
    if (!j.is_object()) {
        r.error = "config must be an object";
        return r;
    }

    // 1. log_level: 0..5 (ERROR..TRACE)
    if (j.contains("log_level")) {
        if (!j["log_level"].is_number_integer()) {
            LOG_WARN("[HB-HR] hot-reload: log_level not an integer, ignored");
        } else {
            int new_lvl = j["log_level"].get<int>();
            if (new_lvl < 0 || new_lvl > 5) {
                LOG_WARN("[HB-HR] hot-reload: log_level=" << new_lvl
                         << " out of range [0..5], ignored");
            } else {
                r.prev_log_level = g_log_level.exchange(new_lvl);
                r.log_level_applied = true;
                LOG_INFO("[HB-HR] log_level: " << r.prev_log_level
                         << " -> " << new_lvl);
            }
        }
    }

    // 2. heartbeat_interval_sec: 5..3600 (5s min, 1h max)
    if (j.contains("heartbeat_interval_sec")) {
        if (!j["heartbeat_interval_sec"].is_number_integer()) {
            LOG_WARN("[HB-HR] hot-reload: heartbeat_interval_sec not an integer, ignored");
        } else {
            int new_hb = j["heartbeat_interval_sec"].get<int>();
            if (new_hb < 5 || new_hb > 3600) {
                LOG_WARN("[HB-HR] hot-reload: heartbeat_interval_sec=" << new_hb
                         << " out of range [5..3600], ignored");
            } else {
                r.prev_hb_interval = g_hb_interval_sec.exchange(new_hb);
                r.hb_interval_applied = true;
                LOG_INFO("[HB-HR] heartbeat_interval_sec: "
                         << r.prev_hb_interval << " -> " << new_hb
                         << " (takes effect on next cycle)");
            }
        }
    }

    // 3. v3.12: scan_paths (string array, max 64 entries, each <= 512 chars)
    if (j.contains("scan_paths")) {
        if (!j["scan_paths"].is_array()) {
            LOG_WARN("[HB-HR] hot-reload: scan_paths not an array, ignored");
        } else {
            std::vector<std::string> new_paths;
            bool bad = false;
            for (const auto& p : j["scan_paths"]) {
                if (!p.is_string()) {
                    LOG_WARN("[HB-HR] hot-reload: scan_paths entry not a string, ignored");
                    bad = true;
                    break;
                }
                std::string s = p.get<std::string>();
                if (s.size() > 512) {
                    LOG_WARN("[HB-HR] hot-reload: scan_paths entry too long (>"
                             << 512 << "), ignored");
                    bad = true;
                    break;
                }
                new_paths.push_back(std::move(s));
            }
            if (!bad) {
                if (new_paths.size() > 64) {
                    LOG_WARN("[HB-HR] hot-reload: scan_paths has " << new_paths.size()
                             << " entries (>64 max), truncated to 64");
                    new_paths.resize(64);
                }
                r.applied_scan_paths = std::move(new_paths);
                LOG_INFO("[HB-HR] scan_paths: " << r.applied_scan_paths.size()
                         << " path(s) queued for rebuild");
            }
        }
    }

    // 4. v3.12: watch_paths (string array, same limits as scan_paths)
    if (j.contains("watch_paths")) {
        if (!j["watch_paths"].is_array()) {
            LOG_WARN("[HB-HR] hot-reload: watch_paths not an array, ignored");
        } else {
            std::vector<std::string> new_paths;
            bool bad = false;
            for (const auto& p : j["watch_paths"]) {
                if (!p.is_string()) {
                    LOG_WARN("[HB-HR] hot-reload: watch_paths entry not a string, ignored");
                    bad = true;
                    break;
                }
                std::string s = p.get<std::string>();
                if (s.size() > 512) {
                    LOG_WARN("[HB-HR] hot-reload: watch_paths entry too long (>"
                             << 512 << "), ignored");
                    bad = true;
                    break;
                }
                new_paths.push_back(std::move(s));
            }
            if (!bad) {
                if (new_paths.size() > 64) {
                    LOG_WARN("[HB-HR] hot-reload: watch_paths has " << new_paths.size()
                             << " entries (>64 max), truncated to 64");
                    new_paths.resize(64);
                }
                r.applied_watch_paths = std::move(new_paths);
                LOG_INFO("[HB-HR] watch_paths: " << r.applied_watch_paths.size()
                         << " path(s) queued for fanotify re-mark");
            }
        }
    }

    // 5. v3.13: journald_exclude_ids (string array, max 64, each id <= 256 chars).
    //   Unlike scan_paths/watch_paths, this does NOT require a collector rebuild.
    //   The JournaldCollector rebuilds its exclude set on every drain (see
    //   JournaldCollector::run). We just mutate cfg.journald_exclude_ids in place;
    //   the new value becomes visible to the collector on its next sd_journal
    //   iteration (<= 1s latency).
    if (j.contains("journald_exclude_ids")) {
        if (!j["journald_exclude_ids"].is_array()) {
            LOG_WARN("[HB-HR] hot-reload: journald_exclude_ids not an array, ignored");
        } else {
            std::vector<std::string> new_ids;
            bool bad = false;
            for (const auto& id : j["journald_exclude_ids"]) {
                if (!id.is_string()) {
                    LOG_WARN("[HB-HR] hot-reload: journald_exclude_ids entry not a string, ignored");
                    bad = true;
                    break;
                }
                std::string s = id.get<std::string>();
                if (s.size() > 256) {
                    LOG_WARN("[HB-HR] hot-reload: journald_exclude_ids entry too long (>"
                             << 256 << "), ignored");
                    bad = true;
                    break;
                }
                new_ids.push_back(std::move(s));
            }
            if (!bad) {
                if (new_ids.size() > 64) {
                    LOG_WARN("[HB-HR] hot-reload: journald_exclude_ids has " << new_ids.size()
                             << " entries (>64 max), truncated to 64");
                    new_ids.resize(64);
                }
                // Apply in place — JournaldCollector reads cfg_ on every drain.
                // T12 audit fix (Bug 1): lock journald_mtx so the
                // assignment can't race with JournaldCollector's
                // iteration. The previous lock-free version could
                // reallocate the vector's buffer mid-iteration, which
                // is use-after-free.
                {
                    std::lock_guard<std::mutex> jl(cfg.journald_mtx);
                    cfg.journald_exclude_ids = new_ids;
                }
                r.applied_journald_exclude_ids = std::move(new_ids);
                LOG_INFO("[HB-HR] journald_exclude_ids: " << r.applied_journald_exclude_ids.size()
                         << " id(s) applied in-place (no rebuild, takes effect on next journald iteration)");
            }
        }
    }

    // 6. anything else: refused, logged once per call
    static const std::set<std::string> kAllowed = {
        "log_level", "heartbeat_interval_sec", "scan_paths", "watch_paths", "journald_exclude_ids"
    };
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (kAllowed.find(it.key()) == kAllowed.end()) {
            LOG_WARN("[HB-HR] hot-reload: key '" << it.key()
                     << "' not hot-reloadable (only log_level, heartbeat_interval_sec, "
                     << "scan_paths, watch_paths, journald_exclude_ids), ignored");
        }
    }
    return r;
}
void load_config(const std::string& config_path, AgentConfig& cfg) {
    std::ifstream f(config_path);
    if (!f) throw std::runtime_error("Cannot open config: " + config_path);
    json j; f >> j;

    cfg.central_url = j.value("central_url", std::string("https://logsoc.anytimeadmin.info"));
    if (!cfg.central_url.empty()&& cfg.central_url.back() == '/') cfg.central_url.pop_back();
    cfg.hostname    = j.value("hostname", std::string());
    // v4.8.0-t4.8.15 (T4.8.15): read version from config.json so /liveness
    // and the heartbeat use the real version instead of the compile-time
    // default "3.20". Allows shipping multiple agent versions from the
    // same binary. Falls back to the hardcoded default if absent.
    cfg.version     = j.value("version", cfg.version);
    if (cfg.hostname.empty()) {
        char buf[256]{};
        gethostname(buf, sizeof(buf));
        cfg.hostname = buf;
    }

    // v3.6: Detect OS info from /etc/os-release + uname
    {
        std::ifstream osf("/etc/os-release");
        std::string line;
        while (std::getline(osf, line)) {
            if (line.find("NAME=") == 0) {
                std::string val = line.substr(5);
                // Strip quotes
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                cfg.os_name = val;
            } else if (line.find("VERSION=") == 0) {
                std::string val = line.substr(8);
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                cfg.os_version = val;
            } else if (line.find("VERSION_ID=") == 0 && cfg.os_version.empty()) {
                // Fallback: use VERSION_ID if VERSION is not set
                std::string val = line.substr(11);
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                cfg.os_version = val;
            }
        }
        // Kernel version and arch from uname
        struct utsname uts;
        if (uname(&uts) == 0) {
            cfg.kernel_version = uts.release;
            cfg.arch = uts.machine;  // e.g. "x86_64", "aarch64"
        }
    }

    // v3.6: Detect non-loopback IP addresses + MAC address
    // Issue #40: store as "interface:IP" pairs so the frontend can display
    // both the interface name and the IP address.
    {
        struct ifaddrs* ifa_list = nullptr;
        if (getifaddrs(&ifa_list) == 0) {
            for (auto* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                if (ifa->ifa_flags & IFF_LOOPBACK) continue;
                std::string iface_name = ifa->ifa_name ? ifa->ifa_name : "";
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    auto* sa4 = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
                    inet_ntop(AF_INET, &sa4->sin_addr, ip, sizeof(ip));
                    cfg.ip_addresses.push_back(iface_name + ":" + ip);
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    char ip6[INET6_ADDRSTRLEN];
                    auto* sa6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
                    inet_ntop(AF_INET6, &sa6->sin6_addr, ip6, sizeof(ip6));
                    cfg.ip_addresses.push_back(iface_name + ":" + ip6);
                } else if (ifa->ifa_addr->sa_family == AF_PACKET && cfg.mac.empty()) {
                    // v3.6: MAC address from packet family (first non-lo interface)
                    auto* sll = reinterpret_cast<sockaddr_ll*>(ifa->ifa_addr);
                    if (sll->sll_halen == 6) {
                        char mac_buf[18];
                        std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                            (unsigned char)sll->sll_addr[0], (unsigned char)sll->sll_addr[1],
                            (unsigned char)sll->sll_addr[2], (unsigned char)sll->sll_addr[3],
                            (unsigned char)sll->sll_addr[4], (unsigned char)sll->sll_addr[5]);
                        // Skip all-zero MACs
                        if (std::string(mac_buf) != "00:00:00:00:00:00") {
                            cfg.mac = mac_buf;
                        }
                    }
                }
            }
            // Fallback: if no MAC from getifaddrs, try /sys/class/net/<iface>/address
            if (cfg.mac.empty()) {
                for (auto* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr) continue;
                    if (ifa->ifa_flags & IFF_LOOPBACK) continue;
                    std::string path = "/sys/class/net/" + std::string(ifa->ifa_name) + "/address";
                    std::ifstream mf(path);
                    if (mf) {
                        std::string m;
                        std::getline(mf, m);
                        // Trim trailing whitespace
                        while (!m.empty() && (m.back() == '\n' || m.back() == '\r'))
                            m.pop_back();
                        if (!m.empty() && m != "00:00:00:00:00:00") {
                            cfg.mac = m;
                            break;
                        }
                    }
                }
            }
            freeifaddrs(ifa_list);
        }
    }

    // v3.6: CPU model from /proc/cpuinfo
    {
        std::ifstream cf("/proc/cpuinfo");
        std::string line;
        while (std::getline(cf, line)) {
            // x86: "model name : ..."
            if (line.find("model name") == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    cfg.cpu_model = line.substr(pos + 2);
                    break;
                }
            }
            // ARM: "Processor : ..."
            if (line.find("Processor") == 0 && cfg.cpu_model.empty()) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    cfg.cpu_model = line.substr(pos + 2);
                }
            }
        }
    }

    // v3.6: Memory MB from /proc/meminfo
    {
        std::ifstream mf("/proc/meminfo");
        std::string line;
        while (std::getline(mf, line)) {
            if (line.find("MemTotal:") == 0) {
                // MemTotal: 16384000 kB
                long mem_kb = 0;
                std::istringstream iss(line.substr(9));
                iss >> mem_kb;
                cfg.memory_mb = static_cast<int>(mem_kb / 1024);
                break;
            }
        }
    }

    // v3.6: Disk GB from statvfs("/")
    {
        struct statvfs vfs;
        if (statvfs("/", &vfs) == 0) {
            uint64_t total_bytes = static_cast<uint64_t>(vfs.f_blocks) * vfs.f_frsize;
            cfg.disk_gb = static_cast<int>(total_bytes / (1024ULL * 1024ULL * 1024ULL));
        }
    }

    // Log detected host info at startup
    {
        std::string ip_list;
        for (size_t i = 0; i < cfg.ip_addresses.size(); ++i) {
            if (i > 0) ip_list += ", ";
            ip_list += cfg.ip_addresses[i];
        }
        LOG_INFO("[*] Host info: OS=" << cfg.os_name << " " << cfg.os_version
                 << ", Arch=" << cfg.arch
                 << ", Kernel=" << cfg.kernel_version
                 << ", IP=" << ip_list
                 << ", MAC=" << cfg.mac
                 << ", CPU=" << cfg.cpu_model
                 << ", Memory=" << cfg.memory_mb << "MB"
                 << ", Disk=" << cfg.disk_gb << "GB");
    }
    cfg.batch_interval_sec = j.value("batch_interval_sec", 30);
    cfg.batch_max_lines    = j.value("batch_max_lines", 500);
    cfg.hmac_window_sec    = j.value("hmac_window_sec", 60);
    // T14.1 — H-06 opt-in nonce flag. Read from the top-level
    // config.json (not a nested `hmac` object since the rest of the
    // HMAC config isn't nested either). Default false for backward
    // compat. When the central team supports it, the operator
    // sets "hmac_nonce_enabled": true in config.json.
    cfg.hmac_nonce_enabled = j.value("hmac_nonce_enabled", false);
    // T14.0b — coalescing opt-in. Read from top-level config (not
    // a nested object). Default false for backward compat. Operator
    // sets "coalesce_enabled": true when ready to accept the merged
    // event format.
    cfg.coalesce_enabled = j.value("coalesce_enabled", false);
    cfg.coalesce_max_pids = j.value("coalesce_max_pids", 20);
    // T14.0f — per-event-type priority. Default off (events are
    // drained in arrival order). Operator can enable to ship
    // FIM/execve/unlink BEFORE journald/scan even when the buffer
    // is full. See ~/.hermes/tickets/T14.0f.
    cfg.priority_enabled = j.value("priority_enabled", false);
    // T14.0d — partial-success semantics. Default off (the central
    // doesn't emit 207 yet). Operator enables when central Multi-Status
    // support lands.
    cfg.partial_success_enabled = j.value("partial_success_enabled", false);

    // Log level: 0=ERROR, 1=WARN, 2=INFO(default), 3=VERBOSE, 4=DEBUG, 5=TRACE
    if (j.contains("log_level")) g_log_level = j["log_level"].get<int>();

    if (j.contains("scan_paths") && j["scan_paths"].is_array()) {
        for (const auto& p : j["scan_paths"])
            if (p.is_string()) cfg.scan_paths.push_back(p.get<std::string>());
    }
    // v3.7.0: AppCollector — read log files, not bind sockets.
    // Default scan_paths is empty (was previously /var/log/auth.log + /var/log/syslog which
    // are already covered by journald). AppCollector is opt-in.
    cfg.app_collector_enabled = j.value("app_collector_enabled", false);
    // Legacy field kept for backward compat — no longer used by the code:
    cfg.syslog_socket_path = j.value("syslog_socket_path", std::string(""));

    if (j.contains("storage")) {
        auto& s = j["storage"];
        if (s.contains("directory")) cfg.fallback_wal_dir = s["directory"].get<std::string>();
        if (s.contains("in_memory_buffer_capacity"))
            cfg.in_memory_buffer_capacity = s["in_memory_buffer_capacity"].get<size_t>();
    }

    cfg.data_dir = j.value("data_dir", std::string());

    // v3.1: options réseau
    if (j.contains("network")) {
        auto& n = j["network"];
        cfg.module_network = j.value("module_network", false);
        if (n.contains("interfaces") && n["interfaces"].is_array()) {
            for (const auto& i : n["interfaces"])
                if (i.is_string()) cfg.net_cfg.interfaces.push_back(i.get<std::string>());
        }
        if (n.contains("bpf_filter"))      cfg.net_cfg.bpf_filter      = n["bpf_filter"].get<std::string>();
        if (n.contains("snaplen"))         cfg.net_cfg.snaplen         = n["snaplen"].get<int>();
        if (n.contains("batch_interval_ms"))cfg.net_cfg.batch_interval_ms= n["batch_interval_ms"].get<int>();
        if (n.contains("payload_preview_bytes")) cfg.net_cfg.payload_preview_bytes = n["payload_preview_bytes"].get<int>();
    }
    // Extra options (pass-through du config.json local)
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (it.value().is_string() || it.value().is_number_integer() || it.value().is_boolean())
            cfg.extra_options[it.key()] = it.value().dump();
    }

    // v3.2: eBPF option
    if (j.contains("module_ebpf")) {
        cfg.module_ebpf = j.value("module_ebpf", false);
    } else {
        cfg.module_ebpf = ebpf::kernel_ok();
        if (cfg.module_ebpf && getuid() != 0) {
            LOG_WARN("[Config] auto-detect: kernel supports eBPF, but not root (UID="
                      << getuid() << ") - disabling eBPF, fallback to file collectors");
            cfg.module_ebpf = false;
        }
        LOG_VERBOSE("[Config] module_ebpf not set, auto-detect: "
                  << (cfg.module_ebpf ? "enabled" : "disabled")
                  << " (" << ebpf::kernel_reason() << ")");
    }
    // T13.4: XDP SYN scan detector (optional, off by default).
    // Only meaningful when module_ebpf is also enabled (it needs the
    // eBPF verifier path + CAP_NET_ADMIN for XDP attach).
    if (j.contains("xdp") && j["xdp"].is_object()) {
        const auto& x = j["xdp"];
        cfg.enable_xdp_scan = x.value("enabled", false);
        cfg.xdp_interface   = x.value("interface", "");
        // If interface is empty, try to auto-detect eth0 / first non-lo NIC
        if (cfg.enable_xdp_scan && cfg.xdp_interface.empty()) {
            // Simple scan: find first NIC that's UP and not lo
            struct ifaddrs* ifaddr = nullptr;
            if (getifaddrs(&ifaddr) == 0 && ifaddr) {
                for (auto* p = ifaddr; p != nullptr; p = p->ifa_next) {
                    if (!p->ifa_name || !p->ifa_flags) continue;
                    if (std::string(p->ifa_name) == "lo") continue;
                    if (p->ifa_flags & IFF_UP && p->ifa_flags & IFF_RUNNING) {
                        cfg.xdp_interface = p->ifa_name;
                        break;
                    }
                }
                freeifaddrs(ifaddr);
            }
            if (cfg.xdp_interface.empty()) {
                LOG_WARN("[T13.4] enable_xdp_scan=true but no suitable interface "
                         "found (no UP & RUNNING NIC other than lo). Disabling.");
                cfg.enable_xdp_scan = false;
            } else {
                LOG_INFO("[T13.4] auto-detected XDP interface: " << cfg.xdp_interface);
            }
        }
        // XDP needs root for CAP_NET_ADMIN
        if (cfg.enable_xdp_scan && getuid() != 0) {
            LOG_WARN("[T13.4] enable_xdp_scan=true but not root — XDP attach will fail. "
                     "Disabling.");
            cfg.enable_xdp_scan = false;
        }
    }
    // v3.10.0: YARA HQ option
    if (j.contains("yara") && j["yara"].is_object()) {
        const auto& y = j["yara"];
        cfg.yara_enabled = y.value("enabled", false);
        cfg.yara_scan_flags = y.value("scan_flags", 1);  // bitmask: 1=file, 2=memory, 4=network, 8=logs
        cfg.yara_max_scan_file_mb = y.value("max_scan_file_mb", 10);
        cfg.yara_max_rule_size_kb = y.value("max_rule_size_kb", 64);
        cfg.yara_match_post_interval_sec = y.value("match_post_interval_sec", 30);
        cfg.yara_scan_timeout_ms = y.value("scan_timeout_ms", 5000);
        cfg.yara_rule_pull_interval_sec = y.value("rule_pull_interval_sec", 300);
        // v3.17.0 (T61.1): bound the compile wall time. 0 = unbounded.
        cfg.yara_max_compile_ms = y.value("max_compile_ms", 30000);
        // v3.15 (T59): YARA content fetch — ship suspicious file content to
        // central. Off by default (the FanotifyCollector still ships its
        // events to the central event log normally).
        cfg.yara_ship_content = y.value("ship_content", false);
        cfg.yara_ship_max_file_size = y.value("ship_max_file_size", 4 * 1024 * 1024);
        cfg.yara_ship_heuristic_threshold = y.value("ship_heuristic_threshold", 3);
        // T12.16: ship_metrics_port ignored (HTTP metrics server removed).
    }
    // v4.8.0 (T4.8): FIM engine feature flag + knobs
    cfg.fim_engine = j.value("fim_engine", cfg.fim_engine);
    if (cfg.fim_engine != "v5_simplified" && cfg.fim_engine != "v4_duplex") {
        LOG_WARN("[Config] fim_engine=\"" << cfg.fim_engine << "\" is unknown; defaulting to v5_simplified");
        cfg.fim_engine = "v5_simplified";
    }
    if (j.contains("fim_pipeline") && j["fim_pipeline"].is_object()) {
        const auto& fp = j["fim_pipeline"];
        cfg.fim_fd_worker_count = fp.value("fd_worker_count", cfg.fim_fd_worker_count);
        cfg.fim_ship_queue_capacity = fp.value("ship_queue_capacity", cfg.fim_ship_queue_capacity);
        cfg.fim_rate_limit_per_pid_per_sec = fp.value("rate_limit_per_pid_per_sec", cfg.fim_rate_limit_per_pid_per_sec);
        cfg.fim_cb_state_file = fp.value("cb_state_file", cfg.fim_cb_state_file);
        // v4.8.0 (T4.8.8): poller fallback interval. watch_paths is loaded
        // separately from fim.watch_paths (see top-level parsing).
        cfg.fim_poll_interval_sec = fp.value("poll_interval_sec", cfg.fim_poll_interval_sec);
        // T12.16: FIM metrics_port ignored (HTTP metrics server removed).
    }
    // v3.3.10: severity mapping from config (override defaults)
    if (j.contains("severity_map") && j["severity_map"].is_object()) {
        for (auto it = j["severity_map"].begin(); it != j["severity_map"].end(); ++it) {
            if (it.value().is_string()) {
                cfg.severity_map[it.key()] = it.value().get<std::string>();
            }
        }
    }
    // v3.4: journald module
    cfg.module_journald = j.value("module_journald", true);
    // v3.10.1: FanotifyCollector opt-in
    cfg.fanotify_enabled = j.value("fanotify_enabled", false);
    if (j.contains("journald_exclude_ids") && j["journald_exclude_ids"].is_array()) {
        cfg.journald_exclude_ids.clear();
        for (const auto& id : j["journald_exclude_ids"])
            if (id.is_string()) cfg.journald_exclude_ids.push_back(id.get<std::string>());
    }
    // v3.4: eBPF probe enable/disable (override defaults)
    if (j.contains("enabled_probes") && j["enabled_probes"].is_object()) {
        // T30.3: snapshot the previous map so we can detect a change
        // and trigger a hot-reload of the eBPF links (destroy + reattach).
        auto prev = cfg.enabled_probes;
        for (auto it = j["enabled_probes"].begin(); it != j["enabled_probes"].end(); ++it) {
            if (it.value().is_boolean()) {
                cfg.enabled_probes[it.key()] = it.value().get<bool>();
            }
        }
        // Detect drift and rebuild if eBPF is already initialized.
        // We do this in load_config() rather than apply_config_update()
        // because load_config() is the canonical point where the central
        // policy (every 5 min) merges with the local config; the hot-
        // reload thread (heartbeat) and the bootstrap thread both call
        // through this path.
        if (ebpf::kernel_ok() && !prev.empty() && prev != cfg.enabled_probes) {
            // T13.8 A-17: guard against calling rebuild before eBPF init
            if (!ebpf::is_initialized()) {
                LOG_WARN("[T30.3] enabled_probes changed but eBPF not initialized — skipping rebuild");
            } else {
                LOG_INFO("[T30.3] enabled_probes changed — rebuilding eBPF links");
                // 1. Update the in-loader map (used by is_probe_enabled)
                ebpf::set_enabled_probes(cfg.enabled_probes);
                // 2. Destroy + reattach the kernel links
                int attached = ebpf::rebuild_ebpf_probes();
                LOG_INFO("[T30.3] rebuild done: " << attached << " probes attached");
            }
        }
    }
    // v3.5: local_filters (spec v4.1: connect, execve, open, unlink filters)
    if (j.contains("local_filters") && j["local_filters"].is_object()) {
        auto& lf = j["local_filters"];
        if (lf.contains("connect") && lf["connect"].is_object()) {
            auto& conn = lf["connect"];
            if (conn.contains("ignore_ports") && conn["ignore_ports"].is_array()) {
                for (const auto& v : conn["ignore_ports"])
                    if (v.is_string()) cfg.local_filters.connect_ignore_ports.push_back(v.get<std::string>());
            }
            if (conn.contains("ignore_ips") && conn["ignore_ips"].is_array()) {
                for (const auto& v : conn["ignore_ips"])
                    if (v.is_string()) {
                        std::string ip_str = v.get<std::string>();
                        // L-03 audit fix: validate CIDR/IP format at load time.
                        // Accept: a.b.c.d or a.b.c.d/n (with n in 0..32).
                        // Reject: malformed strings (logged as WARN, not added).
                        auto slash = ip_str.find('/');
                        if (slash != std::string::npos) {
                            // CIDR format: validate IP part and prefix length
                            std::string network_str = ip_str.substr(0, slash);
                            unsigned int a, b, c, d;
                            if (std::sscanf(network_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4
                                || a > 255 || b > 255 || c > 255 || d > 255) {
                                LOG_WARN("[Config] invalid CIDR IP ignored: " << ip_str);
                                continue;
                            }
                            try {
                                int prefix = std::stoi(ip_str.substr(slash + 1));
                                if (prefix < 0 || prefix > 32) {
                                    LOG_WARN("[Config] invalid CIDR prefix ignored: " << ip_str);
                                    continue;
                                }
                            } catch (...) {
                                LOG_WARN("[Config] invalid CIDR prefix ignored: " << ip_str);
                                continue;
                            }
                        } else {
                            // Plain IP: validate octets
                            unsigned int a, b, c, d;
                            if (std::sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4
                                || a > 255 || b > 255 || c > 255 || d > 255) {
                                LOG_WARN("[Config] invalid IP filter ignored: " << ip_str);
                                continue;
                            }
                        }
                        cfg.local_filters.connect_ignore_ips.push_back(std::move(ip_str));
                    }
            }
        }
        if (lf.contains("execve") && lf["execve"].is_object()) {
            auto& ex = lf["execve"];
            if (ex.contains("ignore_comm") && ex["ignore_comm"].is_array()) {
                for (const auto& v : ex["ignore_comm"])
                    if (v.is_string()) cfg.local_filters.execve_ignore_comm.push_back(v.get<std::string>());
            }
        }
        if (lf.contains("open") && lf["open"].is_object()) {
            auto& op = lf["open"];
            if (op.contains("ignore_paths") && op["ignore_paths"].is_array()) {
                for (const auto& v : op["ignore_paths"])
                    if (v.is_string()) {
                        // M-12: normalize trailing slashes
                        std::string p = v.get<std::string>();
                        while (!p.empty() && p.back() == '/' && p.size() > 1) p.pop_back();
                        cfg.local_filters.open_ignore_paths.push_back(std::move(p));
                    }
            }
            if (op.contains("ignore_flags") && op["ignore_flags"].is_array()) {
                for (const auto& v : op["ignore_flags"])
                    if (v.is_string() && v.get<std::string>() == "O_RDONLY")
                        cfg.local_filters.open_ignore_rdonly = true;
            }
        }
        if (lf.contains("unlink") && lf["unlink"].is_object()) {
            auto& ul = lf["unlink"];
            if (ul.contains("ignore_paths") && ul["ignore_paths"].is_array()) {
                for (const auto& v : ul["ignore_paths"])
                    if (v.is_string()) {
                        // M-12: normalize trailing slashes
                        std::string p = v.get<std::string>();
                        while (!p.empty() && p.back() == '/' && p.size() > 1) p.pop_back();
                        cfg.local_filters.unlink_ignore_paths.push_back(std::move(p));
                    }
            }
        }
    }
    // v3.5: FIM configuration (spec v4.1: fim section)
    if (j.contains("fim") && j["fim"].is_object()) {
        auto& fim = j["fim"];
        if (fim.contains("watch_paths") && fim["watch_paths"].is_array()) {
            for (const auto& v : fim["watch_paths"])
                if (v.is_string()) cfg.fim.watch_paths.push_back(v.get<std::string>());
        }
        if (fim.contains("ignore_paths") && fim["ignore_paths"].is_array()) {
            for (const auto& v : fim["ignore_paths"])
                if (v.is_string()) {
                    // M-12: normalize by stripping trailing slash so
                    // /tmp/foo/ matches /tmp/foo during prefix comparison.
                    std::string p = v.get<std::string>();
                    while (!p.empty() && p.back() == '/' && p.size() > 1) p.pop_back();
                    cfg.fim.ignore_paths.push_back(std::move(p));
                }
        }
    }
    // T64.2.1 (v3.20.0): local policy parsing. These are FALLBACKS only;
    // they get overwritten by pull_policy_from_central() every 5 min.
    // Reading from config.json keeps the agent usable if the central
    // is unreachable (network down, HMAC invalid, etc.).
    if (j.contains("policy") && j["policy"].is_object()) {
        const auto& p = j["policy"];
        // T12.16: metrics_bind_address ignored (HTTP metrics server removed).
        if (p.contains("fim_watch_paths") && p["fim_watch_paths"].is_array()) {
            cfg.policy.fim_watch_paths.clear();
            for (const auto& v : p["fim_watch_paths"])
                if (v.is_string()) cfg.policy.fim_watch_paths.push_back(v.get<std::string>());
        }
        if (p.contains("ship_heuristic_threshold") && p["ship_heuristic_threshold"].is_number_integer()) {
            int t = p["ship_heuristic_threshold"].get<int>();
            if (t < 0) t = 0;
            if (t > 10) t = 10;
            cfg.policy.ship_heuristic_threshold = t;
        }
        cfg.policy.source = "local";
        LOG_INFO("[Policy] loaded from local config.json: watch_paths=" << cfg.policy.fim_watch_paths.size()
                 << " threshold=" << cfg.policy.ship_heuristic_threshold);
    } else {
        // No policy section in config.json: derive defaults from existing fields
        // (backward compat: fim.watch_paths already loaded into cfg.fim)
        cfg.policy.fim_watch_paths = cfg.fim.watch_paths;
        cfg.policy.source = "default";
        LOG_INFO("[Policy] no policy section in config.json, using defaults: "
                 << "watch_paths=" << cfg.policy.fim_watch_paths.size());
    }
    // v3.5: eBPF rate limit (spec v4.1: ebpf.rate_limit_per_pid)
    if (j.contains("ebpf") && j["ebpf"].is_object()) {
        auto& ebpf = j["ebpf"];
        if (ebpf.contains("rate_limit_per_pid"))
            cfg.ebpf_rate_limit = ebpf.value("rate_limit_per_pid", 100u);
        if (ebpf.contains("redact_patterns") && ebpf["redact_patterns"].is_array()) {
            for (const auto& v : ebpf["redact_patterns"])
                if (v.is_string()) cfg.redact_patterns.push_back(v.get<std::string>());
        }
    }
    // v3.5: heartbeat interval (spec v4.1: heartbeat.interval_sec)
    if (j.contains("heartbeat") && j["heartbeat"].is_object()) {
        cfg.heartbeat_interval_sec = j["heartbeat"].value("interval_sec", 60);
        if (cfg.heartbeat_interval_sec < 10) cfg.heartbeat_interval_sec = 10;  // minimum 10s
    }
}

/* ─── Key derivation (v3.8.0: from wal_fallback_key) ─── */
struct DerivedKeys {
    std::vector<uint8_t> aes_key;
    std::vector<uint8_t> hmac_key;
};

DerivedKeys derive_keys(const std::string& fallback_key) {
    // v3.8.0: derive aes_key from wal_fallback_key (or wal_secret for legacy compat)
    std::vector<uint8_t> salt_aes  = {'L','O','G','S','O','C','_','F','W','A','L','_','v','3','_','a','e','s'};
    DerivedKeys dk;
    dk.aes_key  = crypto::derive_key(fallback_key, salt_aes, 32);
    // HMAC key is still derived from hmac_secret (passed in creds, not from this)
    return dk;
}

/* ─── UUID gen ─── */
std::string gen_uuid() { return uuid::generate(); }

/* ─── HTTP discard ─── */
static size_t discard_write(void*, size_t size, size_t nmemb, void*) { return size * nmemb; }

/* ─── Sender thread (v3.8.0: InMemoryBuffer + FallbackWAL; T13: WAL is a
   child process owned by WalWriterProcess — the Sender talks to the
   child over a SEQPACKET socketpair, so the signature is unchanged
   except for the fwal type, which is now wal_writer::WalWriterProcess). */
class Sender {
public:
    Sender(const AgentConfig& cfg,
           InMemoryBuffer<std::string>& buf, wal_writer::WalWriterProcess& fwal,
           const runtime_cred::RuntimeCredentials& cred, const std::string& config_dir)
        : cfg_(cfg), buf_(buf), fwal_(fwal), cred_(cred), config_dir_(config_dir) {}

    void start() { thread_ = std::thread([=]() { run(); }); }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

private:
    const AgentConfig& cfg_;
    InMemoryBuffer<std::string>& buf_;
    wal_writer::WalWriterProcess& fwal_;   // T13: child-process-backed WAL
    const runtime_cred::RuntimeCredentials& cred_;
    const std::string config_dir_;
    std::atomic<bool> running_{true};
    std::thread thread_;
    int consecutive_403_404_ = 0;
    int consecutive_failures_ = 0;   // backoff counter for any send failure
    // T14.0c — dedup cache. (event_type + path + pid) hashes seen in
    // the last 60s window. The Sender filters out duplicates right
    // before send_batch() so we don't burn bandwidth on the central.
    // Set + queue = O(1) insert + O(K) eviction where K = entries
    // that aged out in this cycle. Bounded by ~max_unique_per_minute,
    // which on a busy agent is ~10k. 60s window means the dedup TTL
    // matches the central's HMAC replay window, so the operator's
    // mental model is consistent: "if the same thing happens twice
    // within a minute, it's the same event".
    //
    // NOT thread-safe by design: the dedup state is owned by the
    // Sender thread, only it reads/writes it. The senders' pop_batch
    // is the only place we touch this, so no mutex needed.
    std::unordered_set<std::string> dedup_set_;
    std::deque<std::pair<std::string, std::chrono::steady_clock::time_point>> dedup_queue_;
    // T13.10 atomic_unique_ptr (defense-in-depth on ebpf_ptr) + T14.0 H-03
    // sender batcher (1-lock drain via pop_batch instead of N-lock loop).
    // See ~/.hermes/tickets/T13.10 + T14.0.
    // T14.1 — H-06 prep: monotonic counter for HMAC nonce. Each
    // send_batch() call increments this, converts to string, and passes
    // it to compute_ingest_hmac. The central will dedup nonces via
    // Redis SET (TTL 60s) when the R3 backend work lands. Until then,
    // the central ignores the X-Nonce header (zero behavior change).
    // uint64 → no wraparound for 584,554 years at 1 nonce/ms.
    std::atomic<uint64_t> nonce_counter_{0};
    // T14.0e — adaptive batch size. EMA of observed central latency in
    // microseconds. Used to scale batch_max_lines dynamically:
    //   latency < 100ms  → batch_max = 1000
    //   latency 100-500  → batch_max = 500  (default, == cfg_.batch_max_lines)
    //   latency 500-2000 → batch_max = 200
    //   latency > 2000  → batch_max = 100  (degraded mode)
    // Start at 200ms (assumes "normal" central). EMA factor 0.2 = new
    // sample has 20% weight, history 80% — slow to react, no oscillation.
    std::atomic<int64_t> avg_latency_us_{200000};

    void run() {
        // v3.9.7: adaptive delay based on buffer pressure.
        // - 5s when idle (buffer < 100)
        // - scales down to 100ms when buffer is full (drain fast)
        // - exponential backoff (5s → 60s) when API is failing
        // Old tight-loop (1 event per 110ms HTTP) was WORSE than 5s sleep (50 events per 5s).
        // Lesson: HTTP latency dominates, batch up before sending.
        while (running_) {
            if (consecutive_failures_ > 0) {
                // Exponential backoff
                int fail_delay = std::min(5 * (1 << std::min(consecutive_failures_, 3)), 60);
                std::this_thread::sleep_for(std::chrono::seconds(fail_delay));
            } else {
                // Pressure-based delay: full buffer → 100ms, empty → 5s
                size_t cur = buf_.size();
                size_t cap = buf_.capacity();
                double pressure = (cap > 0) ? static_cast<double>(cur) / static_cast<double>(cap) : 0.0;
                int delay_ms;
                if (cur == 0) {
                    delay_ms = 5000;  // idle
                } else if (pressure < 0.10) {
                    delay_ms = 3000;  // light load
                } else if (pressure < 0.50) {
                    delay_ms = 1000;  // moderate
                } else if (pressure < 0.90) {
                    delay_ms = 300;   // heavy
                } else {
                    delay_ms = 100;   // critical, drain NOW
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            }

            // Priority 1: drain InMemoryBuffer up to batch_max_lines
            // T14.0 — H-03: use pop_batch() (1 lock) instead of
            // pop() in a while loop (N locks). Asymmetric with the
            // FallbackWAL pop_batch() call below, which already drained
            // N events in 1 syscall. This was the throughput cap.
            // T14.0e — adaptive batch size. Use the EMA of central
            // latency to scale batch_max_lines. Read once per cycle
            // (atomic load). Bounded between 50 and 2000 to avoid
            // pathological cases (super-low central latency shouldn't
            // push 100k events in one HTTP call; super-high latency
            // shouldn't drop below 50 because then the agent starves
            // the central of throughput during partial outage).
            size_t effective_batch_max = adaptive_batch_size(avg_latency_us_.load());
            std::vector<std::string> batch = buf_.pop_batch(effective_batch_max);

            // T14.0f — per-event-type priority. If the operator
            // opted in, partition the drained batch by event_type
            // into 3 tiers and reorder so high-priority ships first.
            // Drains MORE than effective_batch_max (we over-drain to
            // ensure high-priority events aren't stuck behind low-
            // priority ones in the buffer), then trims back down to
            // effective_batch_max for the actual HTTP call.
            if (cfg_.priority_enabled && !batch.empty()) {
                batch = reorder_by_priority(std::move(batch));
                if (batch.size() > effective_batch_max) {
                    // The over-drained events go BACK to the front of
                    // the buffer. push() is blocking, but in practice
                    // the buffer has space (we just popped N, so
                    // there's N free slots available).
                    for (size_t i = effective_batch_max; i < batch.size(); ++i) {
                        buf_.push(std::move(batch[i]));
                    }
                    batch.resize(effective_batch_max);
                }
            }

            // Priority 2: drain FallbackWAL if buffer is empty
            bool from_fallback = false;
            if (batch.empty()) {
                auto fwal_events = fwal_.pop_batch(effective_batch_max);
                for (auto& ev : fwal_events) {
                    batch.push_back(std::move(ev.raw_event));
                }
                from_fallback = !fwal_events.empty();
            }

            if (batch.empty()) continue;  // Nothing to send

            // T14.0c — dedup filter. Walks the batch, drops events whose
            // (type, path, pid) hash is already in the 60s window. The
            // window is auto-evicted (entries older than 60s removed
            // before the filter runs, so the set stays bounded).
            const size_t before_count = batch.size();
            batch = dedup_filter(std::move(batch));
            const size_t after_count = batch.size();
            if (before_count != after_count) {
                LOG_INFO("[SENDER] dedup: " + std::to_string(before_count - after_count)
                         + " duplicates dropped in this batch");
            }

            if (batch.empty()) continue;  // All dupes — skip the HTTP call

            // T14.0b — event coalescing. If the operator opted in,
            // group N events with the same (event_type, path) into
            // a single merged event. Default off. The dedup runs
            // FIRST so coalescing doesn't have to handle events that
            // were going to be dropped anyway.
            if (cfg_.coalesce_enabled) {
                const size_t before_coal = batch.size();
                batch = coalesce_filter(std::move(batch));
                const size_t after_coal = batch.size();
                if (before_coal != after_coal) {
                    LOG_INFO("[SENDER] coalesce: " + std::to_string(before_coal)
                             + " events merged into " + std::to_string(after_coal));
                }
            }
            if (batch.empty()) continue;  // All merged into nothing (shouldn't happen but safe)

            LOG_INFO("[SENDER] sending batch of " + std::to_string(batch.size())
                        + " events (fallback=" + std::string(from_fallback ? "yes" : "no")
                        + ", adaptive_max=" + std::to_string(effective_batch_max) + ")");

            // T14.0e — measure the central's response time and update the EMA.
            // Only the SUCCESS path updates the EMA: failed sends don't
            // reflect the central's true capacity, they reflect a network
            // glitch or auth issue. Using `std::chrono::steady_clock`
            // (monotonic, not wall-clock) so NTP adjustments don't
            // poison the EMA.
            auto t0 = std::chrono::steady_clock::now();
            bool ok = send_batch(batch);
            auto t1 = std::chrono::steady_clock::now();
            if (ok) {
                int64_t sample_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
                int64_t prev_us = avg_latency_us_.load();
                // EMA: new = 0.2 * sample + 0.8 * prev. Integer math to
                // avoid floats (atomic of double is finicky on some archs).
                int64_t next_us = (sample_us / 5) + (prev_us * 4 / 5);
                // Clamp to [10ms, 30s] to bound the EMA.
                if (next_us < 10000) next_us = 10000;
                if (next_us > 30000000) next_us = 30000000;
                avg_latency_us_.store(next_us);
            }
            if (ok) {
                consecutive_failures_ = 0;
                consecutive_403_404_ = 0;
                // T14.0d — partial-success handling. If the operator
                // opted in AND the central returned 207 Multi-Status,
                // we re-push the entire batch. This is a conservative
                // over-approximation (some events may have succeeded
                // and would be sent again, creating duplicates on the
                // central side, mitigated by the central's existing
                // event_id dedup). A future T14.0d-bis will parse the
                // 207 body to extract just the failed event_ids and
                // re-push those (true partial-success). For now, this
                // is the safe default that doesn't drop any events.
                if (cfg_.partial_success_enabled && last_http_code_ == 207) {
                    LOG_WARN("[SENDER] partial-success (207) detected but body parsing not "
                             "yet implemented — re-pushing entire batch as fallback. "
                             "Set partial_success_enabled=false until body parsing lands.");
                    for (auto& ev : batch) {
                        fwal_.push(std::move(ev));
                    }
                }
            } else {
                for (auto& ev : batch) {
                    fwal_.push(ev);
                }
            }

            // Periodic cleanup of old fallback WAL segments
            fwal_.cleanup_old_segments(3600);
        }
    }

    // T14.0e — adaptive batch size. Static so it can be unit-tested
    // without a Sender instance. Maps an observed latency in microseconds
    // to a target batch size. The thresholds are based on the assumption
    // that central HTTP round-trip should be < 500ms for the
    // 500-events-at-500B baseline (≈250 KB payload). Slower = fewer
    // events per call. Faster = more.
    //
    // 0-99ms:    1000  (central can absorb big batches)
    // 100-499ms:  500  (default, == cfg_.batch_max_lines)
    // 500-1999ms: 200  (slowing down)
    // 2000ms+:    100  (degraded, agent in backoff mode anyway)
    static size_t adaptive_batch_size(int64_t latency_us) {
        if (latency_us < 100000)  return 1000;
        if (latency_us < 500000)  return 500;
        if (latency_us < 2000000) return 200;
        return 100;
    }

    // T14.0f — priority reorder. Static for unit testing. Reads the
    // event_type of each event and assigns it to a tier:
    //   HIGH (0):   fim, execve, unlink, write  (security-critical)
    //   MED  (1):   open, tcp_connect, connect  (interesting but not always)
    //   LOW  (2):   journald, scan, everything else (background)
    // Returns a vector where all tier 0 events come first, then tier 1,
    // then tier 2. Within a tier, original order is preserved (FIFO).
    static int priority_tier(const std::string& json_line) {
        try {
            auto j = json::parse(json_line);
            std::string et = j.value("event_type", std::string());
            if (et.empty()) et = j.value("type", std::string());
            if (et.empty()) et = j.value("probe", std::string());
            if (et == "fim" || et == "execve" || et == "unlink" || et == "write") return 0;
            if (et == "open" || et == "tcp_connect" || et == "connect") return 1;
            return 2;  // journald, scan, anything else
        } catch (...) {
            return 2;  // unparseable → low priority
        }
    }

    std::vector<std::string> reorder_by_priority(std::vector<std::string> in) {
        if (in.size() <= 1) return in;
        // Stable sort by tier (lower tier = higher priority = earlier).
        // std::stable_sort preserves original order within equal keys.
        std::stable_sort(in.begin(), in.end(), [](const std::string& a, const std::string& b) {
            return priority_tier(a) < priority_tier(b);
        });
        return in;
    }

    // T14.0b — event coalescing. Groups N events with the same
    // (event_type, path) into a single merged event:
    //   { "event_type": "open", "path": "/etc/passwd",
    //     "count": 5, "pids": [1234, 5678, 9012, 3456, 7890] }
    // Only applied if cfg_.coalesce_enabled is true. The merged event
    // has a slightly different JSON shape (count + pids fields) so
    // downstream tools need to know about it. Static for unit testing.
    //
    // Strategy: single pass, build a map<group_key, list of original
    // indices>. group_key = event_type + "|" + path. Then emit one
    // merged event per group, plus the ungrouped events as-is.
    // The pid list is truncated at cfg_.coalesce_max_pids to avoid
    // unbounded payload growth.
    std::vector<std::string> coalesce_filter(std::vector<std::string> in) {
        if (in.empty()) return in;
        // We need the AgentConfig values. They're available via cfg_
        // but coalesce_filter is a non-static member. We are already
        // a member of Sender so cfg_ is accessible.
        std::unordered_map<std::string, std::vector<size_t>> groups;
        std::vector<size_t> singletons;  // indices of events with no group
        for (size_t i = 0; i < in.size(); ++i) {
            std::string key = make_dedup_key(in[i]);
            // Use the same key as dedup (type+path+pid) but group
            // by type+path ONLY (strip the pid part). Easier: extract
            // just the (type, path) part of the dedup key.
            // The dedup key format is "type|path|pid", so split on "|"
            // and take the first 2 fields.
            if (key.empty() || key.find('|') == std::string::npos) {
                singletons.push_back(i);
                continue;
            }
            // Find the second '|' separator
            size_t second = key.find('|', key.find('|') + 1);
            if (second == std::string::npos) {
                singletons.push_back(i);
                continue;
            }
            std::string group_key = key.substr(0, second);
            groups[group_key].push_back(i);
        }
        // Build output. Singletons go first, then merged groups.
        std::vector<std::string> out;
        out.reserve(singletons.size() + groups.size());
        for (size_t i : singletons) {
            out.push_back(std::move(in[i]));
        }
        for (auto& [group_key, indices] : groups) {
            if (indices.size() == 1) {
                // Just one event in this group → no point merging
                out.push_back(std::move(in[indices[0]]));
                continue;
            }
            // Merge: take the first event as the "template", add count + pids
            try {
                auto j = json::parse(in[indices[0]]);
                j["count"] = indices.size();
                json pids = json::array();
                const size_t max_pids = cfg_.coalesce_max_pids;
                for (size_t k = 0; k < indices.size() && k < max_pids; ++k) {
                    auto sub = json::parse(in[indices[k]]);
                    pids.push_back(sub.value("pid", 0));
                }
                j["pids"] = std::move(pids);
                out.push_back(j.dump());
            } catch (...) {
                // parse error → fall back to sending the first one as-is
                // (the others are silently dropped, but dedup would've
                // caught them if they were identical)
                out.push_back(std::move(in[indices[0]]));
            }
        }
        return out;
    }

    // T14.0c — dedup key extractor. Pulls (event_type, path, pid) out of
    // a raw event JSON line. Returns "" if the line isn't valid JSON or
    // doesn't have all 3 fields. The empty return means "don't dedup
    // this event" (safe default — better to send a duplicate than to
    // drop a unique event).
    //
    // Static so it's unit-testable without a Sender instance.
    static std::string make_dedup_key(const std::string& json_line) {
        try {
            auto j = json::parse(json_line);
            // Try common key names (depends on the collector)
            std::string et = j.value("event_type", std::string());
            if (et.empty()) et = j.value("type", std::string());
            if (et.empty()) et = j.value("probe", std::string());
            std::string path = j.value("path", std::string());
            if (path.empty()) path = j.value("target", std::string());
            if (path.empty()) path = j.value("file", std::string());
            // pid: can be int or string in the JSON
            std::string pid = j.value("pid_str", std::string());
            if (pid.empty()) {
                try { pid = std::to_string(j.at("pid").get<int>()); }
                catch (...) { pid = "0"; }
            }
            if (et.empty()) return "";  // can't dedup without type
            return et + "|" + path + "|" + pid;
        } catch (...) {
            return "";  // parse error → don't dedup
        }
    }

    // T14.0c — dedup filter. Takes ownership of the input vector,
    // returns a new vector with duplicates removed. Side effect: updates
    // the dedup cache (adds keys for events that survive the filter,
    // evicts keys older than 60s). O(N + K) where N=batch size, K=evicted
    // count (typically 0, max ~1000/min).
    std::vector<std::string> dedup_filter(std::vector<std::string> in) {
        // 1. Evict old entries (older than 60s) from the front of the queue.
        // The queue is ordered by insertion time (FIFO), so the front is
        // the oldest. As long as we evict ALL entries older than now-60s,
        // the invariant holds.
        const auto now = std::chrono::steady_clock::now();
        const auto cutoff = now - std::chrono::seconds(60);
        while (!dedup_queue_.empty() && dedup_queue_.front().second < cutoff) {
            dedup_set_.erase(dedup_queue_.front().first);
            dedup_queue_.pop_front();
        }
        // 2. Filter the input. Each event with a non-empty key that
        //    is ALREADY in the set is dropped. Each event with a
        //    non-empty key NOT in the set is kept AND added to the set.
        //    Events with an empty key (parse error) are always kept.
        std::vector<std::string> out;
        out.reserve(in.size());
        for (auto& ev : in) {
            std::string key = make_dedup_key(ev);
            if (key.empty()) {
                out.push_back(std::move(ev));  // can't dedup, keep
            } else if (dedup_set_.count(key) == 0) {
                dedup_set_.insert(key);
                dedup_queue_.emplace_back(std::move(key), now);
                out.push_back(std::move(ev));
            }
            // else: key already seen in 60s window → drop
        }
        return out;
    }

    // v3.6: utility to join strings with a delimiter
    static std::string join_strings(const std::vector<std::string>& v, const std::string& delim) {
        if (v.empty()) return "";
        std::string r = v[0];
        for (size_t i = 1; i < v.size(); ++i) r += delim + v[i];
        return r;
    }

    // T14.0d — last HTTP code captured by send_batch. Read by the
    // 207 partial-success path in the run() loop. Not atomic: the
    // Sender is single-threaded, only the Sender thread reads/writes.
    long last_http_code_ = 0;

    bool send_batch(const std::vector<std::string>& lines) {
        json payload;
        payload["agent_id"] = cred_.agent_id;  // FastAPI EventIngest requires agent_id in body
        // v3.6: Host-level context (sent once per batch, applies to all lines)
        if (!cfg_.os_name.empty())       payload["os_name"]       = cfg_.os_name;
        if (!cfg_.os_version.empty())    payload["os_version"]    = cfg_.os_version;
        if (!cfg_.kernel_version.empty()) payload["kernel_version"] = cfg_.kernel_version;
        // T38: send compiled-in version, not config.json's version
        payload["agent_version"] = AGENT_VERSION;
        // v3.6: Host IPs (comma-joined for batch-level context)
        if (!cfg_.ip_addresses.empty())  payload["host_ips"] = join_strings(cfg_.ip_addresses, ",");
        payload["lines"] = json::array();
        for (const auto& line : lines) {
            json item;
            item["event_id"]    = gen_uuid();
            item["source_host"] = cfg_.hostname;
            item["severity"]    = "info";  // default unless WAL JSON has it
            // T12.13 (audit Nova C-06): instead of silently truncating the
            // WAL line at 4096 chars, set a `truncated` flag + `orig_len`
            // so the central can see the loss. The truncated slice is
            // still attached as `message` to preserve backward compat.
            constexpr size_t MAX_MSG_LEN = 4096;
            if (line.size() > MAX_MSG_LEN) {
                item["message"]    = line.substr(0, MAX_MSG_LEN);
                item["truncated"]  = true;
                item["orig_len"]   = line.size();
                // T12.13: rate-limit the warning to avoid log flooding on
                // pathological WAL lines. 1 warning per 1000 truncations.
                static std::atomic<uint64_t> trunc_count{0};
                uint64_t c = trunc_count.fetch_add(1) + 1;
                if (c == 1 || c % 1000 == 0) {
                    LOG_WARN("[Sender] WAL message truncated to " << MAX_MSG_LEN
                              << " chars (orig=" << line.size()
                              << ", total truncations since boot=" << c << ")");
                }
            } else {
                item["message"] = line;
            }

            // If the WAL line is JSON with severity/tags, preserve them
            // L-07 audit fix: validate severity against a whitelist.
            // Accepts info/low/medium/high/critical (case-insensitive).
            // Invalid severity values are silently dropped.
            try {
                json wal_event = json::parse(line);
                if (wal_event.contains("severity")) {
                    // T14.5 — extended whitelist to cover syslog RFC 5424
                    // severity levels (debug, info, notice, warning, error,
                    // critical, alert, emergency) AND the simplified
                    // 5-tier levels (info, low, medium, high, critical) used
                    // by the eBPF severity_scorer. The previous whitelist
                    // was too narrow and silently dropped "warning" events
                    // (logged via the [Sender] invalid severity dropped
                    // warning warning), causing them to fall back to the
                    // default "info" severity and lose their priority
                    // signal in the central dashboard.
                    //
                    // All values are normalized to lowercase before
                    // comparison. The list is the union of syslog and the
                    // eBPF tier model — the central can use either.
                    static const std::unordered_set<std::string> valid_sevs = {
                        // eBPF tier (severity_scorer.cpp score_to_severity)
                        "info", "low", "medium", "high", "critical",
                        // syslog RFC 5424 numeric -> name mapping
                        "debug", "notice", "warning", "error", "alert", "emergency"
                    };
                    if (wal_event["severity"].is_string()) {
                        std::string sev = wal_event["severity"].get<std::string>();
                        std::string sev_lower = sev;
                        std::transform(sev_lower.begin(), sev_lower.end(), sev_lower.begin(), ::tolower);
                        if (valid_sevs.count(sev_lower)) {
                            item["severity"] = sev_lower;  // normalized to lowercase
                        } else {
                            // Unknown severity: keep it (forward-compat for
                            // future levels) but log once. Better to ship
                            // an unknown value than to silently coerce.
                            item["severity"] = sev_lower;
                            LOG_WARN("[Sender] unknown severity kept as-is: " << sev);
                        }
                    }
                }
                if (wal_event.contains("service"))
                    item["service"] = wal_event["service"];
                if (wal_event.contains("tags"))
                    item["tags"] = wal_event["tags"];
                if (wal_event.contains("source_host"))
                    item["source_host"] = wal_event["source_host"];
                if (wal_event.contains("event_id"))
                    item["event_id"] = wal_event["event_id"];
                // ── Human-readable fields from collectors ──
                // Extract the actual message (human-readable text)
                if (wal_event.contains("message"))
                    item["message"] = wal_event["message"];
                // Extract raw_message if present
                if (wal_event.contains("raw_message"))
                    item["raw_message"] = wal_event["raw_message"];
                // Extract source_ip (eBPF: "N/A" → replace with first host IPv4)
                if (wal_event.contains("source_ip")) {
                    auto& sip = wal_event["source_ip"];
                    if (sip.is_string() && sip.get<std::string>() == "N/A" && !cfg_.ip_addresses.empty()) {
                        // Use the first IPv4 address — extract from "interface:IP" format (issue #40)
                        std::string first_ip = cfg_.ip_addresses.front();
                        auto colon_pos = first_ip.find(':');
                        if (colon_pos != std::string::npos) first_ip = first_ip.substr(colon_pos + 1);
                        item["source_ip"] = first_ip;
                    } else if (sip.is_string()) {
                        item["source_ip"] = sip.get<std::string>();
                    }
                }
                // Extract event type (fim, open, unlink, connect, execve, etc.)
                if (wal_event.contains("event"))
                    item["event"] = wal_event["event"];
                // Propagate structured context fields for dashboard display
                if (wal_event.contains("comm"))
                    item["comm"] = wal_event["comm"];
                if (wal_event.contains("username"))
                    item["username"] = wal_event["username"];
                if (wal_event.contains("filename"))
                    item["filename"] = wal_event["filename"];
                if (wal_event.contains("dst_ip"))
                    item["dst_ip"] = wal_event["dst_ip"];
                if (wal_event.contains("dst_port"))
                    item["dst_port"] = wal_event["dst_port"];
                if (wal_event.contains("inode"))
                    item["inode"] = wal_event["inode"];
                if (wal_event.contains("pid"))
                    item["pid"] = wal_event["pid"];
                if (wal_event.contains("uid"))
                    item["uid"] = wal_event["uid"];
                // raw_event for forensics
                if (wal_event.contains("raw_event"))
                    item["raw_event"] = wal_event["raw_event"];
                // v3.9.9 — T3 correlation: propagate journald enrichment fields
                if (wal_event.contains("journald_match"))
                    item["journald_match"] = wal_event["journald_match"];
                if (wal_event.contains("journald_message"))
                    item["journald_message"] = wal_event["journald_message"];
                if (wal_event.contains("journald_unit"))
                    item["journald_unit"] = wal_event["journald_unit"];
                if (wal_event.contains("journald_identifier"))
                    item["journald_identifier"] = wal_event["journald_identifier"];

                // ── T14.4 — propagate 16 enrichment fields that were
                // silently dropped by the sender (issue #37, 2026-06-19).
                // The collectors (loader.cpp, fim_poller.cpp, fim_collector.cpp,
                // correlator.hpp) write these into the WAL, but the sender's
                // payload mapping was incomplete. The backend has the
                // corresponding ClickHouse columns (added by workboard card
                // 2a8ea036) but they were stuck at defaults (0, '', []).
                //
                // Each `if (wal_event.contains("X")) item["X"] = ...` block
                // is wrapped in a type check (is_string / is_array / is_number)
                // to avoid type-mismatch exceptions on older WAL lines that
                // might have a different type for the same key.

                // 1. Documented wire-protocol fields (doc/developer-backend.md)
                if (wal_event.contains("argv") && wal_event["argv"].is_array())
                    item["argv"] = wal_event["argv"];
                if (wal_event.contains("action") && wal_event["action"].is_string())
                    item["action"] = wal_event["action"];
                if (wal_event.contains("source") && wal_event["source"].is_string())
                    item["source"] = wal_event["source"];
                if (wal_event.contains("flags") && wal_event["flags"].is_string())
                    item["flags"] = wal_event["flags"];
                if (wal_event.contains("bytes_size") && wal_event["bytes_size"].is_number())
                    item["bytes_size"] = wal_event["bytes_size"];
                if (wal_event.contains("family") && wal_event["family"].is_string())
                    item["family"] = wal_event["family"];
                if (wal_event.contains("sha256") && wal_event["sha256"].is_string())
                    item["sha256"] = wal_event["sha256"];

                // eBPF enrichment fields retirés — le backend (app/enrichment.py) calcule
                // severity_score, mitre, sigma côté serveur. Voir issue SOC-AGENT #40.

                // 3. Coalescing fields (T14.0b opt-in) — the coalesce_filter
                // in Sender produces events with count + pids, but the
                // sender's own payload mapping didn't include them, so
                // they defaulted to 1 and [] on the backend. Now the
                // merged event format is preserved end-to-end.
                if (wal_event.contains("count") && wal_event["count"].is_number())
                    item["count"] = wal_event["count"];
                if (wal_event.contains("pids") && wal_event["pids"].is_array())
                    item["pids"] = wal_event["pids"];

                // 4. Cross-validation eBPF ↔ journald (correlator.hpp)
                // These power the HIDDEN_PROCESS detection: a journald
                // event whose corresponding eBPF event is missing (e.g.
                // a rootkit that suppresses its own auditd/journald log)
                // gets ebpf_match=false so the SOC dashboard can flag it.
                if (wal_event.contains("ebpf_match") && wal_event["ebpf_match"].is_boolean())
                    item["ebpf_match"] = wal_event["ebpf_match"];
                if (wal_event.contains("ebpf_event") && wal_event["ebpf_event"].is_string())
                    item["ebpf_event"] = wal_event["ebpf_event"];
                if (wal_event.contains("ebpf_comm") && wal_event["ebpf_comm"].is_string())
                    item["ebpf_comm"] = wal_event["ebpf_comm"];
                if (wal_event.contains("ebpf_filename") && wal_event["ebpf_filename"].is_string())
                    item["ebpf_filename"] = wal_event["ebpf_filename"];
                if (wal_event.contains("correlation_window_ms") && wal_event["correlation_window_ms"].is_number())
                    item["correlation_window_ms"] = wal_event["correlation_window_ms"];
            } catch (const std::exception& e) {
                // T12.13 (audit Nova C-07): was a silent catch-all. Now
                // we log (rate-limited) + count the error so a flood of
                // malformed WAL lines is visible in metrics. The
                // `keep defaults` behavior (severity="info", no journald
                // fields) is preserved — only the visibility changed.
                static std::atomic<uint64_t> parse_err_count{0};
                uint64_t c = parse_err_count.fetch_add(1) + 1;
                if (c == 1 || c % 1000 == 0) {
                    LOG_WARN("[Sender] WAL line not JSON (parse error #"
                              << c << " since boot): " << e.what()
                              << " — first 64 chars: "
                              << line.substr(0, std::min<size_t>(64, line.size())));
                }
            }

            payload["lines"].push_back(item);
        }
        std::string body = payload.dump();
        auto now = std::chrono::system_clock::now();
        int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        std::string ts_str = std::to_string(ts);
        // T14.1 — H-06 opt-in HMAC nonce. Default: agent does NOT send
        // the X-Nonce header and signs the legacy payload
        // f"{ts}.{body_hash}" (preserves today's behavior, zero risk).
        // Opt-in: the operator sets "hmac_nonce_enabled": true in
        // config.json (AFTER confirming the central accepts the
        // new format). When enabled, the agent increments the
        // monotonic counter, includes the nonce in BOTH the HMAC
        // payload and an X-Nonce header. The flag is the contract
        // between agent and central — they switch together.
        std::string nonce_str;  // empty = opt-out path
        if (cfg_.hmac_nonce_enabled) {
            // fetch_add is the standard atomic increment, returns the
            // post-increment value (so first nonce = 1, not 0).
            nonce_str = std::to_string(nonce_counter_.fetch_add(1, std::memory_order_relaxed));
        }
        std::string hmac_sig = agent_v3::compute_ingest_hmac(cred_.agent_id, cred_.hmac_secret, cred_.central_url, ts_str, body, nonce_str);
        std::string url = cred_.central_url + "/api/v1/events/";

        CURL* curl = curl_easy_init();
        if (!curl) return false;
        struct curl_slist* hdr = nullptr;
        hdr = curl_slist_append(hdr, "Content-Type: application/json");
        hdr = curl_slist_append(hdr, ("X-Agent-Id: " + cred_.agent_id).c_str());
        hdr = curl_slist_append(hdr, ("X-Timestamp: " + ts_str).c_str());
        if (!nonce_str.empty()) {
            // Only sent when opt-in is enabled. The central should
            // ignore unknown headers anyway, but we keep the wire
            // protocol pristine in the default case.
            hdr = curl_slist_append(hdr, ("X-Nonce: " + nonce_str).c_str());
        }
        hdr = curl_slist_append(hdr, ("X-Signature: " + hmac_sig).c_str());
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_write);
        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_slist_free_all(hdr);
        curl_easy_cleanup(curl);
        // v3.9.1: bumped to LOG_INFO for production visibility (was LOG_DEBUG — invisible in default log level)
        LOG_INFO("[SENDER] POST " + cred_.central_url + "/api/v1/events/ => HTTP " + std::to_string(http_code) + " (res=" + std::to_string(res) + ")");

        // T14.0d — capture the HTTP code for the partial-success path.
        // We do NOT capture the response body here (the curl callback
        // is wired up to discard writes for backwards compat with the
        // existing post-processing). The partial-success path will use
        // a future-proofing approach: if the central emits 207, we
        // re-push the entire batch (over-approximation, but safe).
        // A future T14.0d-bis can wire up body capture when the
        // central's 207 contract is finalized.
        last_http_code_ = http_code;

        if (http_code == 403 || http_code == 404) {
            consecutive_403_404_++;
            LOG_WARN("[SENDER] HTTP " << http_code
                      << " (strike " << consecutive_403_404_ << "/3)");
            if (consecutive_403_404_ >= 3) {
                LOG_ERROR("[SENDER] Persistent 403/404 — stopping sender. Admin revoke/del?");
                // ANOM-006: do NOT delete credentials — allow manual recovery / re-approval
                running_ = false;
            }
            return false;
        }

        if (res != CURLE_OK || (http_code != 200 && http_code != 201)) {
            LOG_WARN("[SENDER] HTTP " << http_code << " / curl " << curl_easy_strerror(res));
            consecutive_failures_++;
            return false;
        }

        consecutive_403_404_ = 0;
        consecutive_failures_ = 0;
        return true;
    }
};

/* ─── Collector thread (file tail) — v3.8.0: writes to InMemoryBuffer ─── */
class Collector {
public:
    Collector(const std::string& path, const std::string& name, InMemoryBuffer<std::string>& buf)
        : path_(path), name_(name), buf_(buf) {}

    void start() { thread_ = std::thread([=]() { run(); }); }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

private:
    std::string path_, name_;
    InMemoryBuffer<std::string>& buf_;
    std::atomic<bool> running_{true};
    std::thread thread_;

    void run() {
        LOG_INFO("[+] Collector: " << name_ << " -> " << path_);
        std::ifstream file;
        std::streampos pos = 0;

        auto reopen = [&]() -> bool {
            if (file.is_open()) file.close();
            if (!fs::exists(path_)) return false;
            file.open(path_, std::ios::binary);
            if (!file) return false;
            file.seekg(0, std::ios::end);
            pos = file.tellg();
            return true;
        };
        reopen();

        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (!fs::exists(path_)) { file.close(); continue; }
            if (!file.is_open()) { reopen(); continue; }
            auto sz = static_cast<std::streamoff>(fs::file_size(path_));
            if (sz < pos) { reopen(); continue; }
            if (file.is_open() && sz > pos) {
                file.clear();  // reset eofbit from previous getline loop
                file.seekg(pos);
                std::string line;
                while (std::getline(file, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    if (!line.empty()) {
                        buf_.drop_oldest_if_full(line);
                        LOG_VERBOSE("[COLLECTOR] buf_.push() done for " + name_);
                    }
                }
                // V3.3.1 fix: tellg() returns -1 at EOF; seekg(-1) corrupts stream
                auto new_pos = file.tellg();
                if (new_pos == std::streampos(-1) || new_pos < 0) {
                    pos = sz;
                } else {
                    pos = new_pos;
                }
            }
        }
        if (file.is_open()) file.close();
    }
};

/* ─── AppCollector: reads log files listed in scan_paths (no socket) ─── */
// v3.7.0: Renamed from SyslogCollector. The old version tried to bind() a UNIX
// datagram socket (role: server), which failed with EACCES when running as
// non-root and is the wrong architecture anyway. AppCollector's role is to READ
// log files that do not transit through journald (app access logs, deny logs,
// custom app logs). It is disabled when scan_paths is empty.
class AppCollector {
public:
    AppCollector(const std::string& path, InMemoryBuffer<std::string>& buf)
        : path_(path), buf_(buf) {}

    void start() { thread_ = std::thread([=]() { run(); }); }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

private:
    std::string path_;
    InMemoryBuffer<std::string>& buf_;
    std::atomic<bool> running_{true};
    std::thread thread_;

    void run() {
        LOG_INFO("[+] AppCollector: watching " << path_);

        std::ifstream f;
        long last_pos = 0;
        // Re-open periodically in case of log rotation (inode change)
        auto last_reopen = std::chrono::steady_clock::now();

        while (running_) {
            if (!f.is_open()) {
                f.open(path_, std::ios::binary);
                if (!f.is_open()) {
                    LOG_WARN("[AppCollector] cannot open " << path_ << ", retry in 5s");
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }
                f.seekg(0, std::ios::end);
                last_pos = static_cast<long>(f.tellg());
            }

            // Re-open every 60s (handles rotation: inode change)
            auto now = std::chrono::steady_clock::now();
            if (now - last_reopen > std::chrono::seconds(60)) {
                f.close();
                f.open(path_, std::ios::binary);
                if (f.is_open()) {
                    f.seekg(last_pos);
                } else {
                    last_pos = 0;
                }
                last_reopen = now;
            }

            std::string line;
            while (std::getline(f, line)) {
                last_pos = static_cast<long>(f.tellg());
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                    line.pop_back();
                if (line.empty()) continue;
                buf_.drop_oldest_if_full(line);
            }

            f.clear();  // clear EOF
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (f.is_open()) f.close();
        LOG_INFO("[-] AppCollector stopped (" << path_ << ")");
    }
};

/* ─── JournaldCollector: reads from systemd journal via sd_journal API ─── */
class JournaldCollector {
public:
    JournaldCollector(const AgentConfig& cfg, InMemoryBuffer<std::string>& buf)
        : cfg_(cfg), buf_(buf) {}

    void start() {
#ifdef __linux__
        LOG_INFO("[+] JournaldCollector starting (sd_journal API, PID=" << getpid() << ")");
        thread_ = std::thread([=]() { run(); });
#else
        LOG_WARN("[JournaldCollector] Not available on non-Linux systems");
#endif
    }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
    uint64_t events() const { return events_; }

private:
    const AgentConfig& cfg_;
    InMemoryBuffer<std::string>& buf_;
    std::atomic<bool> running_{true};
    std::thread thread_;
    uint64_t events_{0};

    // Syslog priority → severity string
    static std::string priority_to_severity(int pri) {
        if (pri <= 2) return "critical";   // emerg, alert, crit
        if (pri == 3) return "error";       // err
        if (pri == 4) return "warning";    // warning
        if (pri == 5) return "notice";     // notice
        if (pri == 6) return "info";        // info
        return "debug";                      // debug(7) and unknown
    }

    // Build journald exclude set from config
    // T12 audit fix (Bug 1): snapshot cfg_.journald_exclude_ids
    // under journald_mtx so the assignment from the heartbeat thread
    // (apply_config_update) can't reallocate the vector's buffer
    // while we iterate over it. Use-after-free otherwise.
    std::unordered_set<std::string> build_exclude_set() const {
        std::vector<std::string> ids_copy;
        {
            std::lock_guard<std::mutex> jl(cfg_.journald_mtx);
            ids_copy = cfg_.journald_exclude_ids;
        }
        std::unordered_set<std::string> excl;
        for (const auto& id : ids_copy) {
            excl.insert(id);
        }
        return excl;
    }

    void run() {
#ifdef __linux__
        LOG_INFO("[+] JournaldCollector thread entered (sd_journal API)");

        auto exclude_set = build_exclude_set();
        LOG_INFO("[JournaldCollector] exclude set: " << exclude_set.size() << " identifiers");

        while (running_) {
            sd_journal* j = nullptr;
            int rc = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
            if (rc < 0) {
                LOG_ERROR("[JournaldCollector] sd_journal_open failed: " << strerror(-rc) << " (rc=" << rc << ")");
                std::this_thread::sleep_for(std::chrono::seconds(10));
                continue;
            }
            LOG_INFO("[JournaldCollector] sd_journal_open OK, handle=" << (void*)j
                     << " flags=SD_JOURNAL_LOCAL_ONLY=" << (int)SD_JOURNAL_LOCAL_ONLY
                     << " uid=" << getuid() << " pid=" << getpid());
            std::cerr << std::flush;  // v3.9.3: force flush on socket-bound stderr (was buffered)

            // v3.9.3 — EXTRA DIAGNOSTIC per Nova 2026-06-03:
            // Per Nova's binary tests, SD_JOURNAL_LOCAL_ONLY + previous() should return 1
            // on Hestia. But the agent's runtime shows previous()=0, which means either
            // (a) the journal cursor context is different (namespace/credentials), or
            // (b) the journal really is empty for the agent's process view.
            // We add explicit diagnostic logs to disambiguate.
            sd_journal_seek_tail(j);
            int n_prev = sd_journal_previous(j);  // 1 = on last entry, 0 = empty journal view, <0 = err
            uint64_t last_usec = 0;
            if (n_prev == 1) sd_journal_get_realtime_usec(j, &last_usec);
            time_t last_sec = (time_t)(last_usec / 1000000);
            LOG_INFO("[JournaldCollector] Tail-positioned: previous=" << n_prev
                     << " (1=ok, 0=empty journal view, <0=err)"
                     << ", last_entry_usec=" << last_usec
                     << ", last_entry_time=" << std::ctime(&last_sec));
            std::cerr << std::flush;  // v3.9.3: force flush (see above)

            // If we got an entry, dump its MESSAGE to verify we see the same as journalctl
            if (n_prev == 1) {
                const void* data; size_t len;
                if (sd_journal_get_data(j, "MESSAGE", &data, &len) == 0) {
                    std::string msg(static_cast<const char*>(data), len);
                    LOG_INFO("[JournaldCollector] last entry MESSAGE=" << msg.substr(0, 200));
                }
            } else {
                // n_prev == 0: journal looks empty from this process. Try seek_head as diagnostic.
                LOG_WARN("[JournaldCollector] previous()=0 — journal view may be empty or restricted");
                rc = sd_journal_seek_head(j);
                int n_head = (rc == 0) ? sd_journal_next(j) : -1;
                if (n_head > 0) {
                    const void* data; size_t len;
                    if (sd_journal_get_data(j, "MESSAGE", &data, &len) == 0) {
                        std::string msg(static_cast<const char*>(data), len);
                        LOG_INFO("[JournaldCollector] head->next diagnostic: entry found, MESSAGE="
                                 << msg.substr(0, 200));
                    } else {
                        LOG_INFO("[JournaldCollector] head->next diagnostic: entry found but no MESSAGE field");
                    }
                } else {
                    LOG_ERROR("[JournaldCollector] head->next diagnostic: no entries at all from head! "
                              "n_head=" << n_head << " (journal is TRULY empty in this process view, "
                              "or split mode / credentials restrict access)");
                }
                // Re-seek to tail for the main loop
                sd_journal_seek_tail(j);
                sd_journal_previous(j);
            }

            LOG_INFO("[JournaldCollector] Connected to systemd journal, watching for new entries");

            uint64_t wait_iters = 0, wait_appends = 0, wait_invalidates = 0, wait_nops = 0, entries_read = 0;
            while (running_) {
                // Wait up to 1s for new data
                rc = sd_journal_wait(j, 1000000);
                wait_iters++;

                if (rc == SD_JOURNAL_NOP) {
                    // Timeout, no change — keep looping
                    wait_nops++;
                    continue;
                }
                if (rc < 0) {
                    LOG_ERROR("[JournaldCollector] sd_journal_wait error: " << strerror(-rc)
                              << " (iter=" << wait_iters << ")");
                    break;
                }

                // v3.9.2: BOTH APPEND and INVALIDATE mean "new data may be available"
                //   - SD_JOURNAL_APPEND (1): new entries were appended
                //   - SD_JOURNAL_INVALIDATE (2): journal file rotated/changed
                //     (happens on first wait() after open — this is NORMAL and
                //     must be treated the same as APPEND, otherwise we miss the
                //     first read cycle)
                if (rc == SD_JOURNAL_APPEND) wait_appends++;
                else if (rc == SD_JOURNAL_INVALIDATE) wait_invalidates++;

                // v3.13 (SOC-AGENT#4): rebuild exclude set on every drain. Cost is
                // ~1us (build an unordered_set from <= 64 strings), and this makes
                // journald_exclude_ids hot-reloadable via the heartbeat response.
                // The previous code built the set ONCE at startup (line ~1047), so
                // a config change had no effect until restart. With this change,
                // the new value becomes visible on the next sd_journal iteration
                // (<= 1s latency).
                auto exclude_set = build_exclude_set();

                // Drain all new entries
                uint32_t batch_read = 0;
                while (sd_journal_next(j) > 0) {
                    if (!running_) break;

                    const void* data = nullptr;
                    size_t len = 0;

                    // Extract key fields
                    std::string message, syslog_id, comm, pid_str, uid_str,
                                priority_str, facility_str, unit, hostname_str;

                    SD_JOURNAL_FOREACH_DATA(j, data, len) {
                        std::string field(static_cast<const char*>(data), len);
                        auto eq = field.find('=');
                        if (eq == std::string::npos) continue;
                        std::string key = field.substr(0, eq);
                        std::string val = field.substr(eq + 1);

                        if (key == "MESSAGE")             message = val;
                        else if (key == "SYSLOG_IDENTIFIER") syslog_id = val;
                        else if (key == "_COMM")           comm = val;
                        else if (key == "_PID")            pid_str = val;
                        else if (key == "_UID")            uid_str = val;
                        else if (key == "PRIORITY")        priority_str = val;
                        else if (key == "SYSLOG_FACILITY") facility_str = val;
                        else if (key == "_SYSTEMD_UNIT")   unit = val;
                        else if (key == "_HOSTNAME")       hostname_str = val;
                    }

                    // Skip if no message
                    if (message.empty()) continue;

                    // Skip excluded identifiers (default: logsoc-agent heartbeat noise)
                    if (!syslog_id.empty() && exclude_set.count(syslog_id)) continue;

                    // Determine severity from PRIORITY field
                    int pri = 6;  // default info
                    if (!priority_str.empty()) {
                        try { pri = std::stoi(priority_str); } catch (...) {}
                    }

                    // Map syslog facility number to name
                    std::string facility_name = "daemon";
                    if (!facility_str.empty()) {
                        try {
                            int fac = std::stoi(facility_str);
                            static const char* fac_names[] = {
                                "kern","user","mail","daemon","auth","syslog","lpr","news",
                                "uucp","cron","authpriv","ftp","ntp","security","console","system",
                                "local0","local1","local2","local3","local4","local5","local6","local7"
                            };
                            if (fac >= 0 && fac < 24) facility_name = fac_names[fac];
                        } catch (...) {}
                    }

                    // Best service name: use SYSLOG_IDENTIFIER + fallback logic
                    std::string service = syslog_id;
                    if (service.empty()) service = comm;
                    if (service.empty()) service = unit;
                    if (service.empty()) service = "journald";

                    // Build structured JSON event
                    json ev;
                    ev["event_id"]    = gen_uuid();
                    ev["source_host"] = cfg_.hostname;
                    ev["severity"]    = priority_to_severity(pri);
                    ev["service"]     = "journald";
                    ev["tags"]        = json::array({"journald", syslog_id.empty() ? "systemd" : syslog_id});

                    // Build the message payload as structured JSON
                    json payload;
                    payload["message"]  = message;
                    payload["facility"]  = facility_name;
                    payload["priority"]  = pri;
                    if (!pid_str.empty())    payload["pid"]  = std::stoi(pid_str);
                    if (!uid_str.empty())    payload["uid"]  = std::stoi(uid_str);
                    if (!comm.empty())       payload["comm"] = comm;
                    if (!syslog_id.empty())  payload["identifier"] = syslog_id;
                    if (!unit.empty())       payload["unit"] = unit;
                    // T12.13 (audit Nova M-11): wrap stoi in try/catch so a
                    // malformed _PID/_UID (rare but possible from journald)
                    // doesn't kill the whole journald event. Fall back to
                    // omitting the field — the central can still ingest
                    // the human-readable message and severity.
                    if (!pid_str.empty()) {
                        try { payload["pid"] = std::stoi(pid_str); }
                        catch (const std::exception&) {
                            LOG_WARN("[journald] malformed _PID=" + pid_str + " — omitted");
                        }
                    }
                    if (!uid_str.empty()) {
                        try { payload["uid"] = std::stoi(uid_str); }
                        catch (const std::exception&) {
                            LOG_WARN("[journald] malformed _UID=" + uid_str + " — omitted");
                        }
                    }

                    // v3.6: Keep human-readable message at root, structured context in separate fields
                    ev["message"]    = message;
                    ev["raw_message"] = payload.dump();
                    // Propagate structured fields at root level for API
                    if (!comm.empty())       ev["comm"] = comm;
                    if (!facility_name.empty()) ev["facility"] = facility_name;
                    if (!syslog_id.empty())  ev["identifier"] = syslog_id;
                    if (!unit.empty())       ev["unit"] = unit;
                    // Same try/catch for the root-level copy — the
                    // duplicate stoi in the original code was
                    // throwing on the SAME malformed input twice.
                    if (!pid_str.empty()) {
                        try { ev["pid"] = std::stoi(pid_str); } catch (const std::exception&) {}
                    }
                    if (!uid_str.empty()) {
                        try { ev["uid"] = std::stoi(uid_str); } catch (const std::exception&) {}
                    }
                    // v3.9.9 — populate journald-specific columns for T3 correlation
                    // (ClickHouse ASOF JOIN reads siem_logs.journald_unit/identifier)
                    if (!unit.empty())       ev["journald_unit"] = unit;
                    if (!syslog_id.empty())  ev["journald_identifier"] = syslog_id;

                    // v3.9.0 — REMOVED agent-side correlation
                    // The spec (Nova 2026-06-03) is explicit: the agent NEVER sets
                    // journald_match/ebpf_match. These flags stay at 0 (default) and
                    // are computed by the backend via ClickHouse ASOF JOIN (T3, future).
                    // The local Correlator was producing a feature-creep that also
                    // burned the InMemoryBuffer ring with cross-validation lookups
                    // every journald event — contributing to the eBPF flood drops.

                    // v3.7.0 eBPF ↔ journald cross-validation (REMOVED v3.9.0, see above)
                    // {
                    //     uint32_t journald_pid = 0;
                    //     try { if (!pid_str.empty()) journald_pid = std::stoul(pid_str); } catch (...) {}
                    //     if (journald_pid > 0) {
                    //         logsoc::JournaldEntry jentry;
                    //         jentry.ts_ms = logsoc::Correlator::now_ms();
                    //         ... (full block removed, 36 lines)
                    //     }
                    // }

                    bool wok = buf_.drop_oldest_if_full(ev.dump());
                    // v3.9.7 FIX: wok == true means a drop occurred (oldest evicted), not the opposite!
                    if (wok) {
                        LOG_ERROR("[JournaldCollector] buf_.push() DROPPED oldest event (buffer full, size>=capacity)");
                    }
                    events_++;
                    entries_read++;
                    batch_read++;
                }

                // v3.9.2: LOG_INFO per wakeup so we can see flow in real time
                // Always log (even on NOP) every 30 wakeups as a heartbeat
                if (rc == SD_JOURNAL_NOP && (wait_iters % 30) == 0) {
                    LOG_DEBUG("[JournaldCollector] heartbeat (wait_iters=" << wait_iters
                             << ", NOP=" << wait_nops
                             << ", APPEND=" << wait_appends
                             << ", INVALIDATE=" << wait_invalidates
                             << ", entries_read=" << entries_read << ")");
                } else if (rc != SD_JOURNAL_NOP) {
                    LOG_DEBUG("[JournaldCollector] wait()=" << rc
                             << " (APPEND=" << wait_appends
                             << ", INVALIDATE=" << wait_invalidates
                             << ", NOP=" << wait_nops
                             << ", iter=" << wait_iters
                             << ") — read " << batch_read << " new entries (total=" << entries_read << ")");
                    std::cerr << std::flush;  // v3.9.3: force flush
                }
            }

            sd_journal_close(j);
            if (running_) {
                LOG_WARN("[JournaldCollector] Journal connection lost, reconnecting in 5s...");
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
        LOG_INFO("[-] JournaldCollector stopped (" << events_ << " events)");
#else
        (void)cfg_; (void)wal_; (void)events_;
#endif
    }
};

/* ─── FanotifyCollector: userspace FIM via fanotify(7) — v3.10.1 ─── */
// Provides absolute path resolution for file integrity events, replacing the
// basename-only output of the eBPF kprobe/vfs_write. This is the path that
// Wazuh/Tripwire/Samhain take — they don't try to reconstruct the path in
// kprobe either, they use inotify/fanotify which the kernel gives the path
// for free (via /proc/<pid>/fd/<fd>).
//
// Strategy:
//   1. fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF) — no permission needed
//   2. For each path in cfg.fim.watch_paths, fanotify_mark(..., FAN_MARK_ADD |
//      FAN_EVENT_ON_CHILD, event_mask) — recursive directory mark
//   3. Event loop:
//        - read() the fanotify fd (blocks until event)
//        - parse fanotify_event_metadata (fd, pid, mask)
//        - resolve absolute path via readlink("/proc/<pid>/fd/<fd>")
//        - ignore our own agent PID and cfg.fim.ignore_paths
//        - build JSON event {event:"fim", filename:abs_path, pid, comm, ...}
//        - call yara_engine_->scan_file(abs_path, "file")  [opt-in]
//        - push to InMemoryBuffer (same path as eBPF + Journald collectors)
//   4. Clean shutdown: close the fanotify fd; kernel auto-removes marks on close
//
// Privileges required: CAP_SYS_ADMIN (already in apparmor profile) or root.
// On non-Linux platforms: no-op.
class FanotifyCollector {
public:
    FanotifyCollector(const AgentConfig& cfg, InMemoryBuffer<std::string>& buf)
        : cfg_(cfg), buf_(buf) {}

    void start() {
#ifdef __linux__
        LOG_INFO("[+] FanotifyCollector starting (PID=" << getpid() << ")");
        thread_ = std::thread([=]() { run(); });
#else
        LOG_WARN("[FanotifyCollector] Not available on non-Linux systems");
#endif
    }
    void stop() {
        running_ = false;
        if (fan_fd_ >= 0) {
            // Closing the fanotify fd interrupts the blocking read() in the worker
            ::close(fan_fd_);
            fan_fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }
    void set_yara_engine(logsoc::YaraEngine* e) { yara_engine_ = e; }
    // v3.15 (T59): wire the YaraShipper (content fetcher). Pointer is
    // non-owning (the YaraShipper lives in main() alongside YaraEngine).
    void set_yara_shipper(logsoc::agent::yara::YaraShipper* s) { yara_shipper_ = s; }
    uint64_t events() const { return events_; }
    uint64_t dropped() const { return dropped_; }

    // T12.12: runtime watch management. These let the T28 dispatcher
    // (action_executor.cpp) add/remove a fanotify watch at runtime
    // without spawning a shell. They share the fan_fd_ that the run()
    // loop is reading on, so events on the newly-marked file will be
    // captured by the existing event loop. No coordination needed:
    // fanotify_mark(2) is independent of read(2)/poll(2) on the same
    // fd in the kernel.
    //
    // Returns 0 on success, -1 on error (sets errno). The recursive
    // walk is bounded to depth 8, same as the startup walk.
    //
    // The bodies (mark_one, walk_and_mark, add_watch, remove_watch)
    // are defined inline below as private helpers. We don't need a
    // public declaration here because the bodies are visible to the
    // C shims (t28_fim_watch_add/remove) defined right after the
    // class closes — they're in the same TU.

    int add_watch(const std::string& path, bool recursive);
    int remove_watch(const std::string& path, bool recursive);

private:
    const AgentConfig& cfg_;
    InMemoryBuffer<std::string>& buf_;
    std::atomic<bool> running_{true};
    std::thread thread_;
    int fan_fd_ = -1;
    logsoc::YaraEngine* yara_engine_ = nullptr;
    // v3.15 (T59): optional content shipper (heuristic + libcurl POST).
    // null when yara_ship_content=false (the default).
    logsoc::agent::yara::YaraShipper* yara_shipper_ = nullptr;
    // T12 audit fix (Bug 4): cross-thread access by heartbeat_thread
    // on the FanotifyCollector instance (line 2196 in the audit).
    // Atomic prevents the C++ data race UB.
    std::atomic<uint64_t> events_{0};
    std::atomic<uint64_t> dropped_{0};

    // T12.12: build the JSON event (same shape as the eBPF FIM event in loader.cpp:457
    // so the central FastAPI /api/v1/events/ endpoint accepts it the same way).
    // NOTE: filename MUST be the absolute path (this is the whole point of
    // using fanotify instead of kprobe). We also include `comm` resolved from
    // /proc/<pid>/comm for consistency with the eBPF collector.
    //
    // T12 (audit fix #5, 2026-06-15): the previous version used
    // snprintf with %s/%.16s/%.512s for username/comm/filename WITHOUT
    // sanitizing quotes or backslashes. A username like `root"injected"`
    // or a path containing `"` would produce invalid JSON, the FastAPI
    // backend returns 422 → FIM event silently lost.
    //
    // Fix: copy the strings into local fixed-size buffers, run them
    // through the same sanitize_str() used by the eBPF loader (replaces
    // " and \ with space, replaces non-printable with space), then
    // snprintf from the sanitized buffers. This matches the eBPF
    // FIM event shape exactly so the backend parser is happy.
    static void sanitize_str(char *buf, size_t len) {
        for (size_t i = 0; i < len && buf[i]; ++i) {
            if (buf[i] == '\"' || buf[i] == '\\') buf[i] = ' ';
            if (buf[i] < 0x20 || buf[i] > 0x7E) buf[i] = ' ';
        }
    }
    static std::string build_fim_json(uint64_t ts, pid_t pid, uid_t uid,
                                      const std::string& comm,
                                      const std::string& username,
                                      const std::string& abs_path,
                                      uint64_t inode, const char* mask_name) {
        // M-13 audit fix: replaced snprintf with char json[1024] (truncation
        // risk if fields are long) by nlohmann::json::dump() which dynamically
        // sizes the output. Sanitize strings to remove quotes/backslashes and
        // non-printable characters (same as before, but now using std::string).
        auto sanitize = [](const std::string& s) -> std::string {
            std::string out;
            out.reserve(s.size());
            for (unsigned char c : s) {
                if (c == '"' || c == '\\') out += ' ';
                else if (c < 0x20 || c > 0x7E) out += ' ';
                else out += static_cast<char>(c);
            }
            return out;
        };
        json j;
        j["ts"] = static_cast<unsigned long long>(ts);
        j["pid"] = static_cast<int>(pid);
        j["uid"] = static_cast<unsigned int>(uid);
        j["username"] = sanitize(username).substr(0, 32);
        j["event"] = "fim";
        j["comm"] = sanitize(comm).substr(0, 16);
        j["inode"] = static_cast<unsigned long long>(inode);
        j["filename"] = sanitize(abs_path).substr(0, 512);
        j["action"] = sanitize(mask_name ? std::string(mask_name) : std::string()).substr(0, 32);
        j["source"] = "fanotify";
        return j.dump();
    }

    // Resolve a username from UID via getpwuid. Falls back to the numeric UID
    // string if the user is not in /etc/passwd.
    //
    // T13.5 noise fix (2026-06-17): this function is called once per
    // event (line 2265 in the dispatcher) for actor_uid enrichment. On
    // hosts where NSS uses systemd-userdb (Ubuntu 22.04+ with DynamicUser
    // support), every call to getpwuid() opens the abstract socket
    // /run/systemd/userdb/io.systemd.DynamicUser. Under AppArmor
    // enforce, that abstract socket is unmachable (kernel returns
    // "disconnected path" before any rule can match), so we get ~6
    // DENIED per second. Caching the UID→username resolution here is
    // the KISS fix: the UID space on a host is bounded (~1000 entries
    // typically), so the cache grows slowly and is hit on every event
    // after the first one. Same pattern as src/ebpf/loader.cpp:174
    // (resolve_uid) which already does this for eBPF events.
    static std::string uid_to_username(uid_t uid) {
        static std::unordered_map<uid_t, std::string> cache;
        static std::mutex cache_mtx;
        {
            std::lock_guard<std::mutex> lock(cache_mtx);
            auto it = cache.find(uid);
            if (it != cache.end()) return it->second;
        }
        // Use getpwuid_r (thread-safe) and a 4096-byte buffer. If
        // ERANGE, retry with a 16384-byte buffer. The previous code
        // used getpwuid() which is NOT thread-safe and which
        // corrupted the static passwd buffer under concurrent calls
        // (audit Nova T66 lesson). The retry-on-ERANGE pattern is
        // copied from src/ebpf/loader.cpp:196 to handle long GECOS.
        struct passwd pwd;
        struct passwd* result = nullptr;
        char buf[4096];
        int rc = ::getpwuid_r(uid, &pwd, buf, sizeof(buf), &result);
        if (rc == ERANGE) {
            std::vector<char> big(16384);
            rc = ::getpwuid_r(uid, &pwd, big.data(), big.size(), &result);
        }
        std::string name;
        if (rc == 0 && result) {
            name = std::string(result->pw_name);
        } else {
            name = std::to_string(uid);
        }
        {
            std::lock_guard<std::mutex> lock(cache_mtx);
            cache[uid] = name;
        }
        return name;
    }

    // Read /proc/<pid>/comm. Returns empty on error.
    static std::string read_comm(pid_t pid) {
        if (pid <= 0) return {};
        std::string path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream f(path);
        if (!f.is_open()) return {};
        std::string s;
        std::getline(f, s);
        // /proc/<pid>/comm has trailing \n
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }

    // Read UID from /proc/<pid>/status. The line is "Uid:\t<ruid>\t<euid>\t<suid>\t<fsuid>".
    // We take the real UID (ruid) as the actor identity. Returns 0 on error.
    static uid_t read_uid(pid_t pid) {
        if (pid <= 0) return 0;
        std::string path = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream f(path);
        if (!f.is_open()) return 0;
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("Uid:", 0) == 0) {
                // Strip leading "Uid:\t"
                size_t pos = line.find_first_of("0123456789");
                if (pos == std::string::npos) return 0;
                return static_cast<uid_t>(std::stoul(line.substr(pos)));
            }
        }
        return 0;
    }

    // Resolve absolute path via /proc/<pid>/fd/<fd>. This is the canonical
    // way to get the path of an open file from a process context. Returns
    // empty if the fd is gone (process closed the file between fanotify
    // notification and our readlink).
    static std::string resolve_path_via_proc(pid_t pid, int fd) {
        if (pid <= 0 || fd < 0) return {};
        char link[64];
        std::snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
        char target[1024];
        ssize_t n = ::readlink(link, target, sizeof(target) - 1);
        if (n < 0) return {};
        target[n] = '\0';
        return std::string(target);
    }

    // Get inode number via fstat on the fanotify fd (kernel has it open).
    static uint64_t get_inode(int fd) {
        struct stat st;
        if (::fstat(fd, &st) < 0) return 0;
        return static_cast<uint64_t>(st.st_ino);
    }

    // Map fanotify mask → action name (for the JSON event).
    static const char* mask_name(uint64_t mask) {
        if (mask & FAN_CREATE)         return "create";
        if (mask & FAN_DELETE)         return "delete";
        if (mask & FAN_MOVED_FROM)     return "move_from";
        if (mask & FAN_MOVED_TO)       return "move_to";
        if (mask & FAN_MODIFY)         return "modify";
        return "unknown";
    }

    // Apply cfg.fim.ignore_paths prefix filter.
    bool is_ignored(const std::string& path) const {
        for (const auto& p : cfg_.fim.ignore_paths) {
            if (p.empty()) continue;
            if (path.size() >= p.size() &&
                std::memcmp(path.data(), p.data(), p.size()) == 0) {
                return true;
            }
        }
        return false;
    }

    // Map inode → absolute path, populated during the dir walk.
    // Used to resolve fanotify events: the event has a fd; we stat the
    // fd to get the inode, then look it up here to recover the absolute
    // path. This avoids the readlink(/proc/<pid>/fd/<fd>) race and the
    // DFID+NAME complexity.
    std::unordered_map<uint64_t, std::string> inode_to_path_;
    // A-05: mutex to guard inode_to_path_ against concurrent access
    // from FIM thread and main thread.
    std::mutex inode_to_path_mtx_;

    void run() {
#ifdef __linux__
        // T12 audit fix (Bug 2): snapshot policy.fim_watch_paths
        // under policy_mtx. The previous lock-free read could
        // race with PolicyPuller's std::move assignment (line 2803)
        // — iterator invalidation and use-after-free. The vector
        // is also iterated again at line 1823 below; we take a
        // single local copy and use it for both checks.
        std::vector<std::string> watch_paths_copy;
        {
            std::lock_guard<std::mutex> pl(cfg_.policy.policy_mtx);
            watch_paths_copy = cfg_.policy.fim_watch_paths;
        }
        if (watch_paths_copy.empty()) {
            LOG_INFO("[FanotifyCollector] policy.fim_watch_paths is empty, nothing to watch");
            return;
        }

        // 1. Init fanotify fd
        // v3.10.2: FAN_NONBLOCK so poll() + read() can detect EAGAIN without blocking.
        // Without FAN_NONBLOCK, a blocking read() on a misbehaving fd returned
        // EACCES (errno=13) intermittently on Hestia kernel 6.8 — the kernel
        // seems to mark the fd as "no read access" after a queue overflow.
        // Using FAN_NONBLOCK + poll() avoids this entirely.
        fan_fd_ = ::fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY);
        if (fan_fd_ < 0) {
            int err = errno;
            LOG_ERROR("[FanotifyCollector] fanotify_init failed: "
                      << ::strerror(err) << " (errno=" << err
                      << ", need CAP_SYS_ADMIN or root)");
            return;
        }
        LOG_INFO("[FanotifyCollector] fanotify_init OK, fd=" << fan_fd_ << " (FAN_NONBLOCK)");

        // 2. Mark each watch path recursively
        // Hestia kernel 6.8.0-117 returns EINVAL on FAN_EVENT_ON_CHILD
        // (kernel bug or Ubuntu patch). Workaround: mark each FILE
        // individually. For DIR paths in watch_paths, walk the tree and
        // mark each file. For mountpoint coverage, we expose a special
        // path syntax: "/@mount:/etc" → mark the / mount and filter
        // events by prefix. The directory walk is bounded (depth 8) to
        // avoid marking tens of thousands of files.
        //
        // For each watch path:
        //   - regular file → fanotify_mark on the file directly
        //   - directory → walk (bounded depth) and mark each file
        //   - special "/@mount:<prefix>" → FAN_MARK_MOUNT on / + filter
        int marked = 0;
        constexpr int MAX_WALK_DEPTH = 8;
        for (const auto& path : watch_paths_copy) {
            // v3.10.2: use POSIX stat() instead of std::filesystem::exists/is_directory
            // (the latter returned wrong values on Hestia 6.8 — likely a libstdc++
            // static-link ABI quirk).
            struct stat path_st;
            if (::stat(path.c_str(), &path_st) != 0) {
                int err = errno;
                if (err != ENOENT) {
                    LOG_WARN("[FanotifyCollector] skip watch path (stat failed): " << path
                             << " — " << ::strerror(err));
                } else {
                    LOG_WARN("[FanotifyCollector] skip watch path (not found): " << path);
                }
                continue;
            }
            const bool is_dir = S_ISDIR(path_st.st_mode);
            LOG_INFO("[FanotifyCollector] watch path " << path
                     << " stat_ok mode=0" << std::oct << path_st.st_mode
                     << " is_dir=" << is_dir);

            if (is_dir) {
                // Bounded directory walk using POSIX opendir/readdir.
                // v3.10.2: std::filesystem::directory_iterator returned 0 entries
                // on Hestia 6.8 (probably a libstdc++ static-link ABI issue or
                // a kernel-level opendir restriction). POSIX opendir() is the
                // ground truth and works on every Linux.
                // We mark each file with FAN_MODIFY (the only FIM signal that
                // makes sense per-file). We do NOT use FAN_EVENT_ON_CHILD
                // (EINVAL on this kernel).
                size_t file_count = 0;
                size_t dir_count = 0;
                std::deque<std::pair<std::string, int>> stack;
                stack.push_back({path, 0});
                while (!stack.empty()) {
                    auto [cur, depth] = stack.back();
                    stack.pop_back();
                    if (depth > MAX_WALK_DEPTH) continue;

                    DIR* d = ::opendir(cur.c_str());
                    if (!d) {
                        int err = errno;
                        // EACCES on the dir itself is normal for /etc/ssl/private etc.
                        // — skip silently. Other errors are worth a log.
                        if (depth < 2) {
                            // Always log for top-level dirs to surface permission issues
                            LOG_WARN("[FanotifyCollector] opendir(" << cur
                                     << ") failed: " << ::strerror(err)
                                     << " (errno=" << err << ")");
                        }
                        continue;
                    }
                    int readdir_count = 0;
                    int lstat_fail = 0;
                    struct dirent* ent;
                    while ((ent = ::readdir(d)) != nullptr) {
                        readdir_count++;
                        // Skip "." and ".."
                        if (ent->d_name[0] == '.' &&
                            (ent->d_name[1] == '\0' ||
                             (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
                            continue;
                        }
                        std::string ep = cur + "/" + ent->d_name;

                        // Use lstat to avoid following symlinks (would mark
                        // the target instead of the symlink, which is wrong
                        // for FIM — we want to know if the symlink itself
                        // changes).
                        struct stat lst;
                        if (::lstat(ep.c_str(), &lst) != 0) {
                            lstat_fail++;
                            if (lstat_fail <= 3) {
                                LOG_WARN("[FanotifyCollector] lstat(" << ep
                                         << ") failed: " << ::strerror(errno));
                            }
                            continue;  // vanished between readdir and lstat
                        }
                        bool is_directory = S_ISDIR(lst.st_mode);
                        bool is_regular   = S_ISREG(lst.st_mode);

                        if (is_directory) {
                            stack.push_back({ep, depth + 1});
                            dir_count++;
                        } else if (is_regular) {
                            int rc = ::fanotify_mark(fan_fd_,
                                FAN_MARK_ADD,
                                static_cast<uint64_t>(cfg_.fanotify_file_mask),
                                AT_FDCWD, ep.c_str());
                            if (rc == 0) {
                                file_count++;
                                marked++;
                                // Populate inode→path cache for path resolution
                                { std::lock_guard<std::mutex> lk(inode_to_path_mtx_); inode_to_path_[static_cast<uint64_t>(lst.st_ino)] = ep; }
                            } else if (errno != ENOENT && errno != EACCES) {
                                int err = errno;
                                LOG_WARN("[FanotifyCollector] fanotify_mark(" << ep
                                         << ") failed: " << ::strerror(err));
                            }
                        }
                    }
                    ::closedir(d);
                    if (depth == 0) {
                        LOG_INFO("[FanotifyCollector] opendir(" << cur
                                 << "): readdir=" << readdir_count
                                 << " lstat_fail=" << lstat_fail);
                    }
                }
                LOG_INFO("[FanotifyCollector] dir walk: " << path
                         << " → " << file_count << " files, " << dir_count << " dirs marked");
            } else {
                // Regular file: mark directly with file mask.
                int rc = ::fanotify_mark(fan_fd_,
                                         FAN_MARK_ADD,
                                         static_cast<uint64_t>(cfg_.fanotify_file_mask),
                                         AT_FDCWD, path.c_str());
                if (rc < 0) {
                    int err = errno;
                    LOG_WARN("[FanotifyCollector] fanotify_mark(" << path
                             << ") failed: " << ::strerror(err) << " (errno=" << err << ")");
                    continue;
                }
                marked++;
                // Populate inode→path cache for single-file marks too
                struct stat st;
                if (::stat(path.c_str(), &st) == 0) {
                    { std::lock_guard<std::mutex> lk(inode_to_path_mtx_); inode_to_path_[static_cast<uint64_t>(st.st_ino)] = path; }
                }
                LOG_INFO("[FanotifyCollector] mark added: " << path
                         << " (mask=0x" << std::hex << cfg_.fanotify_file_mask << std::dec << ")");
            }
        }
        if (marked == 0) {
            LOG_ERROR("[FanotifyCollector] no mark succeeded, exiting thread");
            ::close(fan_fd_);
            fan_fd_ = -1;
            return;
        }
        LOG_INFO("[FanotifyCollector] " << marked << "/" << watch_paths_copy.size()
                 << " mark(s) active, entering event loop");

        // 3. Event loop — single blocking read() per iteration
        // fanotify_event_metadata is 24 bytes. We use a generous buffer
        // (8192 bytes) which fits ~340 events or 1 event with a long path.
        constexpr size_t BUF_SZ = 8192;
        std::vector<char> ev_buf(BUF_SZ);
        const pid_t agent_pid = ::getpid();

        while (running_) {
            // v3.10.2: poll() with FAN_NONBLOCK instead of blocking read().
            // The Hestia 6.8 kernel intermittently returned EACCES (errno=13)
            // on a blocking read() after the queue overflowed once. With
            // FAN_NONBLOCK + poll(2s timeout), we can:
            //   1. Detect idle (poll timeout) → loop again cleanly
            //   2. Get EAGAIN cleanly instead of EACCES on retry
            //   3. Catch stop() promptly (close → POLLHUP/POLLERR)
            struct pollfd pfd;
            pfd.fd = fan_fd_;
            pfd.events = POLLIN;
            int pr = ::poll(&pfd, 1, 2000);  // 2s timeout
            if (pr < 0) {
                if (errno != EINTR) {
                    LOG_WARN("[FanotifyCollector] poll() error: " << ::strerror(errno));
                }
                continue;
            }
            if (pr == 0) {
                // timeout — no events. Continue loop.
                continue;
            }
            // Data available: read (non-blocking thanks to FAN_NONBLOCK).
            ssize_t n = ::read(fan_fd_, ev_buf.data(), BUF_SZ);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Spurious wakeup (POLLIN set but no data yet). Retry.
                    continue;
                }
                if (errno == EINTR) continue;
                // v3.10.2: was hitting EACCES here with blocking read. With
                // FAN_NONBLOCK + poll, this branch should be much rarer.
                // If it does happen, log + back off + keep the fd alive.
                int err = errno;
                LOG_WARN("[FanotifyCollector] read() error: " << ::strerror(err)
                         << " (errno=" << err << "), backing off 200ms");
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }
            if (n == 0) continue;  // shouldn't happen on regular files

            // Walk the events. fanotify_event_metadata is variable-length
            // because of an optional fd at the end. The kernel writes the
            // fd when FAN_MODIFY|FAN_CREATE|... — not for FAN_DELETE on a
            // directory (the file is already gone).
            char* end = ev_buf.data() + n;
            for (char* p = ev_buf.data(); p < end; ) {
                auto* meta = reinterpret_cast<struct fanotify_event_metadata*>(p);
                if (meta->vers != FANOTIFY_METADATA_VERSION) {
                    LOG_WARN("[FanotifyCollector] metadata version mismatch: "
                             << meta->vers);
                    break;
                }
                if (meta->fd < 0) {
                    // No fd (e.g. queue overflow). Skip to next event.
                    p += meta->event_len;
                    continue;
                }

                // Skip events from our own agent
                if (static_cast<pid_t>(meta->pid) == agent_pid) {
                    ::close(meta->fd);
                    p += meta->event_len;
                    continue;
                }

                // 1. Resolve absolute path via inode→path cache.
                // The event has an fd; we fstat() it to get the inode,
                // then look it up in the cache populated during the
                // dir walk. This is race-free (the kernel keeps the
                // inode alive in the event metadata) and AppArmor-safe
                // (fstat is allowed on any open fd).
                struct stat st;
                std::string abs_path;
                if (::fstat(meta->fd, &st) == 0) {
                    std::lock_guard<std::mutex> lk(inode_to_path_mtx_);
                    auto it = inode_to_path_.find(static_cast<uint64_t>(st.st_ino));
                    if (it != inode_to_path_.end()) {
                        abs_path = it->second;
                    }
                }
                // v3.10.2: DO NOT close meta->fd here — YARA scan below
                // reads from it. Close at the end of the loop body.

                if (abs_path.empty()) {
                    // Inode not in our cache. Either the dir walk missed
                    // it (depth limit), or a new file was created. Skip.
                    size_t cache_size;
                    { std::lock_guard<std::mutex> lk(inode_to_path_mtx_); cache_size = inode_to_path_.size(); }
                    if (dropped_ < 10) {
                        LOG_WARN("[FanotifyCollector] dropped event: inode not in cache "
                                 "(pid=" << meta->pid << " inode=" << (st.st_ino ? static_cast<uint64_t>(st.st_ino) : 0) << " mask=0x"
                                 << std::hex << meta->mask << std::dec << " cache_size="
                                 << cache_size << ")");
                    }
                    ++dropped_;
                    ::close(meta->fd);  // close fd (was unused since v3.10.2)
                    p += meta->event_len;
                    continue;
                }
                if (events_ + dropped_ <= 5) {
                    LOG_INFO("[FanotifyCollector] event: pid=" << meta->pid
                             << " inode=" << static_cast<uint64_t>(st.st_ino)
                             << " mask=0x" << std::hex << meta->mask
                             << std::dec << " path=" << abs_path);
                }

                // 2. Apply ignore_paths
                if (is_ignored(abs_path)) {
                    ::close(meta->fd);
                    p += meta->event_len;
                    continue;
                }

                // 3. Get comm + username
                // v3.10.2: use the inode from the fstat(meta->fd) call above
                // (line ~1560) instead of re-stat'ing the path. Re-stat would
                // trigger an AppArmor "disconnected path" denial under enforce
                // for any path that the kernel's fanotify fd didn't already
                // open (the audit fires name="etc/passwd" denied_mask="r" when
                // /etc/** is rewritten, etc.). The fstat inode is identical.
                std::string comm = read_comm(static_cast<pid_t>(meta->pid));
                if (comm.empty()) comm = "unknown";
                uid_t actor_uid = read_uid(static_cast<pid_t>(meta->pid));
                std::string username = uid_to_username(actor_uid);
                uint64_t inode = static_cast<uint64_t>(st.st_ino);

                // 4. Build JSON event (same shape as eBPF FIM in loader.cpp:457
                // + source="fanotify" tag and action=create/delete/modify/move).
                uint64_t ts = static_cast<uint64_t>(
                    std::chrono::system_clock::now().time_since_epoch() /
                    std::chrono::milliseconds(1));
                std::string ev_json = build_fim_json(
                    ts, static_cast<pid_t>(meta->pid), actor_uid,
                    comm, username, abs_path, inode,
                    mask_name(meta->mask));

                if (ev_json.empty()) {
                    ++dropped_;
                    ::close(meta->fd);
                    p += meta->event_len;
                    continue;
                }

                // 5. v3.15 (T59): YARA content fetch — enqueue the suspicious
                // file's content for shipping to the central. The heuristic
                // gate, size cap, and bounded queue all live in
                // YaraShipper::enqueue_event() (yara_shipper.{hpp,cpp}). The
                // actual read+POST happens on a background ship thread, so
                // the FIM event loop only pays for a cheap enqueue here.
                // The previous v3.10.2 behavior (in-process YARA scan
                // blocked by AppArmor "disconnected path") is REPLACED by
                // this content-fetch path: the central runs YARA instead
                // of the agent. See SOC-AGENT issue #3 → #5.
                if (yara_shipper_) {
                    // Ship the content. enqueue_event() is non-blocking
                    // (pushes to a bounded MPSC queue) BUT the call site
                    // is in the FIM event loop, so we treat it as a soft
                    // best-effort. The heuristic gate ensures we only
                    // spend I/O on truly suspicious files.
                    yara_shipper_->enqueue_event(
                        abs_path, inode, static_cast<size_t>(st.st_size));
                } else {
                    // No shipper wired → fall back to the historical
                    // "(void)yara_engine_" placeholder. The eBPF FIM
                    // collector still does its own in-process YARA scan
                    // (EbpfCollector::process_event) when yara_enabled
                    // and yara_engine_ are set.
                    (void)yara_engine_;
                }

                // v3.10.2: close fanotify fd (was previously at line ~1566
                // before YARA read required it kept open)
                ::close(meta->fd);

                // 6. Push to InMemoryBuffer (non-blocking, drops oldest on full)
                bool dropped_oldest = buf_.drop_oldest_if_full(ev_json);
                if (dropped_oldest) {
                    ++dropped_;
                }
                ++events_;

                p += meta->event_len;
            }
        }

        if (fan_fd_ >= 0) {
            ::close(fan_fd_);
            fan_fd_ = -1;
        }
        LOG_INFO("[-] FanotifyCollector stopped ("
                 << events_ << " events, " << dropped_ << " dropped)");
#else
        (void)buf_;
#endif
    }

    // T12.12: factor out the mark logic from the startup walk so it
    // can be reused by add_watch/remove_watch (runtime) without
    // duplicating the bounded walk + per-file mask handling.
    //
    // These methods are defined out-of-line (right after the class
    // closes, see line ~2230 below). Forward-declared here as private
    // members so the public add_watch/remove_watch (which are also
    // defined out-of-line) can call them.
    //
    // mark_one: do a single fanotify_mark(2) on `path` with the given
    // `flag` (FAN_MARK_ADD or FAN_MARK_REMOVE). Returns 0 on success,
    // -1 on error (errno set). On success, populates inode_to_path_
    // for ADD only (REMOVE doesn't need it).
    int mark_one(const std::string& path, uint64_t flag);

    // walk_and_mark: recursive bounded walk, same logic as the
    // startup loop, parameterized on the mark flag. depth is the
    // current depth (root call passes 0). Returns the count of
    // successful marks. Errors on individual files are logged and
    // skipped (consistent with the startup behavior).
    int walk_and_mark(const std::string& path, uint64_t flag, int depth);
};

// T12.12: out-of-line definitions for the mark helpers. They have
// to be defined after the class closes because they reference
// private members (fan_fd_, cfg_, inode_to_path_). Defining them
// out-of-class also makes them implicitly inline-eligible without
// the inline keyword (since they're in the same TU as the class).
int FanotifyCollector::mark_one(const std::string& path, uint64_t flag) {
    if (fan_fd_ < 0) {
        errno = EBADF;
        return -1;
    }
    int rc = ::fanotify_mark(fan_fd_,
                             flag,
                             static_cast<uint64_t>(cfg_.fanotify_file_mask),
                             AT_FDCWD, path.c_str());
    if (rc < 0) {
        return -1;
    }
    if (flag == FAN_MARK_ADD) {
        struct stat st;
        if (::stat(path.c_str(), &st) == 0) {
            { std::lock_guard<std::mutex> lk(inode_to_path_mtx_); inode_to_path_[static_cast<uint64_t>(st.st_ino)] = path; }
        }
    }
    return 0;
}

int FanotifyCollector::walk_and_mark(const std::string& path, uint64_t flag, int depth) {
    constexpr int MAX_WALK_DEPTH = 8;
    if (depth > MAX_WALK_DEPTH) return 0;

    struct stat path_st;
    if (::stat(path.c_str(), &path_st) != 0) {
        int err = errno;
        if (err != ENOENT) {
            LOG_WARN("[FanotifyCollector] walk_and_mark: stat(" << path
                     << ") failed: " << ::strerror(err));
        }
        return 0;
    }
    int count = 0;
    if (S_ISDIR(path_st.st_mode)) {
        std::deque<std::pair<std::string, int>> stack;
        stack.push_back({path, depth});
        while (!stack.empty()) {
            auto [cur, d] = stack.back();
            stack.pop_back();
            if (d > MAX_WALK_DEPTH) continue;
            DIR* dir = ::opendir(cur.c_str());
            if (!dir) continue;
            struct dirent* ent;
            while ((ent = ::readdir(dir)) != nullptr) {
                if (ent->d_name[0] == '.' &&
                    (ent->d_name[1] == '\0' ||
                     (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
                    continue;
                }
                std::string ep = cur + "/" + ent->d_name;
                struct stat lst;
                if (::lstat(ep.c_str(), &lst) != 0) continue;
                if (S_ISDIR(lst.st_mode)) {
                    stack.push_back({ep, d + 1});
                } else if (S_ISREG(lst.st_mode)) {
                    if (mark_one(ep, flag) == 0) count++;
                }
            }
            ::closedir(dir);
        }
    } else if (S_ISREG(path_st.st_mode)) {
        if (mark_one(path, flag) == 0) count++;
    }
    return count;
}

int FanotifyCollector::add_watch(const std::string& path, bool recursive) {
    if (fan_fd_ < 0) { errno = EBADF; return -1; }
    int n = recursive ? walk_and_mark(path, FAN_MARK_ADD, 0)
                      : (mark_one(path, FAN_MARK_ADD) == 0 ? 1 : 0);
    if (n == 0) { errno = ENOENT; return -1; }
    LOG_INFO("[FanotifyCollector] add_watch: " << path
             << (recursive ? " (recursive)" : "") << " → " << n << " mark(s)");
    return 0;
}

int FanotifyCollector::remove_watch(const std::string& path, bool recursive) {
    if (fan_fd_ < 0) { errno = EBADF; return -1; }
    int n = recursive ? walk_and_mark(path, FAN_MARK_REMOVE, 0)
                      : (mark_one(path, FAN_MARK_REMOVE) == 0 ? 1 : 0);
    // For remove, n=0 is not an error: the path may simply not
    // have been marked. We return 0 as long as the fd is healthy.
    LOG_INFO("[FanotifyCollector] remove_watch: " << path
             << (recursive ? " (recursive)" : "") << " → " << n << " mark(s) removed");
    return 0;
}

// T12.12: file-static pointer to the unique FanotifyCollector
// instance, set once in main() right after construction. The T28
// dispatcher (action_executor.cpp) reads it through the
// t28_fim_watch_add/remove shims to add/remove watches at runtime
// without spawning a shell.
//
// file-static (not extern global) keeps the symbol private to
// agent.cpp's TU, which is the only place that knows the full
// FanotifyCollector class definition.
static FanotifyCollector* g_fanotify_collector = nullptr;

extern "C" int t28_fim_watch_add(const char* path, int recursive) {
    if (g_fanotify_collector == nullptr || path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return g_fanotify_collector->add_watch(path, recursive != 0);
}

extern "C" int t28_fim_watch_remove(const char* path, int recursive) {
    if (g_fanotify_collector == nullptr || path == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return g_fanotify_collector->remove_watch(path, recursive != 0);
}

/* ─── v3.12 hot-reload rebuild helpers (SOC-AGENT#4) ───
 *
 * These functions physically rebuild the collectors after scan_paths /
 * watch_paths change. Loss of events 1-2s is ACCEPTED (dev only, see
 * CHANGELOG v3.12). For production, the agent would need to maintain
 * per-path incremental state (much more complex, deferred to v3.13).
 *
 * Defined AFTER AppCollector (l. ~1021) and FanotifyCollector (l. ~1411)
 * because they take references to those types.
 */

static void stop_all_app_collectors(std::vector<std::unique_ptr<AppCollector>>& v) {
    for (auto& c : v) {
        if (c) c->stop();
    }
    v.clear();
}

static void rebuild_app_collectors(
    std::vector<std::unique_ptr<AppCollector>>& app_collectors,
    InMemoryBuffer<std::string>& buffer,
    const std::vector<std::string>& new_paths,
    bool app_collector_enabled,
    std::mutex& app_collectors_mtx)
{
    // T13.9: mutex protects app_collectors from concurrent access between
    // heartbeat thread (rebuild) and shutdown (stop_all). Killed audit H-12
    // race. See "T13.9 Threading Model" comment in main() for full ownership.
    std::lock_guard<std::mutex> lk(app_collectors_mtx);
    LOG_INFO("[HB-HR] rebuilding AppCollector: "
             << app_collectors.size() << " -> " << new_paths.size() << " path(s)");

    stop_all_app_collectors(app_collectors);

    if (!app_collector_enabled) {
        LOG_INFO("[HB-HR] AppCollector disabled in config, rebuild skipped");
        return;
    }

    int started = 0;
    for (const auto& path : new_paths) {
        if (!fs::exists(path)) {
            LOG_WARN("[HB-HR] AppCollector: skipping " << path << " (not found)");
            continue;
        }
        auto c = std::make_unique<AppCollector>(path, buffer);
        c->start();
        app_collectors.push_back(std::move(c));
        started++;
    }
    LOG_INFO("[HB-HR] AppCollector active on " << started << " file(s) after rebuild");
}

static void rebuild_fanotify_collector(
    std::unique_ptr<FanotifyCollector>& fanotify_coll,
    AgentConfig& cfg,
    InMemoryBuffer<std::string>& buffer,
    logsoc::YaraEngine* yara_engine,
    const std::vector<std::string>& new_paths)
{
    if (fanotify_coll) {
        uint64_t prev_count = fanotify_coll->events();
        LOG_INFO("[HB-HR] stopping FanotifyCollector (had " << prev_count
                 << " events processed) for re-mark with "
                 << new_paths.size() << " new path(s)");
        // T12.12: unwire the global pointer BEFORE destroying the
        // instance, so a concurrent t28_fim_watch_add() call from
        // the action dispatcher returns EINVAL instead of dereferencing
        // a dangling pointer.
        if (g_fanotify_collector == fanotify_coll.get()) {
            g_fanotify_collector = nullptr;
        }
        fanotify_coll->stop();
        fanotify_coll.reset();
    }

    // T64.4.1 (v3.20.0): keep BOTH cfg.fim.watch_paths (legacy, used by hot-reload) and
    // cfg.policy.fim_watch_paths (read by FanotifyCollector since v3.20) in sync.
    // Central policy pull is the only legitimate source, so overwriting is safe.
    //
    // T12 audit fix #24: lock around the policy write — the main loop reads
    // cfg.policy.fim_watch_paths (possibly iterating for rebuild) on its 30s tick.
    cfg.fim.watch_paths = new_paths;
    {
        std::lock_guard<std::mutex> pl(cfg.policy.policy_mtx);
        cfg.policy.fim_watch_paths = new_paths;
    }

    if (!cfg.fanotify_enabled) {
        LOG_INFO("[HB-HR] fanotify_enabled=false, FanotifyCollector not restarted");
        return;
    }
    if (new_paths.empty()) {
        LOG_INFO("[HB-HR] watch_paths is empty, FanotifyCollector not restarted");
        return;
    }

    fanotify_coll = std::make_unique<FanotifyCollector>(cfg, buffer);
    fanotify_coll->set_yara_engine(yara_engine);
    // T12.12: wire the global pointer so the T28 action dispatcher
    // (action_executor.cpp) can call add_watch/remove_watch at runtime.
    // Set AFTER make_unique so we never expose a half-constructed
    // instance to concurrent callers.
    g_fanotify_collector = fanotify_coll.get();
    fanotify_coll->start();
    LOG_INFO("[HB-HR] FanotifyCollector restarted with "
             << new_paths.size() << " watch path(s)");
}

/* ─── eBPF Collector thread (v3.2 A4) ─── */
class EbpfCollector {
public:
    EbpfCollector(const AgentConfig& cfg, InMemoryBuffer<std::string>& buf)
        : cfg_(cfg), buf_(buf) {}

    // v3.9.6: Backpressure intelligent — drop event by type when buffer is under pressure
    // Priority (highest to lowest): execve > unlink > tcp_connect > open > fim
    // Returns true if the event SHOULD be dropped to relieve pressure
    //
    // v3.9.7: thresholds LOWERED (50%→20%, 80%→50%, 95%→80%) because at Hestia,
    // the network HTTP throughput caps us at ~640 events/min while eBPF produces
    // ~1300 events/min. The buffer reaches its cap quickly and stays >50% most of
    // the time. With the old thresholds, the buffer had to hit 50% (250k events) before
    // any drop happened, by which time we were already in a death spiral.
    // New: start dropping FIM at 20% to keep room for execve/unlink.
    bool should_drop_by_priority(const std::string& ev_type) {
        // Compute current pressure 0.0-1.0 (lock-free via size() with internal mutex)
        size_t cur = buf_.size();
        size_t cap = buf_.capacity();
        if (cap == 0) return false;
        double pressure = static_cast<double>(cur) / static_cast<double>(cap);

        // v3.9.7: periodic pressure log (every 60s) for observability, not verbose per-event
        static std::atomic<uint64_t> dbg_calls{0};
        static std::atomic<uint64_t> last_log_us{0};
        uint64_t n = ++dbg_calls;
        uint64_t now_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        if (n <= 5 || (now_us - last_log_us.load() > 60000000)) {
            last_log_us.store(now_us);
            LOG_INFO("[eBPF] backpressure cur=" << cur << "/" << cap
                      << " pressure=" << std::fixed << std::setprecision(0)
                      << (100.0 * pressure) << "%"
                      << " calls=" << n);
        }

        // Buffer 0-20%: never drop, drop_oldest handles
        // Buffer 20-50%: drop FIM events (already sampled 1/8 kernel-side)
        // Buffer 50-80%: drop open events too
        // Buffer 80-100%: drop tcp_connect too
        // execve, unlink: NEVER drop (critical for MITRE T1059, T1485)
        if (pressure < 0.20) return false;
        if (ev_type == "fim" && pressure >= 0.20) return true;       // drop FIM at 20%+
        if (ev_type == "open" && pressure >= 0.50) return true;     // drop open at 50%+
        if (ev_type == "tcp_connect" && pressure >= 0.80) return true; // drop tcp at 80%+
        return false;
    }

    void start() {
        if (!ebpf::kernel_ok()) {
            LOG_WARN("[eBPF] Kernel unsupported: " + std::string(ebpf::kernel_reason()));
            return;
        }
        if (!ebpf::init()) {
            LOG_ERROR("[eBPF] init() failed");
            return;
        }
        // T13.4: optionally also attach the XDP SYN scan detector.
        // Config-driven (cfg_.enable_xdp_scan, default false so
        // existing deployments are unaffected). If the interface name
        // is missing or XDP attach fails, we just log a warning and
        // continue — skel_soc keeps working.
        if (cfg_.enable_xdp_scan && !cfg_.xdp_interface.empty()) {
            // The callback just logs the alert. T13.3' (ActionRecommender)
            // can later consume this to recommend firewall rules.
            if (!ebpf::t13_4_xdp_init(cfg_.xdp_interface,
                [](uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                   uint64_t syn_count) {
                    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &src_ip, src_str, sizeof(src_str));
                    inet_ntop(AF_INET, &dst_ip, dst_str, sizeof(dst_str));
                    LOG_WARN("[T13.4] SCAN_DETECTED src=" + std::string(src_str)
                             + " dst=" + std::string(dst_str)
                             + ":" + std::to_string(ntohs(dst_port))
                             + " syn_count=" + std::to_string(syn_count));
                })) {
                LOG_WARN("[T13.4] XDP init failed — falling back to pcap-only mode");
            }
        }
        // Ringbuf fd → non-blocking for polling
        int fd = ebpf::get_fd();
        if (fd >= 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        thread_ = std::thread([=]() { run(); });
    }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        // T13.4: stop XDP before stopping skel_soc (in case the
        // ring buffer was actively polling — we want a clean detach).
        ebpf::t13_4_xdp_stop();
        ebpf::stop();
    }

    uint64_t events() const { return events_; }
    uint64_t priority_dropped() const { return priority_dropped_; }  // v3.9.7

private:
    const AgentConfig& cfg_;
    InMemoryBuffer<std::string>& buf_;
    std::atomic<bool> running_{true};
    std::thread thread_;
    // T12 audit fix (Bug 4): cross-thread access by metrics_thread
    // and heartbeat_thread on the EbpfCollector instance. Atomic
    // prevents the C++ data race UB and the torn-read risk on
    // 32-bit platforms (on x86-64 a uint64_t read is naturally
    // atomic at the hardware level, but the C++ standard still
    // requires synchronization).
    std::atomic<uint64_t> events_{0};
    std::atomic<uint64_t> priority_dropped_{0};  // v3.9.7: distinct from buf_dropped — events rejected by should_drop_by_priority
    logsoc::YaraEngine* yara_engine_ = nullptr;  // v3.10.0: optional YARA scan hook (no ownership)
    // v4.8.0 (T4.8): FimCollector (no ownership) — routes fim+write_fd through
    // the V4.8 pipeline (FdResolver + rate limit + MITRE tag). Set via
    // set_fim_collector() after the collector is constructed in main().
    logsoc::agent::fim::FimCollector* fim_collector_ = nullptr;

public:
    // v3.10.0: wire YARA engine into the eBPF collector for FIM/open scan
    void set_yara_engine(logsoc::YaraEngine* e) { yara_engine_ = e; }
    // v4.8.0 (T4.8): wire FimCollector into the eBPF collector for fim+write_fd
    void set_fim_collector(logsoc::agent::fim::FimCollector* c) { fim_collector_ = c; }

    void run() {
        LOG_INFO("[+] eBPF collector started");
        uint64_t poll_calls = 0;
        uint64_t poll_hits = 0;
        // T4.8.27.18 / 27C.1.9: poll every 10ms (was 100ms) so the
        // g_queue → InMemoryBuffer pipeline can keep up with FIM bursts.
        // 100Hz poll + ringbuf drain = no event lags behind another.
        // T13.4: every 10th iteration (100ms) we also poll the XDP
        // ring buffer for SYN scan alerts. XDP polling is cheap (~0 cost
        // when no events), so we can do it often.
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            poll_calls++;

            // T13.4: drain XDP ring buffer (non-blocking, 0ms timeout)
            if ((poll_calls % 10) == 0) {
                ebpf::t13_4_xdp_poll(0);
            }

            char buf[4096]{};
            int n = ebpf::poll(buf, sizeof(buf) - 1);
            if (n == 0) continue;              // stop requested
            if (n < 0)  continue;           // no data

            // T4.8.27 / 27C.1.12: pipeline proven to work — debug log removed.

            // Periodic heartbeat log (every 300 polls = 30s)
            if (poll_calls % 300 == 0) {
                LOG_VERBOSE("[eBPF] poll alive: " << poll_calls << " calls,"
                          << poll_hits << " hits");
            }

            poll_hits++;
            if (poll_hits <= 5 || poll_hits % 100 == 0) {
                LOG_VERBOSE("[eBPF] poll hit #" << poll_hits << "/" << poll_calls
                          << " n=" << n);
            }

            // v3.9.7: Parse ONLY the event type FIRST for cheap backpressure.
            // Avoid building the full 500-byte JSON envelope just to drop the event.
            std::string ev_type;
            try {
                json ev_quick = json::parse(std::string(buf, static_cast<size_t>(n)));
                ev_type = ev_quick.value("event", "");
            } catch (...) {
                ev_type = "";
            }

            // T12.14 (audit Nova H-10): the "double parse" (ev_quick
            // above + ev below) is INTENTIONAL perf optimization, not
            // a bug. The first parse only reads one key to make a
            // cheap drop decision under backpressure; the second
            // parse only runs for events that survive the drop. Doing
            // a single parse + full envelope build for every event
            // would burn CPU on events we drop anyway. The combined
            // cost is 2x parse for ~5% of events (those not dropped)
            // and 1x parse for the 95% we drop. Trade-off accepted.

            // Cheap drop decision (no JSON envelope built yet)
            if (should_drop_by_priority(ev_type)) {
                priority_dropped_++;
                if (priority_dropped_ <= 5 || priority_dropped_ % 1000 == 0) {
                    LOG_INFO("[eBPF] priority_dropped #" << priority_dropped_
                              << " (ev_type=" << ev_type
                              << ", pressure=" << std::fixed << std::setprecision(0)
                              << (100.0 * static_cast<double>(buf_.size())
                                  / static_cast<double>(buf_.capacity())) << "%)");
                }
                events_++;  // total events seen
                continue;
            }

            // Format : "{\"ts\":...,\"pid\":...,\"uid\":...,\"username\":\"...\",\"comm\":\"...\",\"event\":\"...\"}\n"
            std::string raw(buf, static_cast<size_t>(n));
            json item;
            item["event_id"]    = gen_uuid();
            item["source_host"] = cfg_.hostname;
            item["severity"]    = "info";
            item["service"]    = "ebpf";
            item["source_ip"]  = "N/A";  // eBPF events are local, no meaningful source_ip

            // Try to parse the raw event as JSON; build human-readable message
            try {
                json ev = json::parse(raw);

                // Build human-readable message
                std::string ev_type = ev.value("event", "unknown");
                std::string comm = ev.value("comm", "");
                std::string username = ev.value("username", "");
                uint32_t pid_val = ev.value("pid", 0);
                std::string human_msg;

                // v4.8.0 (T4.8): route fim + write_fd events through FimCollector
                // for userspace path resolution, rate limiting, MITRE tagging.
                // The collector will format them as enriched events and push
                // them into the same buffer (buf_) for the Sender to ship.
                //
                // For "fim" events: we ALSO pass the basename+pid+ktime_ns to
                // the FimCollector (which may merge with a future write_fd),
                // and we STILL build the legacy item below for backward compat
                // (in case the FimCollector rejects it — rate-limited, queue
                // full, etc.). The FimCollector publishes enriched events with
                // abs_path + MITRE tags; the legacy path is a fallback.
                //
                // For "write_fd" events: these are internal to V4.8, the legacy
                // path has no handler for type 8 (removed in T4.8.1). We skip
                // the legacy item construction entirely and rely on the
                // FimCollector's enriched event publication.
                if (fim_collector_ && cfg_.fim_engine == "v5_simplified") {
                    if (ev_type == "fim") {
                        std::string fname = ev.value("filename", "");
                        uint64_t kt = ev.value("ktime_ns", (uint64_t)0);
                        if (pid_val > 0 && !fname.empty()) {
                            fim_collector_->on_fim_event(pid_val, fname, kt, "write");
                        }
                        // Continue to legacy path so the basename event is still
                        // logged (the FimCollector publishes an enriched one too).
                    } else if (ev_type == "write_fd") {
                        int fd = ev.value("fd", -1);
                        uint64_t kt = ev.value("ktime_ns", (uint64_t)0);
                        if (pid_val > 0 && fd >= 0) {
                            fim_collector_->on_write_fd_event(pid_val, fd, kt);
                        }
                        // write_fd is internal — don't ship via legacy path
                        // (the FimCollector will publish the resolved event)
                        continue;  // skip the rest of the loop body
                    }
                }

                if (ev_type == "execve") {
                    std::string args = ev.value("args", "");
                    human_msg = "Process executed: " + (comm.empty() ? "<unknown>" : comm);
                    if (!args.empty()) human_msg += " " + args;
                    human_msg += " (pid=" + std::to_string(pid_val);
                    if (!username.empty()) human_msg += ", user=" + username;
                    human_msg += ")";
                } else if (ev_type == "fim") {
                    std::string fname = ev.value("filename", "");
                    human_msg = "File modification: " + (fname.empty() ? "<unknown>" : fname);
                    if (!comm.empty()) human_msg += " by " + comm;
                    human_msg += " (pid=" + std::to_string(pid_val);
                    if (!username.empty()) human_msg += ", user=" + username;
                    human_msg += ")";
                } else if (ev_type == "open") {
                    std::string fname = ev.value("filename", "");
                    std::string flags_str = ev.value("flags", "");
                    human_msg = "File opened: " + (fname.empty() ? "<unknown>" : fname);
                    if (!flags_str.empty()) human_msg += " [" + flags_str + "]";
                    if (!comm.empty()) human_msg += " by " + comm;
                    human_msg += " (pid=" + std::to_string(pid_val);
                    if (!username.empty()) human_msg += ", user=" + username;
                    human_msg += ")";
                } else if (ev_type == "unlink") {
                    std::string fname = ev.value("filename", "");
                    human_msg = "File deleted: " + (fname.empty() ? "<unknown>" : fname);
                    if (!comm.empty()) human_msg += " by " + comm;
                    human_msg += " (pid=" + std::to_string(pid_val);
                    if (!username.empty()) human_msg += ", user=" + username;
                    human_msg += ")";
                } else if (ev_type == "tcp_connect") {
                    std::string src_ip = ev.value("src_ip", "");
                    std::string dst_ip = ev.value("dst_ip", "");
                    int dst_port = ev.value("dst_port", 0);
                    human_msg = "TCP connection: ";
                    if (!comm.empty()) human_msg += comm + " → ";
                    human_msg += dst_ip + ":" + std::to_string(dst_port);
                    if (!src_ip.empty() && src_ip != "0.0.0.0") human_msg += " (from " + src_ip + ")";
                    human_msg += " (pid=" + std::to_string(pid_val);
                    if (!username.empty()) human_msg += ", user=" + username;
                    human_msg += ")";
                    // For tcp_connect, source_ip is meaningful
                    item["source_ip"] = src_ip.empty() ? "N/A" : src_ip;
                } else if (ev_type == "write") {
                    uint32_t fd = ev.value("fd", 0);
                    uint64_t count = ev.value("count", (uint64_t)0);
                    std::string payload = ev.value("payload", "");
                    human_msg = "Write fd=" + std::to_string(fd) + " count=" + std::to_string(count);
                    if (!payload.empty()) human_msg += " payload=\"" + payload.substr(0, 64) + "\"";
                    human_msg += " (pid=" + std::to_string(pid_val);
                    if (!username.empty()) human_msg += ", user=" + username;
                    human_msg += ")";
                } else {
                    human_msg = "eBPF event: " + ev_type + " " + raw;
                }

                // A-07: cap human_msg to prevent unbounded JSON events
                if (human_msg.size() > 4096) {
                    LOG_WARN("[eBPF] human_msg truncated from " << human_msg.size() << " to 4096 bytes");
                    human_msg.resize(4096);
                }

                item["message"] = human_msg;
                item["raw_event"] = raw;  // Keep raw JSON for forensics

                // Propagate key fields to root level for dashboard
                if (!comm.empty()) item["comm"] = comm;
                if (!username.empty()) item["username"] = username;
                if (ev.contains("filename")) item["filename"] = ev["filename"];
                if (ev.contains("dst_ip")) item["dst_ip"] = ev["dst_ip"];
                if (ev.contains("dst_port")) item["dst_port"] = ev["dst_port"];
                if (pid_val > 0) item["pid"] = pid_val;
                if (ev.contains("uid")) item["uid"] = ev["uid"].get<uint32_t>();
                if (ev.contains("inode")) item["inode"] = ev["inode"];

                // eBPF enrichment propagation retiré — le backend (app/enrichment.py) calcule
                // severity_score, mitre, sigma côté serveur. Voir issue SOC-AGENT #40.

                // Also propagate the optional fields from the raw eBPF event
                // that the backend ClickHouse columns expect:
                // - argv (execve): the loader writes it as a string ("a b c"),
                //   but the wire-protocol expects an array. We pass the string
                //   through; the backend parser splits on space.
                // - action (fim): "modify"/"create"/"delete" (string)
                // - flags (open): open flags as string ("O_RDONLY|O_WRONLY")
                // - bytes_size (write): how many bytes were written (number)
                // - family (connect): "ipv4"/"ipv6"/"unix" (string)
                // - source: the original event source ("ebpf"/"fim_collector")
                // - sha256 (fim): file SHA-256, computed by fim_collector.cpp
                //   (NOT by loader.cpp — the loader doesn't have the file
                //   content). When fim_engine=v5_simplified, sha256 comes
                //   from the FimCollector publish, not from this raw event.
                if (ev.contains("argv") && ev["argv"].is_string())
                    item["argv"] = ev["argv"];
                if (ev.contains("action") && ev["action"].is_string())
                    item["action"] = ev["action"];
                if (ev.contains("flags") && ev["flags"].is_string())
                    item["flags"] = ev["flags"];
                if (ev.contains("bytes_size") && ev["bytes_size"].is_number())
                    item["bytes_size"] = ev["bytes_size"];
                if (ev.contains("family") && ev["family"].is_string())
                    item["family"] = ev["family"];
                if (ev.contains("source") && ev["source"].is_string())
                    item["source"] = ev["source"];

                // v3.7: eBPF ↔ journald cross-validation
                // Enregistre cet event dans le buffer circulaire, puis cherche
                // un match journald dans la fenêtre ±2s
                {
                    logsoc::EbpfEntry ebpf_entry;
                    ebpf_entry.ts = static_cast<std::time_t>(ev.value("ts", (uint64_t)0));
                    ebpf_entry.ts_ms = ev.value("ts", (uint64_t)0) * 1000ULL;
                    if (ebpf_entry.ts_ms == 0) ebpf_entry.ts_ms = logsoc::Correlator::now_ms();
                    ebpf_entry.pid = pid_val;
                    ebpf_entry.event = ev_type;
                    ebpf_entry.comm = comm;
                    if (ev.contains("filename")) ebpf_entry.filename = ev["filename"].get<std::string>();

                    logsoc::Correlator::instance().record_ebpf(ebpf_entry);
                    logsoc::Correlator::instance().inc_ebpf_total();

                    // Cherche match journald
                    auto jmatch = logsoc::Correlator::instance().find_journald_for_ebpf(ebpf_entry);
                    if (jmatch) {
                        item["journald_match"] = true;
                        item["journald_message"] = logsoc::Correlator::truncate(jmatch->message, 256);
                        item["journald_unit"] = jmatch->unit;
                        item["journald_identifier"] = jmatch->syslog_id;
                        item["correlation_window_ms"] = (int64_t)ebpf_entry.ts_ms - (int64_t)jmatch->ts_ms;
                        if (item["correlation_window_ms"].get<int64_t>() < 0)
                            item["correlation_window_ms"] = -item["correlation_window_ms"].get<int64_t>();
                        logsoc::Correlator::instance().inc_ebpf_matched();
                    } else {
                        item["journald_match"] = false;
                        item["correlation_window_ms"] = 0;
                    }
                }

                if (ev.contains("event")) {
                    item["tags"] = json::array({ ev["event"].get<std::string>() });
                    // Map event type → severity from config
                    auto sev_it = cfg_.severity_map.find(ev_type);
                    if (sev_it != cfg_.severity_map.end()) {
                        item["severity"] = sev_it->second;
                    } else {
                        auto def_it = cfg_.severity_map.find("default");
                        item["severity"] = (def_it != cfg_.severity_map.end()) ? def_it->second : "info";
                    }
                }
                if (!ev.contains("event")) item["tags"] = json::array({"ebpf"});

                // v3.10.0: YARA HQ hook — scan FIM/open file with active rules
                // This is fire-and-forget: scan_file() does its own throttling,
                // SHA256, HTTP post (via post_match internal to YaraEngine).
                if (cfg_.yara_enabled && yara_engine_ &&
                    (ev_type == "fim" || ev_type == "open")) {
                    std::string yfname = ev.value("filename", "");
                    if (!yfname.empty() && yfname[0] == '/') {
                        yara_engine_->scan_file(yfname, "file");
                    }
                }
            } catch (const std::exception& e) {
                LOG_WARN("[eBPF] JSON parse error: " + std::string(e.what()));
                // T12.13 (audit Nova C-06): same truncation handling as
                // the batch sender (line 1007). Tag the message so the
                // central can see we lost data.
                constexpr size_t MAX_MSG_LEN = 4096;
                if (raw.size() > MAX_MSG_LEN) {
                    item["message"]   = raw.substr(0, MAX_MSG_LEN);
                    item["truncated"] = true;
                    item["orig_len"]  = raw.size();
                } else {
                    item["message"] = raw;
                }
                item["tags"] = json::array({"ebpf"});
            }

            // v3.9.7: backpressure is done BEFORE building the JSON envelope (see above).
            // No more double-parsing here.
            // Write to buffer (same path as other collectors → Sender picks it up)
            // v3.9.7 FIX: wok == true means a drop occurred (oldest was evicted), not the opposite!
            // T4.8.27.15 / 27C.1.6: For critical security events (modload, execve, unlink,
            // ptrace, bpf, accept, vfs_open), use force_push() — these events must NEVER
            // be dropped. They are rare (<10/sec) so brief buffer overflow is acceptable.
            static const std::set<std::string> kCritical = {
                "modload", "execve", "unlink", "ptrace", "bpf", "accept", "vfs_open"
            };
            bool is_critical = kCritical.count(ev_type) > 0;
            bool wok;
            if (is_critical) {
                bool over_cap = buf_.force_push(item.dump());
                wok = over_cap;  // true means we breached cap
                if (over_cap) {
                    LOG_WARN("[eBPF] CRITICAL event " + ev_type + " forced insert (buffer over cap, no drop)");
                }
            } else {
                wok = buf_.drop_oldest_if_full(item.dump());
            }
            if (wok) {
                LOG_ERROR("[eBPF] buf_.push() DROPPED oldest event (buffer full, size>=capacity)");
            }
            if (poll_hits <= 5 || poll_hits % 100 == 0) {
                LOG_DEBUG("[eBPF] write_event result=" << wok << " payload=" << item.dump().size() << " bytes");
            }
            events_++;
        }
        LOG_INFO("[-] eBPF collector stopped (" << events_ << " events, "
                  << priority_dropped_ << " priority-dropped)");
    }
};

/* ─── Signal handlers ─── */
void signal_handler(int) { g_running = false; }

/* ─── WAL directory helper ─── */
std::string resolve_wal_dir(const std::string& config_path,
                            const std::string& cfg_wal_dir,
                            const std::string& data_dir) {
    std::string dir = cfg_wal_dir;
    if (dir.empty()) {
        if (!data_dir.empty()) {
            dir = data_dir + "/wal";
        } else {
            // systemd ProtectSystem=full blocks writes under /etc/
            auto parent = fs::path(config_path).parent_path().string();
            if (!parent.empty() && parent.rfind("/etc/", 0) == 0) {
                dir = "/var/lib/logsoc-agent/wal";
            } else {
                dir = parent;
                if (dir.empty()) dir = ".";
                dir += "/wal";
            }
        }
    }
    fs::create_directories(dir);
    return dir;
}

/* ─── T64.2.2 (v3.20.0): Policy pull from central ───
 *
 * Polls GET /api/v1/agent-config/policy every 5 minutes (300s) and
 * updates cfg.policy with the central's view. On failure, keeps the
 * last good policy (no degradation to defaults). First pull is done
 * synchronously at boot in main() before threads start, so cfg.policy
 * is always populated before YaraShipper / FanotifyCollector read it.
 *
 * HMAC format: HMAC-SHA256(hmac_secret, f"{timestamp}.{agent_id}.GET./api/v1/agent-config/policy")
 * (matches backend _verify_hmac_get in app/routers/agent_config.py)
 */

static size_t policy_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* s = static_cast<std::string*>(userp);
    s->append(static_cast<char*>(contents), total);
    return total;
}

// Result of one pull attempt (for logging/audit only)
struct PolicyPullResult {
    bool ok = false;
    long http_code = 0;
    std::string error;
    bool changed = false;  // policy values actually changed since last pull
};

// Single GET /api/v1/agent-config/policy.
// Returns parsed fields in cfg.policy on success. Network/parse failures
// return ok=false and DO NOT mutate cfg (so we keep the last good policy).
static PolicyPullResult pull_policy_once(const runtime_cred::RuntimeCredentials& cred,
                                         AgentConfig& cfg,
                                         const std::string& path) {
    PolicyPullResult r;
    auto now = std::chrono::system_clock::now();
    int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string ts_str = std::to_string(ts);
    std::string sig = agent_v3::compute_policy_get_hmac(cred.hmac_secret, cred.agent_id,
                                                       ts_str, "GET", path);
    std::string url = cred.central_url + path;

    CURL* curl = curl_easy_init();
    if (!curl) { r.error = "curl_easy_init failed"; return r; }

    std::string body;
    struct curl_slist* hdr = nullptr;
    hdr = curl_slist_append(hdr, ("X-Agent-Id: " + cred.agent_id).c_str());
    hdr = curl_slist_append(hdr, ("X-Timestamp: " + ts_str).c_str());
    hdr = curl_slist_append(hdr, ("X-Signature: " + sig).c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, policy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.http_code);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        r.error = std::string("curl: ") + curl_easy_strerror(res);
        return r;
    }
    if (r.http_code != 200) {
        r.error = "HTTP " + std::to_string(r.http_code) + ": " + body.substr(0, 200);
        return r;
    }

    // Parse JSON response
    json j;
    try {
        j = json::parse(body);
    } catch (const std::exception& e) {
        r.error = std::string("json parse: ") + e.what();
        return r;
    }
    if (!j.is_object()) {
        r.error = "response is not a JSON object";
        return r;
    }
    // KISS / 2026-06-11: accept BOTH response shapes for forward + backward compat:
    //   1. {"policy": { ... }}  — wrapped (what the original spec said)
    //   2. {"fim_watch_paths": ..., ...}  — flat
    //      (what the v0.14 backend actually returns, per AgentPolicyResponse
    //      Pydantic model — no `policy` envelope).
    // The flat shape is what Hestia is currently sending. To avoid forcing
    // a backend re-deploy + DB row + PUT, the agent now transparently
    // unwraps the policy key if present, otherwise treats the root object
    // as the policy payload.
    // T12.16: metrics_bind_address is no longer applied (HTTP server removed).
    // The field is silently ignored if present in the policy payload.
    const json* policy_ptr = nullptr;
    if (j.contains("policy") && j["policy"].is_object()) {
        policy_ptr = &j["policy"];
    } else {
        // Flat shape: the response IS the policy. Use j as the source.
        policy_ptr = &j;
    }
    const auto& p = *policy_ptr;

    // T12 audit fix #24: lock the policy mutex for the entire mutation
    // + change-detection window. Without it, the main loop could be
    // reading cfg.policy.fim_watch_paths (iterating for rebuild) at
    // the same time we assign it via std::move → iterator invalidation
    // and use-after-free crash. The lock is held briefly (a few µs) so
    // contention is negligible.
    std::lock_guard<std::mutex> policy_lock(cfg.policy.policy_mtx);

    // Capture before-state for change detection
    std::vector<std::string> old_paths = cfg.policy.fim_watch_paths;
    int old_thresh = cfg.policy.ship_heuristic_threshold;

    // T12.16: metrics_bind_address validation block removed (HTTP server
    // is gone). The field, if present in the policy payload, is silently
    // ignored — no more IPv4 validation, no more 'old_bind' tracking.
    if (p.contains("fim_watch_paths") && p["fim_watch_paths"].is_array()) {
        std::vector<std::string> np;
        np.reserve(p["fim_watch_paths"].size());
        for (const auto& v : p["fim_watch_paths"]) {
            if (!v.is_string()) continue;
            std::string path = v.get<std::string>();
            // T4.8.11: defensive validation
            if (path.empty()) continue;                      // skip empty
            if (path.size() > 4096) continue;                 // skip absurdly long
            if (path[0] != '/') continue;                     // require absolute
            // Reject ".." path components (no traversal)
            if (path.find("/../") != std::string::npos ||
                path.find("../") == 0 ||
                path.find("/..") == path.size() - 3) {
                continue;
            }
            np.push_back(std::move(path));
        }
        cfg.policy.fim_watch_paths = std::move(np);
    }
    if (p.contains("ship_heuristic_threshold") && p["ship_heuristic_threshold"].is_number_integer()) {
        int t = p["ship_heuristic_threshold"].get<int>();
        if (t < 0) t = 0;
        if (t > 10) t = 10;
        cfg.policy.ship_heuristic_threshold = t;
    }
    cfg.policy.source = "central";
    cfg.policy.last_pulled_at = ts;

    // Detect changes for audit log
    if (old_paths != cfg.policy.fim_watch_paths ||
        old_thresh != cfg.policy.ship_heuristic_threshold) {
        r.changed = true;
        // T64.4.2: signal main loop to rebuild FanotifyCollector (only if paths changed)
        if (old_paths != cfg.policy.fim_watch_paths) {
            cfg.policy.fim_watch_paths_dirty.store(true);
            LOG_INFO("[PolicyPuller] fim_watch_paths changed: " << old_paths.size()
                     << " -> " << cfg.policy.fim_watch_paths.size()
                     << " paths; main loop will restart FanotifyCollector");
        }
    }
    // T30.3: read the central enabled_probes map (optional). When it
    // differs from the local config, mark enabled_probes_dirty so the
    // main loop calls rebuild_ebpf_probes() outside of the policy-pull
    // thread (the rebuild is not safe during the policy-pull callback).
    if (p.contains("enabled_probes") && p["enabled_probes"].is_object()) {
        auto prev_ep = cfg.policy.enabled_probes;
        for (auto it = p["enabled_probes"].begin();
             it != p["enabled_probes"].end(); ++it) {
            if (it.value().is_boolean()) {
                cfg.policy.enabled_probes[it.key()] = it.value().get<bool>();
            }
        }
        if (prev_ep != cfg.policy.enabled_probes) {
            cfg.policy.enabled_probes_dirty.store(true);
            LOG_INFO("[PolicyPuller] enabled_probes changed; main loop will rebuild eBPF links");
            r.changed = true;
        }
    }

    r.ok = true;
    return r;
}

// Background thread: pulls policy every interval_sec.
// Stops cleanly when stop() is called (typically on shutdown).
class PolicyPuller {
public:
    PolicyPuller(const runtime_cred::RuntimeCredentials& cred,
                 AgentConfig& cfg,
                 const std::string& path,
                 int interval_sec = 300)
        : cred_(cred), cfg_(cfg), path_(path), interval_sec_(interval_sec) {}

    void start() {
        running_ = true;
        thread_ = std::thread([this] { run(); });
    }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
private:
    void run() {
        LOG_INFO("[PolicyPuller] started, interval=" << interval_sec_ << "s path=" << path_);
        while (running_) {
            // Sleep interval_sec in 1s chunks so stop() is reactive
            for (int i = 0; i < interval_sec_ && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!running_) break;
            try {
                auto r = pull_policy_once(cred_, cfg_, path_);
                if (r.ok) {
                    if (r.changed) {
                        // T12.16: bind= no longer logged (HTTP server removed).
                        LOG_INFO("[PolicyPuller] policy updated: watch_paths=" << cfg_.policy.fim_watch_paths.size()
                                 << " threshold=" << cfg_.policy.ship_heuristic_threshold);
                    } else {
                        LOG_VERBOSE("[PolicyPuller] pull OK, no changes");
                    }
                } else {
                    LOG_WARN("[PolicyPuller] pull failed: " << r.error
                             << " (keeping last good policy from " << cfg_.policy.source << ")");
                }
            } catch (const std::exception& e) {
                LOG_WARN("[PolicyPuller] exception: " << e.what());
            }
        }
        LOG_INFO("[PolicyPuller] stopped");
    }

    const runtime_cred::RuntimeCredentials& cred_;
    AgentConfig& cfg_;
    const std::string path_;
    int interval_sec_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

/* ─── T77 / YARA Ruleset Puller (v3.21.0) ──────────────────────────────
 *
 * Companion to PolicyPuller. Polls the central's
 *   GET /api/v1/yara/ruleset
 * endpoint every 5min, checks sha256, and on change does:
 *   1. GET /api/v1/yara/ruleset/download  (3MB blob)
 *   2. sha256 verify
 *   3. yara_engine.load_compiled_blob()
 *   4. atomic swap of YR_RULES* (3s downtime, vs 30s+ if compile in prod)
 *
 * PITFALLS:
 *   - The agent MUST keep the previous YR_RULES* valid until
 *     the new one is fully swapped (load_compiled_blob does
 *     this internally).
 *   - On sha256 mismatch, we DISCARD the blob and keep the
 *     previous one (defense against MITM + corruption).
 *   - The interval is 5min (same as policy). For tighter SLA,
 *     drop to 60s — but each poll = 1 GET (metadata) + maybe
 *     1 GET (download), so don't over-poll.
 *   - The "YaraEngine*" is a non-owning pointer (lives in main()
 *     alongside the puller). We never destroy it here.
 *   - Thread-safe: YaraEngine's scan methods are lock-free
 *     readers; the swap in load_compiled_blob is mutex-protected.
 */
struct YaraRulesetPullResult {
    bool ok = false;
    long http_code = 0;
    std::string error;
    bool changed = false;  // ruleset actually changed since last pull
    std::string new_sha;   // A-11: sha256 of the newly downloaded ruleset (set when changed=true)
};

static YaraRulesetPullResult pull_yara_ruleset_metadata(
    const runtime_cred::RuntimeCredentials& cred,
    const std::string& path,
    std::string* out_sha256,
    int64_t* out_bytes_size,
    std::string* out_comment,
    std::string* out_severity_json)
{
    YaraRulesetPullResult r;
    auto now = std::chrono::system_clock::now();
    int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string ts_str = std::to_string(ts);
    std::string sig = agent_v3::compute_policy_get_hmac(cred.hmac_secret, cred.agent_id,
                                                       ts_str, "GET", path);
    std::string url = cred.central_url + path;

    CURL* curl = curl_easy_init();
    if (!curl) { r.error = "curl_easy_init failed"; return r; }

    std::string body;
    struct curl_slist* hdr = nullptr;
    hdr = curl_slist_append(hdr, ("X-Agent-Id: " + cred.agent_id).c_str());
    hdr = curl_slist_append(hdr, ("X-Timestamp: " + ts_str).c_str());
    hdr = curl_slist_append(hdr, ("X-Signature: " + sig).c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, policy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.http_code);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        r.error = std::string("curl: ") + curl_easy_strerror(res);
        return r;
    }
    if (r.http_code != 200) {
        r.error = "HTTP " + std::to_string(r.http_code) + ": " + body.substr(0, 200);
        return r;
    }

    json j;
    try {
        j = json::parse(body);
    } catch (const std::exception& e) {
        r.error = std::string("json parse: ") + e.what();
        return r;
    }
    if (!j.is_object()) {
        r.error = "response is not a JSON object";
        return r;
    }

    if (j.contains("sha256") && j["sha256"].is_string()) {
        *out_sha256 = j["sha256"].get<std::string>();
    } else {
        r.error = "missing 'sha256' field";
        return r;
    }
    if (j.contains("bytes_size") && j["bytes_size"].is_number_integer()) {
        *out_bytes_size = j["bytes_size"].get<int64_t>();
    }
    if (j.contains("comment") && j["comment"].is_string()) {
        *out_comment = j["comment"].get<std::string>();
    }
    // T77.6: extract the severity sidecar JSON. The backend
    // stores {rule_id: severity} as a JSON string in this field.
    // If absent (old backend pre-T77.6), we leave it empty and
    // the agent's load_compiled_blob will skip populating the
    // rule_severity_ map (matches get severity="unknown" in UI).
    if (j.contains("severity_json") && j["severity_json"].is_string()) {
        *out_severity_json = j["severity_json"].get<std::string>();
    }

    r.ok = true;
    return r;
}

// Download the blob. PITFALL T77.2: the backend returns a JSON
// envelope (not raw binary), so we accumulate the response in
// a string, parse out `ruleset_blob_b64`, then base64-decode
// the actual blob bytes for libyara.
//
// Example response body:
//   {"ruleset_blob_b64":"<base64>","sha256":"...","source_count":7761,
//    "bytes_size":3124761,"compiled_at":"2026-06-12T..."}
//
// Write callback: append to a string (this is JSON text, not
// binary — must not split UTF-8 boundaries or skip NULs).
static size_t yara_blob_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* s = static_cast<std::string*>(userp);
    s->append(static_cast<char*>(contents), total);
    return total;
}

static YaraRulesetPullResult download_yara_ruleset_blob(
    const runtime_cred::RuntimeCredentials& cred,
    const std::string& path,
    std::vector<uint8_t>* out_blob)
{
    YaraRulesetPullResult r;
    auto now = std::chrono::system_clock::now();
    int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string ts_str = std::to_string(ts);
    std::string sig = agent_v3::compute_policy_get_hmac(cred.hmac_secret, cred.agent_id,
                                                       ts_str, "GET", path);
    std::string url = cred.central_url + path;

    CURL* curl = curl_easy_init();
    if (!curl) { r.error = "curl_easy_init failed"; return r; }

    std::string body;
    struct curl_slist* hdr = nullptr;
    hdr = curl_slist_append(hdr, ("X-Agent-Id: " + cred.agent_id).c_str());
    hdr = curl_slist_append(hdr, ("X-Timestamp: " + ts_str).c_str());
    hdr = curl_slist_append(hdr, ("X-Signature: " + sig).c_str());
    hdr = curl_slist_append(hdr, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    // 3MB blob at ~10Mbps = 3s; allow 30s for slow links.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, yara_blob_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.http_code);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        r.error = std::string("curl: ") + curl_easy_strerror(res);
        return r;
    }
    if (r.http_code != 200) {
        r.error = "HTTP " + std::to_string(r.http_code) + ": " + body.substr(0, 200);
        return r;
    }

    // Parse JSON envelope. Extract ruleset_blob_b64, base64-decode
    // it into out_blob. PITFALL: empty blob (placeholder row) is
    // VALID — bytes_size=0, sha256=''. The agent should keep its
    // current local ruleset in that case (caller checks sha
    // unchanged and returns early).
    json j;
    try {
        j = json::parse(body);
    } catch (const std::exception& e) {
        r.error = std::string("download JSON parse: ") + e.what();
        return r;
    }
    if (!j.is_object() || !j.contains("ruleset_blob_b64") ||
        !j["ruleset_blob_b64"].is_string()) {
        r.error = "download response missing 'ruleset_blob_b64' string field";
        return r;
    }
    std::string blob_b64 = j["ruleset_blob_b64"].get<std::string>();
    if (blob_b64.empty()) {
        // Placeholder row: no ruleset pushed yet. The caller
        // (pull_yara_ruleset_once) will see bytes_size=0 in
        // the metadata and short-circuit anyway, but we also
        // handle the empty case here for safety.
        out_blob->clear();
        r.ok = true;
        return r;
    }

    // A-10: Replace hand-rolled base64 decoder with OpenSSL BIO.
    // The hand-rolled version had edge-case risks (padding, whitespace).
    // OpenSSL's BIO_read handles all standard base64 variants correctly.
    std::string blob_decoded;
    {
        BIO* bio = BIO_new(BIO_f_base64());
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO* mem = BIO_new_mem_buf(blob_b64.data(), static_cast<int>(blob_b64.size()));
        bio = BIO_push(bio, mem);
        blob_decoded.resize(blob_b64.size());
        int len = BIO_read(bio, &blob_decoded[0], static_cast<int>(blob_decoded.size()));
        BIO_free_all(bio);
        if (len <= 0) {
            r.error = "base64 decode failed (OpenSSL BIO_read returned " + std::to_string(len) + ")";
            return r;
        }
        blob_decoded.resize(static_cast<size_t>(len));
    }
    out_blob->assign(blob_decoded.begin(), blob_decoded.end());
    r.ok = true;
    return r;
}

static YaraRulesetPullResult pull_yara_ruleset_once(
    const runtime_cred::RuntimeCredentials& cred,
    logsoc::YaraEngine* yara_engine,
    const std::string& last_local_sha256,
    const std::string& meta_path,
    const std::string& download_path)
{
    YaraRulesetPullResult r;
    if (!yara_engine) {
        r.error = "yara_engine is null";
        return r;
    }

    // Step 1: fetch metadata
    std::string remote_sha;
    int64_t remote_bytes = 0;
    std::string remote_comment;
    std::string remote_severity_json;  // T77.6
    auto meta_r = pull_yara_ruleset_metadata(cred, meta_path, &remote_sha,
                                              &remote_bytes, &remote_comment,
                                              &remote_severity_json);
    if (!meta_r.ok) {
        r.error = "metadata GET failed: " + meta_r.error;
        return r;
    }
    if (remote_sha.empty()) {
        r.error = "empty sha256 in metadata response";
        return r;
    }
    if (remote_bytes == 0) {
        // No ruleset pushed yet (placeholder row). No-op.
        LOG_INFO("[YaraRulesetPuller] no ruleset pushed yet (sha256=''), skipping");
        r.ok = true;
        return r;
    }
    if (remote_sha == last_local_sha256) {
        // No change since last pull.
        LOG_VERBOSE("[YaraRulesetPuller] sha256 unchanged (" << remote_sha.substr(0, 12) << "...)");
        r.ok = true;
        r.changed = false;
        return r;
    }

    // Step 2: download the blob
    std::vector<uint8_t> blob;
    auto dl_r = download_yara_ruleset_blob(cred, download_path, &blob);
    if (!dl_r.ok) {
        r.error = "blob download failed: " + dl_r.error;
        return r;
    }
    if (blob.empty()) {
        r.error = "downloaded blob is empty";
        return r;
    }
    if ((int64_t)blob.size() != remote_bytes) {
        r.error = "downloaded size mismatch: expected " + std::to_string(remote_bytes) +
                  ", got " + std::to_string(blob.size());
        return r;
    }

    // Step 3: load into YaraEngine. load_compiled_blob does the
    // sha256 verify + atomic swap internally. T77.6: we also
    // pass the severity_json sidecar so rule_severity_ gets
    // populated. If severity_json is empty (old backend pre-T77.6),
    // load_compiled_blob leaves rule_severity_ empty (matches
    // will show severity="unknown" in the UI — acceptable
    // fallback, the next push with a real sidecar fixes it).
    size_t n = yara_engine->load_compiled_blob(blob, remote_sha, remote_severity_json);
    if (n == 0) {
        r.error = "load_compiled_blob failed (sha256 verify or libyara load error)";
        return r;
    }
    r.ok = true;
    r.changed = true;
    r.new_sha = remote_sha;  // A-11: record the sha256 after successful download+verify
    return r;
}

class YaraRulesetPuller {
public:
    YaraRulesetPuller(const runtime_cred::RuntimeCredentials& cred,
                     logsoc::YaraEngine* yara_engine,
                     const std::string& meta_path,
                     const std::string& download_path,
                     int interval_sec = 300)
        : cred_(cred), yara_engine_(yara_engine),
          meta_path_(meta_path), download_path_(download_path),
          interval_sec_(interval_sec) {}

    void start() {
        running_ = true;
        thread_ = std::thread([this] { run(); });
    }
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
    // For the main thread to read the last successful sha256
    // (used to short-circuit repeated pulls).
    const std::string& last_local_sha256() const { return last_local_sha_; }

private:
    void run() {
        LOG_INFO("[YaraRulesetPuller] started, interval=" << interval_sec_ << "s");
        while (running_) {
            for (int i = 0; i < interval_sec_ && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!running_) break;
            try {
                auto r = pull_yara_ruleset_once(cred_, yara_engine_,
                                                 last_local_sha_,
                                                 meta_path_, download_path_);
                if (r.ok) {
                    if (r.changed) {
                        // A-11: set last_local_sha_ AFTER successful download+verify,
                        // not before. This ensures we short-circuit correctly on the
                        // next pull cycle and don't re-download the same ruleset.
                        last_local_sha_ = r.new_sha;
                        LOG_INFO("[YaraRulesetPuller] ruleset updated: "
                                 << "active_rules=" << yara_engine_->rule_count()
                                 << " sha256=" << r.new_sha.substr(0, 12) << "...");
                    } else {
                        LOG_VERBOSE("[YaraRulesetPuller] pull OK, no changes");
                    }
                } else {
                    LOG_WARN("[YaraRulesetPuller] pull failed: " << r.error
                             << " (keeping last good ruleset)");
                }
            } catch (const std::exception& e) {
                LOG_WARN("[YaraRulesetPuller] exception: " << e.what());
            }
        }
        LOG_INFO("[YaraRulesetPuller] stopped");
    }

    const runtime_cred::RuntimeCredentials& cred_;
    logsoc::YaraEngine* yara_engine_;
    const std::string meta_path_;
    const std::string download_path_;
    int interval_sec_;
    std::string last_local_sha_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

/* ─── Main ─── */
int main(int argc, char* argv[]) {
    std::string config_path = "config.json";
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--debug" || arg == "-d") { g_log_level = 4; }
        else if (arg == "--trace" || arg == "-t") { g_log_level = 5; }
        else if (arg == "--verbose" || arg == "-v") { g_log_level = 3; }
        else if (arg == "--quiet" || arg == "-q") { g_log_level = 1; }  // WARN+ only
        else if (arg == "--help" || arg == "-h") {
            std::cerr << "LogSOC Agent v3.11\n"
                      << "Usage: soc_agent [OPTIONS] [config_path]\n\n"
                      << "Options:\n"
                      << "  --debug, -d    Debug output (level 4)\n"
                      << "  --trace, -t    Trace output (level 5, very verbose)\n"
                      << "  --verbose, -v  Verbose output (level 3)\n"
                      << "  --quiet, -q    Warnings and errors only (level 1)\n"
                      << "  --help, -h     Show this help\n"
                      << "  config_path    Path to config.json (default: ./config.json)\n";
            return 0;
        }
        else if (!arg.empty() && arg[0] != '-') config_path = arg;
    }

    try {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        LOG_INFO("[*] LogSOC Agent " << AgentConfig{}.version << " starting...");

        // ── T13.9 Threading Model ──────────────────────────────────────────
        //
        // Threads in this process:
        //   1. main thread       — config load, init, 30s main loop, shutdown
        //   2. sender thread     — Sender::run(), drains InMemoryBuffer, POSTs
        //   3. eBPF collector    — EbpfCollector::run(), polls ringbuf at 10Hz
        //   4. heartbeat thread  — perform_heartbeat() every N sec, hot-reload
        //   5. metrics thread    — T31 metrics shipper, 60s interval
        //   6. fim_shipper thread — drains FimCollector ship queue into buffer
        //   7. action_validator  — drains action_recommender IPC queue
        //   8. PolicyPuller      — background policy pull every 5 min
        //   9. YaraRulesetPuller — background YARA ruleset pull
        //  10. JournaldCollector — reads systemd journal via sd_journal API
        //
        // Child processes (fork + setuid, NOT threads):
        //   - WalWriterProcess         — writes WAL files as logsoc:logsoc
        //   - FimScannerProcess        — scans filesystem as logsoc:logsoc + DAC_READ_SEARCH
        //   - ActionRecommenderProcess — pattern matching as logsoc:logsoc
        //
        // Shared state and their guards:
        //   cfg (AgentConfig)     — main thread owns; heartbeat reads via &cfg ref.
        //                           Safe because heartbeat joins before cfg destructs.
        //   buffer (InMemoryBuffer) — thread-safe (internal mutex + atomic).
        //   fallback_wal           — thread-safe (WalWriterProcess IPC).
        //   ebpf_ptr (unique_ptr)  — main thread owns; heartbeat reads via &ebpf_ptr
        //                           ref. Safe because heartbeat joins BEFORE
        //                           ebpf_ptr.reset() (killed audit A-14 UAF).
        //   app_collectors (vector) — guarded by app_collectors_mtx. Mutex covers
        //                           rebuild (heartbeat) + initial start (main);
        //                           shutdown is safe because heartbeat is joined
        //                           before the stop loop (killed audit H-12 race).
        //   fanotify_coll          — main thread owns; heartbeat rebuilds via ref.
        //                           Safe because heartbeat joins before destruct.
        //   yara_engine            — main thread owns; heartbeat reads via ref.
        //                           Safe because heartbeat joins before destruct.
        //
        // Shutdown order (CRITICAL — UAF prevention, see block comments inline):
        //   1.  g_running = false (signals all loops)
        //   2.  buffer.stop()
        //   3.  drain buffer → fallback_wal
        //   4.  app_collectors stop (heartbeat NOT yet joined; mutex held by
        //       no one since rebuild path is idle; safe to iterate)
        //   5.  journald / fanotify / sender / puller stop
        //   6.  fim_shipper_stop + join
        //   7.  action_validator_stop + join
        //   8.  action_recommender.reset()
        //   9.  net.stop()
        //  10.  metrics_thread.join()
        //  11.  heartbeat_thread.join()  ← MUST be before ebpf_ptr.reset()
        //  12.  ebpf_ptr->stop() + reset  ← AFTER heartbeat join (kills A-14)
        //  13.  yara pullers stop + yara_engine.reset()
        // ──────────────────────────────────────────────────────────────────

        // 1. Load config
        AgentConfig cfg;
        load_config(config_path, cfg);
        std::string config_dir = fs::path(config_path).parent_path().string();
        if (config_dir.empty()) config_dir = ".";
        // v3.2.5: persist creds in data_dir (systemd ReadWritePaths), fallback to /var/lib/logsoc-agent
        std::string data_dir = cfg.data_dir;
        if (data_dir.empty()) {
            // If config is under /etc, use /var/lib/logsoc-agent for state persistence
            if (config_dir == "/etc/logsoc-agent" || config_dir.rfind("/etc/", 0) == 0) {
                data_dir = "/var/lib/logsoc-agent";
            } else {
                data_dir = config_dir;
            }
        }
        if (!fs::exists(data_dir)) fs::create_directories(data_dir);

        // 1.5 Self-integrity check (SHA-256 of running binary + config)
        {
            std::string binary_path = fs::read_symlink("/proc/self/exe").string();
            std::string config_hash = crypto::sha256_file(config_path);
            std::string binary_hash = crypto::sha256_file(binary_path);
            LOG_INFO("[INTegrity] config_hash=" << config_hash.substr(0, 16) << "..."
                      << " binary_hash=" << binary_hash.substr(0, 16) << "...");
            // Store hash for heartbeat/verification
            cfg.extra_options["config_sha256"] = config_hash;
            cfg.extra_options["binary_sha256"] = binary_hash;

            // T30.5: compare against the install-time reference hash
            // written by packaging/debian/DEBIAN/postinst. If they differ,
            // the binary was modified after install (could be a legit
            // upgrade, or could be a tampering attempt). The flag is
            // shipped in the heartbeat (T30.5) for the backend to log.
            std::ifstream ref_ifs("/var/lib/logsoc-agent/install.sha256");
            if (ref_ifs) {
                std::string ref_hash;
                ref_ifs >> ref_hash;
                ref_ifs.close();
                if (!ref_hash.empty() && ref_hash != binary_hash) {
                    LOG_WARN("[INTegrity] binary hash mismatch — "
                             "ref=" << ref_hash.substr(0, 16) << " "
                             << "current=" << binary_hash.substr(0, 16));
                    cfg.extra_options["binary_integrity_ok"] = "false";
                } else {
                    cfg.extra_options["binary_integrity_ok"] = "true";
                }
            } else {
                // No reference hash (probably an upgrade from a pre-T30.5
                // install, or a dev build). Treat as unknown, not failed.
                cfg.extra_options["binary_integrity_ok"] = "unknown";
            }
        }

        // 2. v3.8.0: Runtime credentials in RAM only.
        // Auth flow: read agent_id from agent.identity, then call
        // /api/v1/agents/{id}/activate to get hmac_secret + wal_fallback_key.
        // If no agent.identity, fall back to full register/poll flow.
        runtime_cred::RuntimeCredentials cred;
        bool need_registration = false;
        if (runtime_cred::load_agent_identity(data_dir, cred.agent_id)) {
            LOG_INFO("[AUTH] Loaded agent_id from disk: " + cred.agent_id);
            // Central URL not persisted; we re-derive from cfg (or read from agent.identity if we extended it)
            cred.central_url = cfg.central_url;
            // Call /activate to get fresh creds in RAM (server computes fingerprint match)
            // On HTTP 404 the agent_id no longer exists on the server; fall through to re-registration.
            // On other failures, retry with backoff instead of crashing.
            long activate_http_code = 0;
            if (!cred.load_from_server(cred.central_url, cred.agent_id, &activate_http_code)) {
                if (activate_http_code == 404) {
                    LOG_WARN("[AUTH] Agent ID not found on server (HTTP 404). Re-registering...");
                    // Remove stale agent.identity so we re-register cleanly
                    std::filesystem::remove(data_dir + "/agent.identity");
                    need_registration = true;
                } else {
                    LOG_WARN("[AUTH] /activate failed (HTTP " + std::to_string(activate_http_code) + "). Will retry in 60s...");
                    std::this_thread::sleep_for(std::chrono::seconds(60));
                    // Retry once more before giving up
                    if (!cred.load_from_server(cred.central_url, cred.agent_id)) {
                        LOG_ERROR("[!] Activation failed after retry. Check network/backend.");
                        return 1;
                    }
                    if (cred.device_fingerprint.empty()) {
                        LOG_WARN("[!] Server did not return expected fingerprint (legacy response?)");
                    }
                    LOG_INFO("[AUTH] Credentials in RAM. Nothing written to disk.");
                }
            } else {
                if (cred.device_fingerprint.empty()) {
                    LOG_WARN("[!] Server did not return expected fingerprint (legacy response?)");
                }
                LOG_INFO("[AUTH] Credentials in RAM. Nothing written to disk.");
            }
        } else {
            need_registration = true;
        }

        if (need_registration) {
            LOG_INFO("[AUTH] No agent.identity. Starting registration...");
            std::string request_id, agent_id, central_url;
            if (!agent_v3::perform_registration(cfg.central_url, cfg.hostname,
                                                  AGENT_VERSION, request_id, agent_id,
                                                  central_url)) {
                LOG_ERROR("[!] Registration failed. Check connectivity and backend status.");
                return 1;
            }
            // Persist just agent_id to agent.identity (0600)
            if (!runtime_cred::save_agent_identity(data_dir, agent_id)) {
                LOG_WARN("[!] Could not save agent.identity to disk — re-registration will be required at next boot");
            }
            cred.agent_id = agent_id;
            cred.central_url = central_url;
            LOG_INFO("[AUTH] Register accepted. Waiting admin approval...");
            // Poll for approval (re-uses existing poll_activation_status logic)
            agent_v3::Credentials legacy_cred;
            if (!agent_v3::poll_activation_status(cred.central_url, request_id, agent_id,
                                                     legacy_cred, 3600, 10, data_dir)) {
                LOG_ERROR("[!] Activation failed or rejected. Contact admin.");
                return 1;
            }
            // Copy hmac_secret from legacy cred response
            cred.hmac_secret = legacy_cred.hmac_secret;
            cred.token = legacy_cred.token;
            // Now do one /activate call to get the wal_fallback_key cleanly
            if (!cred.load_from_server(cred.central_url, cred.agent_id)) {
                LOG_WARN("[!] /activate failed — wal_fallback_key unavailable, fallback WAL disabled");
            } else {
                LOG_INFO("[AUTH] wal_fallback_key received from server (server-stored).");
            }
        }

        // 3. v3.8.0: InMemoryBuffer + FallbackWAL.
        // T13 (audit 2026-06-16): the FallbackWAL instance is now wrapped
        // in wal_writer::WalWriterProcess. The parent (this process, root)
        // holds a handle; the actual filesystem writes happen in a forked
        // child that has called setuid(logsoc)/setgid(logsoc). The IPC
        // channel is a socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)
        // created right before the fork, then closed on each side.
        //
        // The child never sees the network. The parent never touches the
        // disk. /var/lib/logsoc-agent/wal/ files are therefore owned by
        // logsoc:logsoc automatically, no chown needed.
        std::vector<uint8_t> salt_v({'f','w','a','l','-','a','e','s','-','s','a','l','t','-','v','1'});
        std::vector<uint8_t> aes_key = crypto::derive_key(cred.hmac_secret, salt_v, 32);
        wal_writer::Config wwp_cfg;
        wwp_cfg.wal_user  = "logsoc";
        wwp_cfg.wal_group = "logsoc";
        wwp_cfg.data_dir  = resolve_wal_dir(config_path, "/var/lib/logsoc-agent/wal", cfg.data_dir);
        wwp_cfg.aes_key   = aes_key;
        wwp_cfg.agent_id  = cred.agent_id;
        wal_writer::WalWriterProcess fallback_wal(std::move(wwp_cfg));
        if (!fallback_wal.start()) {
            LOG_ERROR("[!] WalWriterProcess: failed to fork child — fallback WAL disabled");
        } else if (fallback_wal.is_alive()) {
            LOG_INFO("[*] FallbackWAL ready (via child process, uid="
                     << "logsoc" << ", " << fallback_wal.count() << " events on disk)");
        } else {
            LOG_WARN("[!] FallbackWAL: child not alive, will lazy-create on first push");
        }

        // In-memory ring buffer — primary path
        InMemoryBuffer<std::string> buffer(cfg.in_memory_buffer_capacity);
        LOG_INFO("[*] InMemoryBuffer ready: capacity=" << buffer.capacity() << " events");

        // --- eBPF priority test (v3.2 minimal) ---
        std::string ebpf_mode = "none";
        std::string ebpf_reason = "not_tested";
        bool use_ebpf = false;
        if (cfg.module_ebpf) {
        // Apply local_filters to eBPF (v3.5 — spec v4.1)
            if (!cfg.local_filters.connect_ignore_ports.empty()) {
                ebpf::set_filter_connect_ports(cfg.local_filters.connect_ignore_ports);
                LOG_INFO("[eBPF] Filter: connect.ignore_ports (" << cfg.local_filters.connect_ignore_ports.size() << " ports)");
            }
            if (!cfg.local_filters.connect_ignore_ips.empty()) {
                ebpf::set_filter_connect_ips(cfg.local_filters.connect_ignore_ips);
                LOG_INFO("[eBPF] Filter: connect.ignore_ips (" << cfg.local_filters.connect_ignore_ips.size() << " IPs/CIDRs)");
            }
            if (!cfg.local_filters.execve_ignore_comm.empty()) {
                ebpf::set_filter_execve_comm(cfg.local_filters.execve_ignore_comm);
                LOG_INFO("[eBPF] Filter: execve.ignore_comm (" << cfg.local_filters.execve_ignore_comm.size() << " comms)");
            }
            if (!cfg.local_filters.open_ignore_paths.empty()) {
                ebpf::set_filter_open_paths(cfg.local_filters.open_ignore_paths);
                LOG_INFO("[eBPF] Filter: open.ignore_paths (" << cfg.local_filters.open_ignore_paths.size() << " paths)");
            }
            if (!cfg.local_filters.unlink_ignore_paths.empty()) {
                ebpf::set_filter_unlink_paths(cfg.local_filters.unlink_ignore_paths);
                LOG_INFO("[eBPF] Filter: unlink.ignore_paths (" << cfg.local_filters.unlink_ignore_paths.size() << " paths)");
            }
            ebpf::set_filter_ignore_rdonly(cfg.local_filters.open_ignore_rdonly);
            ebpf::set_rate_limit(cfg.ebpf_rate_limit);
            LOG_INFO("[eBPF] Rate limit: " << cfg.ebpf_rate_limit << " events/sec/PID");
            if (!cfg.redact_patterns.empty()) {
                ebpf::set_redact_patterns(cfg.redact_patterns);
                LOG_INFO("[eBPF] Redact patterns: " << cfg.redact_patterns.size() << " custom patterns");
            }
            // Apply enabled_probes config before init (v3.4)
            ebpf::set_enabled_probes(cfg.enabled_probes);
            std::string disabled_list;
            for (const auto& kv : cfg.enabled_probes) {
                if (!kv.second) {
                    if (!disabled_list.empty()) disabled_list += ",";
                    disabled_list += kv.first;
                }
            }
            if (!disabled_list.empty()) {
                LOG_INFO("[eBPF] Disabled probes: " << disabled_list);
            }
            if (ebpf::kernel_ok()) {
                if (ebpf::init()) {
                    use_ebpf = true;
                    ebpf_mode = "ringbuf";
                    ebpf_reason = "ok";
                    LOG_INFO("[eBPF] Kernel OK, loader init success. eBPF prioritized.");
                } else {
                    ebpf_reason = std::string("init_failed:") + ebpf::kernel_reason();
                    LOG_WARN("[eBPF] init() failed, reason: " << ebpf_reason);
                }
            } else {
                ebpf_reason = ebpf::kernel_reason();
                LOG_WARN("[eBPF] Kernel unsupported: " << ebpf_reason);
            }
        } else {
            ebpf_reason = "disabled_by_config";
        }

        // 5. NetworkCollector remembers eBPF status
        // T4.8.9: wire the shared buffer (buf_) so network events flow
        // through the same Sender/HMAC/SSL pipeline as FIM/eBPF/Fanotify.
        // The previous T3.1 inline curl POST in the pcap handler is GONE.
        // T4.8.24: wire the local threat detector. The detector runs in
        // the flush thread (single-threaded) and tags events with severity
        // + MITRE before they hit the shared buffer. The detector instance
        // lives in main() so we can reset it on config reload.
        logsoc::net::detect::NetworkDetector net_detector;
        logsoc::NetworkCollector net;
        net.set_ebpf_active(use_ebpf);
        net.set_shared_buffer(&buffer);
        net.set_detector(&net_detector);

        // 6. v3.7.0: AppCollector reads log files (no socket). Disabled when scan_paths empty.
        std::vector<std::unique_ptr<AppCollector>> app_collectors;
        // T13.9: mutex protects app_collectors from concurrent access between
        // heartbeat thread (rebuild via apply_config_update) and shutdown
        // (stop_all loop). Killed audit H-12 race.
        std::mutex app_collectors_mtx;
        if (cfg.app_collector_enabled) {
            if (cfg.scan_paths.empty()) {
                LOG_INFO("[*] AppCollector: disabled (scan_paths is empty)");
            } else {
                for (const auto& path : cfg.scan_paths) {
                    if (!fs::exists(path)) {
                        LOG_WARN("[!] AppCollector: skipping " << path << " (not found)");
                        continue;
                    }
                    auto c = std::make_unique<AppCollector>(path, buffer);
                    c->start();
                    app_collectors.push_back(std::move(c));
                }
                if (!app_collectors.empty()) {
                    LOG_INFO("[+] AppCollector active on " << app_collectors.size() << " file(s)");
                }
            }
        } else {
            LOG_INFO("[*] AppCollector: disabled (app_collector_enabled=false in config)");
        }

        // 7. Start sender
        Sender sender(cfg, buffer, fallback_wal, cred, data_dir);
        sender.start();

        // 7a. T64.2.2: Initial policy pull (synchronous, blocking).
        // Done BEFORE YaraShipper/FanotifyCollector start so cfg.policy
        // is populated with central's view (or local fallback if central
        // is down). Best-effort: failure here just keeps the local
        // config.json values.
        {
            const std::string policy_path = "/api/v1/agent-config/policy";
            try {
                auto r = pull_policy_once(cred, cfg, policy_path);
                if (r.ok) {
                    // T12.16: bind= no longer logged (HTTP server removed).
                    LOG_INFO("[Policy] initial pull OK from central: watch_paths="
                             << cfg.policy.fim_watch_paths.size()
                             << " threshold=" << cfg.policy.ship_heuristic_threshold);
                } else {
                    LOG_WARN("[Policy] initial pull failed: " << r.error
                             << " — using local config.json (source=" << cfg.policy.source << ")");
                }
            } catch (const std::exception& e) {
                LOG_WARN("[Policy] initial pull exception: " << e.what()
                         << " — using local config.json");
            }
        }

        // 7b. Start background policy puller (refresh every 5 min)
        PolicyPuller puller(cred, cfg, "/api/v1/agent-config/policy", 300);
        puller.start();

        // 7c. Optional network capture
        if (cfg.module_network) {
            if (!logsoc::NetworkCollector::check_root()) {
                LOG_WARN("[!] module_network=true but not root. Disabling.");
            } else {
                // T4.8.9: NO MORE inline curl POST in the pcap handler.
                // Network events are pushed to the shared buffer (set
                // above via set_shared_buffer) and shipped by the main
                // Sender thread with HMAC + SSL + WAL fallback. The
                // set_flush_callback path is REMOVED (was a sync HTTP
                // call from the pcap hot path → 1 thread blocked per
                // packet on slow network).
                if (net.init(cfg.net_cfg)) {
                    net.start();
                    LOG_INFO("[*] Network capture running on "
                             + cfg.net_cfg.interfaces[0]
                             + " (T4.8.9 ring+shared_buf pipeline)");
                } else {
                    LOG_ERROR("[!] Network capture init failed");
                }
            }
        }

        // 7c. Optional eBPF collector
        // T13.9: unique_ptr replaces raw ptr. The OLD code used `.release()`
        // to leak ownership into a raw pointer for thread captures, which
        // caused UAF (audit A-14) because the raw ptr was destroyed at
        // shutdown BEFORE heartbeat_thread.join(). unique_ptr makes the
        // ownership explicit: heartbeat captures `&ebpf_ptr` (the
        // atomic_unique_ptr itself, not the underlying EbpfCollector) and
        // is joined before ebpf_ptr.reset(). See "T13.9 Threading Model"
        // comment in main(). T13.10: now an atomic_unique_ptr (mutex-guarded)
        // so that even if a future dev touches the shutdown order, the
        // heartbeat read can't race with the main-thread reset.
        atomic_unique_ptr<EbpfCollector> ebpf_ptr;
        if (use_ebpf) {
            if (!logsoc::NetworkCollector::check_root()) {
                LOG_WARN("[!] module_ebpf=true but not root. Disabling.");
                use_ebpf = false;
                ebpf_mode = "none";
                ebpf_reason = "not_root";
                ebpf::stop();
            } else {
                auto ec_owned = std::make_unique<EbpfCollector>(cfg, buffer);
                ec_owned->start();
                // T13.9: std::move transfers ownership. The metrics_thread and
                // heartbeat_thread capture `&ebpf_ptr` (the unique_ptr itself)
                // and access the underlying collector via `->`. unique_ptr
                // provides the same `->`, `if (ebpf_ptr)`, and `ebpf_ptr ?`
                // syntax as a raw pointer, so all 16 downstream call sites
                // remain unchanged.
                ebpf_ptr = std::move(ec_owned);
                LOG_INFO("[*] eBPF collector started");
            }
        }

        // v4.8.0 (T4.8): FIM pipeline (FimCollector + FdResolver + shipper).
        // Owns: FdResolver (constructed inside FimCollector), FimCollector,
        // and the FimShipper thread that pops enriched events and pushes
        // them into the same buffer (buf_) as other collectors.
        // Started AFTER EbpfCollector so ebpf_ptr can be wired via
        // set_fim_collector().
        std::unique_ptr<logsoc::agent::fd::FdResolver> fim_resolver;
        std::unique_ptr<logsoc::agent::fim::FimCollector> fim_collector;
        // v4.8.0-t4.8.9: FimPoller declared at main scope (was previously
        // declared inside the v5_simplified if-block, which caused the
        // unique_ptr to destruct ~FimPoller immediately after construction,
        // joining the poller thread before it could detect any file changes.
        // Symptom in journald: [FimPoller] started → initial snapshot taken
        // → stopped within 1s, no [FimPoller] change detected events.
        // Fix: hoist the unique_ptr declaration to main scope so it lives
        // for the full agent lifetime and is only destructed at shutdown.
        std::unique_ptr<fim_scanner::FimScannerProcess> fim_poller;
        // T13.3': privilege-separated action recommender child (analyst)
        // + parent-side ActionValidator. The child sends recommendations
        // over IPC, the parent validates against 3 barriers before
        // calling t28::execute() with its root capabilities.
        std::unique_ptr<action_recommender::ActionRecommenderProcess> action_recommender_proc;
        std::unique_ptr<action_validator::ActionValidator> action_validator_inst;
        std::thread action_validator_thread;
        std::atomic<bool> action_validator_stop{false};
        std::thread fim_shipper_thread;
        std::atomic<bool> fim_shipper_stop{false};
        if (cfg.module_ebpf && cfg.fim_engine == "v5_simplified") {
            std::string cb_state_file = cfg.fim_cb_state_file;
            if (cb_state_file.empty()) {
                cb_state_file = "/var/lib/logsoc-agent/fim_cb_state.json";
            }
            logsoc::agent::fd::Config fdc;
            fdc.cb_state_file = cb_state_file;
            fdc.worker_count = cfg.fim_fd_worker_count;
            fdc.queue_capacity = 4096;
            fdc.per_resolve_timeout = std::chrono::milliseconds(10);
            fim_resolver = std::make_unique<logsoc::agent::fd::FdResolver>(fdc);
            logsoc::agent::fim::Config fimc;
            fimc.ship_queue_capacity = cfg.fim_ship_queue_capacity;
            fimc.rate_limit_per_pid_per_sec = cfg.fim_rate_limit_per_pid_per_sec;
            fimc.enable_watchdog = true;
            fimc.watchdog_period = std::chrono::seconds(30);
            fim_collector = std::make_unique<logsoc::agent::fim::FimCollector>(fimc, *fim_resolver);
            // Wire into EbpfCollector so fim + write_fd events are routed
            // through the V4.8 pipeline.
            if (ebpf_ptr) {
                ebpf_ptr->set_fim_collector(fim_collector.get());
            }
            // FimShipper: pops enriched events from the FimCollector and
            // pushes them as JSON strings into the shared buffer. The
            // Sender drains the buffer and ships via POST /api/v1/events/.
            // v4.8.0 (T4.8 hotfix): add heartbeat log every 100 events and
            // a debug log per event when verbose mode is on. Without this
            // the shipper is a black box — ClickHouse ingestion is the only
            // end-to-end observability, and that hides local failures.
            // See "T13.9 Threading Model" comment in main() for lifetime guarantees.
            fim_shipper_thread = std::thread([&]() {
                uint64_t shipped_total = 0;
                uint64_t dropped_total = 0;
                uint64_t watchdog_total = 0;
                auto last_log = std::chrono::steady_clock::now();
                while (!fim_shipper_stop.load()) {
                    // T13.2c: drain the scanner's inbound event queue
                    // FIRST. Events arrive via IPC from the FimScannerProcess
                    // child (logsoc:logsoc with CAP_DAC_READ_SEARCH). We
                    // inject them into FimCollector::publish_external so
                    // the existing merge + rate limit + ship-queue logic
                    // (unchanged) processes them identically to eBPF events.
                    if (fim_poller) {
                        logsoc::agent::fim::FimEvent scanner_ev;
                        int drained = 0;
                        // Drain up to 64 events per shipper tick to avoid
                        // starving the pop_ship_event loop below. The
                        // scanner child publishes at most a few per second
                        // (one per SHA change), so 64 is generous.
                        while (drained++ < 64 && fim_poller->pop_event(scanner_ev)) {
                            fim_collector->publish_external(scanner_ev);
                        }
                    }
                    logsoc::agent::fim::FimEvent fev;
                    if (!fim_collector->pop_ship_event(fev, std::chrono::milliseconds(100))) {
                        // Periodic liveness ping (every 30s) so operators can
                        // confirm the shipper thread is alive even with no events.
                        auto now = std::chrono::steady_clock::now();
                        if (now - last_log >= std::chrono::seconds(30)) {
                            LOG_DEBUG("[FimShipper] alive: shipped=" << shipped_total
                                     << " dropped=" << dropped_total
                                     << " watchdog=" << watchdog_total
                                     << " queue_depth=" << fim_collector->ship_queue_depth());
                            last_log = now;
                        }
                        continue;
                    }
                    // Skip watchdog pings (they're for liveness monitoring,
                    // not FIM events). Increment the metric for visibility.
                    if (std::string(fev.operation) == "watchdog") {
                        logsoc::agent::metrics::FimMetrics::counters()
                            .fim_watchdog_pings.fetch_add(1);
                        watchdog_total++;
                        continue;
                    }
                    // Format as a JSON line compatible with the Sender's
                    // send_batch() expectations: it parses the JSON and
                    // extracts severity, message, tags, etc.
                    json item;
                    item["event_id"]    = gen_uuid();
                    item["source_host"] = cfg.hostname;
                    // Severity: "warning" for MITRE-tagged events, "info" otherwise
                    if (!fev.mitre.empty()) {
                        item["severity"] = "warning";
                    } else {
                        item["severity"] = "info";
                    }
                    item["message"] = "FIM " + std::string(fev.operation)
                                     + " on " + (fev.abs_path.empty() ? fev.basename : fev.abs_path)
                                     + " (resolution=" + fev.resolution + ")";
                    item["event"]    = "fim_v4_8";
                    item["service"]  = "fim";
                    item["comm"]     = "";     // not available from BPF FIM
                    item["username"] = "";
                    item["pid"]      = (int)fev.pid;
                    item["filename"] = fev.abs_path.empty() ? fev.basename : fev.abs_path;
                    item["resolution"] = fev.resolution;
                    // MITRE enrichment retiré du FIM shipper — le backend calcule côté serveur. Voir issue #40.
                    // Push into the shared buffer. The Sender's drop_oldest_if_full
                    // handles backpressure.
                    bool wok = buffer.drop_oldest_if_full(item.dump());
                    if (wok) {
                        // The buffer evicted an older event to make room.
                        // Increment our FIM-specific drop counter for metrics.
                        logsoc::agent::metrics::FimMetrics::counters()
                            .fim_dropped.fetch_add(1);
                        dropped_total++;
                    }
                    // Increment shipped counter (whether or not it was actually
                    // sent — we count "handed to Sender" for now; a more
                    // accurate count would require a callback from the Sender
                    // on success).
                    logsoc::agent::metrics::FimMetrics::counters()
                        .fim_shipped.fetch_add(1);
                    shipped_total++;
                    // T13.3': forward the event to the action recommender
                    // child for pattern matching. We build a compact JSON
                    // payload (just the fields needed for severity::score)
                    // and push it via IPC. If the child is dead, the call
                    // returns false and we just log; the event still gets
                    // shipped to the backend normally. This is best-effort
                    // pattern matching — the source of truth is the
                    // backend's heartbeat-driven pending_actions path.
                    if (action_recommender_proc) {
                        try {
                            nlohmann::json ev_json;
                            ev_json["event_type"]  = 0;  // FIM event_type baseline
                            ev_json["comm"]        = "";
                            ev_json["path"]        = fev.abs_path.empty() ? fev.basename : fev.abs_path;
                            ev_json["uid"]         = 0;
                            ev_json["pid"]         = fev.pid;
                            ev_json["dst_port"]    = 0;
                            ev_json["mitre_count"] = 0;  // MITRE now calculated backend-side
                            ev_json["rule_id"]     = fev.resolution;
                            if (!action_recommender_proc->push_event(ev_json.dump())) {
                                // Child dead or IPC failure. Don't retry per-event.
                                // The child will auto-restart on the next
                                // push_event() call (handled by ensure_child_locked).
                            }
                        } catch (const std::exception& e) {
                            LOG_WARN("[T13.3'] push_event failed: " << e.what());
                        }
                    }
                    // Heartbeat every 100 events so operators can correlate
                    // FIM activity with the Sender's batch log.
                    if (shipped_total % 100 == 0) {
                        LOG_DEBUG("[FimShipper] shipped=" << shipped_total
                                 << " dropped=" << dropped_total
                                 << " last_pid=" << fev.pid
                                 << " last_path=" << (fev.abs_path.empty() ? fev.basename : fev.abs_path));
                    }
                }
                LOG_INFO("[-] FIM shipper stopped (shipped=" << shipped_total
                         << " dropped=" << dropped_total
                         << " watchdog=" << watchdog_total << ")");
            });
            LOG_INFO("[*] FIM v4.8 pipeline started (fd_workers=" << cfg.fim_fd_worker_count
                     << " queue=" << cfg.fim_ship_queue_capacity
                     << " rate_limit=" << cfg.fim_rate_limit_per_pid_per_sec << "/s/pid)");

            // v4.8.0 (T4.8.8): FimPoller fallback. Polls fim.watch_paths
            // every 5s and SHA-256-compares. Detects changes that the eBPF
            // kprobe misses (Hestia 6.8 kernel: SSH root processes do NOT
            // trigger kprobes due to cgroup optimization in user.slice).
            // Auto-disabled if fim.watch_paths is empty.
            // v4.8.0-t4.8.9: declaration hoisted to main scope (see above).
            // T13.2c: FimPoller is now FimScannerProcess — runs in a
            // privilege-separated child (logsoc:logsoc + CAP_DAC_READ_SEARCH)
            // and forwards detected changes via IPC. The parent shipper
            // thread drains the inbound queue and injects events into
            // FimCollector::publish_external (see fim_shipper_thread below).
            if (!cfg.fim.watch_paths.empty()) {
                fim_scanner::Config scfg;
                scfg.watch_paths = cfg.fim.watch_paths;
                scfg.poll_interval_sec = cfg.fim_poll_interval_sec;
                // wal_user/wal_group default to "logsoc" in Config.
                fim_poller = std::make_unique<fim_scanner::FimScannerProcess>(scfg);
                if (!fim_poller->start()) {
                    // Safety net: if the logsoc user doesn't exist or
                    // CAP_DAC_READ_SEARCH isn't available in the service
                    // file, the child can't start. We log and continue
                    // with eBPF-only FIM (the primary path on Hestia).
                    LOG_ERROR("[FimPoller] FimScannerProcess failed to start, "
                              "running in eBPF-only mode (no SHA-256 poller)");
                    fim_poller.reset();
                }
            }
        }

        // T13.3': instantiate the action recommender child + validator.
        // The child is the analyst (logsoc:logsoc, no caps). It receives
        // ship-ready events via push_event(), applies severity scoring,
        // and sends ActionRecommendation messages back. The parent-side
        // ActionValidator applies 3 safety barriers before t28::execute().
        //
        // Auto-disabled if logsoc user doesn't exist or if the
        // rules_allowlist / pid_exclusions / action_allowlist config
        // files are missing AND we don't want to run fail-open. For
        // safety, we run fail-CLOSED: if the validator can't load its
        // 3 allowlists, no actions can execute. The backend-driven
        // path (pending_actions in heartbeat) still works normally
        // — T13.3' is a SECOND path, not a replacement.
        {
            action_validator_inst = std::make_unique<action_validator::ActionValidator>();
            action_validator_inst->load_rules_allowlist("/etc/logsoc-agent/rules_allowlist.json");
            action_validator_inst->load_pid_exclusions("/etc/logsoc-agent/pid_exclusions.json");
            action_validator_inst->load_action_allowlist("/etc/logsoc-agent/action_allowlist.json");

            action_recommender::Config arcfg;
            arcfg.severity_threshold = 90;  // recommend only if score >= 90 (critical)
            arcfg.wal_user = "logsoc";
            arcfg.wal_group = "logsoc";
            action_recommender_proc = std::make_unique<action_recommender::ActionRecommenderProcess>(arcfg);
            if (action_recommender_proc->start()) {
                // Spawn the validator thread that drains recommendations
                // from the child, applies the 3 barriers, and calls
                // t28::execute() if everything passes.
                action_validator_thread = std::thread([&]() {
                    while (!action_validator_stop.load()) {
                        action_recommender::ActionRecommendation rec;
                        if (action_recommender_proc->pop_recommendation(rec)) {
                            auto decision = action_validator_inst->validate(rec);
                            if (decision.barrier == action_validator::BarrierResult::PASS) {
                                LOG_INFO("[T13.3'] VALIDATED recommendation: action="
                                         << rec.action_type << " pid=" << rec.target_pid
                                         << " rule=" << rec.rule_id << " severity=" << rec.severity
                                         << " — calling t28::execute()");
                                // Map the recommendation to a t28::execute() call.
                                // For T13.3' MVP, only kill_pid is wired.
                                if (rec.action_type == "kill_pid" && rec.target_pid > 0) {
                                    std::string payload = "{\"pid\":" +
                                        std::to_string(rec.target_pid) + ",\"signal\":9}";
                                    auto result = logsoc::agent::t28::execute(
                                        "kill_pid", "t13.3-auto", payload, /*dry_run=*/false);
                                    LOG_INFO("[T13.3'] t28::execute result: status="
                                             << result.status << " msg=" << result.result_message);
                                }
                            } else {
                                LOG_WARN("[T13.3'] BLOCKED recommendation: action="
                                         << rec.action_type << " pid=" << rec.target_pid
                                         << " rule=" << rec.rule_id
                                         << " — barrier=" << action_validator::barrier_result_str(decision.barrier)
                                         << " reason=" << decision.reason);
                            }
                        }
                        // Avoid busy-looping if the queue is empty.
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                });
                LOG_INFO("[T13.3'] action_recommender_proc + validator thread started");
            } else {
                LOG_WARN("[T13.3'] ActionRecommenderProcess failed to start, "
                         "running in backend-driven-only mode (no analyst child)");
                action_recommender_proc.reset();
            }
        }

        // v4.8.0-t4.8.10: FIM metrics HTTP server. Exposes FimMetrics
        // (16 counters + 4 gauges + agent_info) via /metrics in Prometheus
        // text format, plus /healthz and /liveness for k8s-style probes.
        // T12.11 (2026-06-16): FimMetricsServer has been removed.
        // The agent no longer opens a TCP port for /metrics — that
        // path is replaced by T12.10's outbound metrics channel
        // (counters ship in the heartbeat body, backend exposes
        // them at /api/v1/agents/{id}/metrics?format=prometheus).
        // The agent version is still set on FimMetrics so any
        // future debug helper that reads counters can label them.
        logsoc::agent::metrics::FimMetrics::set_agent_version(AGENT_VERSION);
        // T12.16: cfg.fim_metrics_port no longer exists (HTTP server removed).
        // (Old code had: (void)cfg.fim_metrics_port;  // legacy field, kept
        //  for config compat but ignored. Removed entirely.)
        (void)cfg;

        // 7c-bis. v3.10.0: YARA HQ engine (file scan hook + central rule pull)
        std::unique_ptr<logsoc::YaraEngine> yara_engine;
        // v3.15 (T59): YaraShipper for content fetch (agent → central).
        // Lives in the same scope as yara_engine (started after engine
        // init, stopped before engine reset). Pointer is non-owning when
        // exposed via set_yara_shipper() (FanotifyCollector doesn't own).
        std::unique_ptr<logsoc::agent::yara::YaraShipper> yara_shipper;
        std::thread yara_pull_thread;
        if (cfg.yara_enabled) {
            logsoc::YaraConfig ycfg;
            ycfg.enabled = true;
            ycfg.scan_flags = cfg.yara_scan_flags;
            ycfg.central_url = cred.central_url;
            ycfg.agent_id = cred.agent_id;
            ycfg.hmac_token = cred.hmac_secret;  // reuse same secret as events (HMAC-SHA256)
            ycfg.max_scan_file_mb = cfg.yara_max_scan_file_mb;
            ycfg.max_rule_size_kb = cfg.yara_max_rule_size_kb;
            ycfg.match_post_interval_sec = cfg.yara_match_post_interval_sec;
            ycfg.scan_timeout_ms = cfg.yara_scan_timeout_ms;
            // v3.17.0 (T61.1): bound the compile wall time. 0 = unbounded.
            ycfg.max_compile_ms = cfg.yara_max_compile_ms;

            yara_engine = std::make_unique<logsoc::YaraEngine>(ycfg);
            if (yara_engine->init()) {
                // Initial rule pull (best-effort, non-blocking on failure)
                size_t n = yara_engine->pull_rules_from_central();
                LOG_INFO("[*] YARA HQ enabled: loaded " << n << " rules (scan_flags="
                         << ycfg.scan_flags << " = 0b" << std::bitset<4>(ycfg.scan_flags).to_string() << ")");
                // Wire into eBPF collector for FIM/open file scan
                if (ebpf_ptr) ebpf_ptr->set_yara_engine(yara_engine.get());

                // v3.15 (T59): YARA content fetch (agent → central). Only
                // instantiated when yara_ship_content=true in config (off by
                // default). The shipper is started immediately; the
                // FanotifyCollector will pick it up via set_yara_shipper()
                // when fanotify_enabled is also true. The start() call is
                // idempotent so duplicate calls from tests/CLI are safe.
                if (cfg.yara_ship_content) {
                    logsoc::agent::yara::ShipperConfig scfg;
                    scfg.endpoint = cred.central_url + "/api/v1/yara/scan";
                    scfg.auth_token = cred.hmac_secret;  // HMAC-SHA256 shared secret (same as event HMAC)
                    scfg.agent_id = cred.agent_id;
                    scfg.max_file_size = static_cast<size_t>(cfg.yara_ship_max_file_size);
                    // T64.2.3 (v3.20.0): prefer policy value (from central pull) over local config
                    //
                    // T12 audit fix #24: read both policy fields under a single
                    // lock acquisition. Both are small scalars/strings so
                    // contention is negligible. Doing them in one lock keeps
                    // them consistent (they should come from the same central
                    // pull snapshot).
                    {
                        std::lock_guard<std::mutex> pl(cfg.policy.policy_mtx);
                        scfg.heuristic_threshold = cfg.policy.ship_heuristic_threshold;
                        // T12.16: metrics_bind_address wiring removed (HTTP server gone).
                    }
                    // T12.16: metrics_port defaulting removed (HTTP server gone).
                    yara_shipper = std::make_unique<logsoc::agent::yara::YaraShipper>(scfg);
                    yara_shipper->start();
                    // T12.16: metrics_port / metrics_bind no longer logged (HTTP server gone).
                    LOG_INFO("[*] YaraShipper enabled (content fetch, threshold="
                             << scfg.heuristic_threshold
                             << ", max_file_size=" << scfg.max_file_size << " bytes"
                             << ", policy_source=" << cfg.policy.source << ")");
                } else {
                    LOG_INFO("[*] YaraShipper: disabled (yara.ship_content=false in config)");
                }

                // Periodic rule pull thread
                int pull_int = cfg.yara_rule_pull_interval_sec;
                yara_pull_thread = std::thread([&yara_engine, pull_int]() {
                    while (g_running) {
                        std::this_thread::sleep_for(std::chrono::seconds(pull_int));
                        if (!g_running) break;
                        size_t n = yara_engine->pull_rules_from_central();
                        if (n > 0) {
                            LOG_INFO("[yara] periodic pull: " << n << " rules");
                        }
                    }
                });
            } else {
                LOG_ERROR("[!] YARA HQ: yr_initialize failed, disabling");
                yara_engine.reset();
            }
        }

        // 7b.yara T77 (v3.21.0): start the YARA ruleset puller as a
        // companion to PolicyPuller. Pulls the central-pushed .yarac
        // blob and atomic-swaps the YR_RULES*. Same 5min cadence.
        std::unique_ptr<YaraRulesetPuller> yara_ruleset_puller;
        if (yara_engine) {
            yara_ruleset_puller = std::make_unique<YaraRulesetPuller>(
                cred,
                yara_engine.get(),
                "/api/v1/yara/ruleset",
                "/api/v1/yara/ruleset/download",
                300
            );
            yara_ruleset_puller->start();
            LOG_INFO("[*] YaraRulesetPuller started (interval=300s, "
                     "path=/api/v1/yara/ruleset)");
        }

        // 7d. Optional journald collector (reads systemd journal via sd_journal API)
        std::unique_ptr<JournaldCollector> journald_coll;
        if (cfg.module_journald) {
#ifdef __linux__
            journald_coll = std::make_unique<JournaldCollector>(cfg, buffer);
            journald_coll->start();
            LOG_INFO("[*] JournaldCollector started (sd_journal API)");
#else
            LOG_WARN("[!] module_journald=true but not available on this platform");
#endif
        }

        // 7e. v3.10.1: FanotifyCollector — userspace FIM with absolute paths.
        // Opt-in via "fanotify_enabled": true in config. Uses cfg.fim.watch_paths
        // as the mark target list. Replaces/complements the eBPF kprobe/vfs_write
        // FIM event (which only had the basename).
        //
        // v3.10.5 (issue #2 SOC-AGENT): FanotifyCollector is fundamentally
        // incompatible with AppArmor enforce mode. The "disconnected path"
        // returned by fanotify on anon fds cannot be matched by any AppArmor
        // rule. Result: ::read(fanotify_fd) returns EACCES intermittently,
        // dropping FIM events. See docs/decisions/ADR-001-fim-apparmor.md
        // for the full analysis. We:
        //   1. Detect AppArmor enforce at runtime
        //   2. Log a clear warning if fanotify_enabled=true under enforce
        //   3. Recommend eBPF FIM (already running via module_ebpf)
        std::unique_ptr<FanotifyCollector> fanotify_coll;
        if (cfg.fanotify_enabled) {
#ifdef __linux__
            if (cfg.fim.watch_paths.empty()) {
                LOG_WARN("[!] fanotify_enabled=true but fim.watch_paths is empty, "
                         "FanotifyCollector disabled (nothing to watch)");
            } else {
                // Detect AppArmor enforce for this process
                std::ifstream aa_status("/proc/self/attr/apparmor/current");
                std::string aa_mode;
                if (aa_status.is_open()) {
                    std::getline(aa_status, aa_mode);
                    aa_status.close();
                }
                bool aa_enforce = (aa_mode.find("enforce") != std::string::npos);

                if (aa_enforce) {
                    LOG_WARN("[!] fanotify_enabled=true BUT process is under AppArmor "
                             "ENFORCE mode. FanotifyCollector will fail with EACCES on "
                             "::read(fanotify_fd) due to the 'disconnected path' limitation "
                             "(anon fd from fanotify has no resolvable path). "
                             "FIM events will be DROPPED. "
                             "RECOMMENDED: keep fanotify_enabled=false and rely on eBPF FIM "
                             "(module_ebpf=true, enabled_probes.fim=true). "
                             "See issue #2 in pixies/SOC-AGENT for details.");
                }

                fanotify_coll = std::make_unique<FanotifyCollector>(cfg, buffer);
                fanotify_coll->set_yara_engine(yara_engine.get());
                // v3.15 (T59): wire the content shipper (may be null if
                // yara_ship_content=false). The FanotifyCollector handles
                // nullptr gracefully (no-op in the FIM loop).
                fanotify_coll->set_yara_shipper(yara_shipper.get());
                // T12.12: wire the global pointer so the T28 action
                // dispatcher (action_executor.cpp) can call
                // add_watch/remove_watch at runtime.
                g_fanotify_collector = fanotify_coll.get();
                fanotify_coll->start();
                LOG_INFO("[*] FanotifyCollector started (watching "
                         << cfg.fim.watch_paths.size() << " path(s)"
                         << (aa_enforce ? ", AppArmor=ENFORCE (see warning above)" : "")
                         << ")");
            }
#else
            LOG_WARN("[!] fanotify_enabled=true but not available on this platform");
#endif
        } else {
            LOG_INFO("[*] FanotifyCollector: disabled (fanotify_enabled=false in config, "
                     "FIM uses eBPF kprobe/vfs_write + open_path_cache basename-to-path resolution)");
        }

        // 8. Heartbeat thread (v3.5: configurable interval, drop_stats)
        // v3.11 (SOC-AGENT#4): the interval is read from g_hb_interval_sec
        // (atomic, hot-reloadable) at the top of each iteration. The previous
        // implementation captured `cfg.heartbeat_interval_sec` by value, so
        // a runtime change had no effect until restart.
        // v3.12: also captures refs to app_collectors / fanotify_coll so
        // the hot-reload can rebuild them when scan_paths / watch_paths
        // change via the heartbeat response.
        // v3.21.0 (T66 / logsoc-web#15): detect disk encryption once at boot
        // and cache the result. /proc/mounts doesn't change at runtime, so
        // recomputing on every heartbeat would be wasted work.
        logsoc::EncryptionStatus enc = logsoc::detect_encryption_at_rest();
        std::optional<bool> hb_encryption_at_rest = enc.encrypted;
        std::string hb_encryption_method = enc.method;
        LOG_INFO("[T66] Disk encryption at rest detection: encrypted=" << (enc.encrypted ? "true" : "false")
                 << " method=" << enc.method
                 << (enc.detail.empty() ? "" : " (" + enc.detail + ")"));
        // We always send the field (not std::nullopt) so the backend can
        // distinguish "not yet reported" from "agent doesn't have detection".
        // The backend also accepts a separate "method" field for the DPO UI.

        g_hb_interval_sec.store(cfg.heartbeat_interval_sec, std::memory_order_relaxed);

        // v4.9.0: cache the SHA-256 of config.json for config hot-reload.
        // The backend compares this hash with its stored config_json hash
        // and pushes the full config back if they differ. We recompute
        // after writing a new config (config_update handler).
        std::string cached_config_hash = crypto::sha256_file(config_path);
        LOG_INFO("[config-hot-reload] initial config_hash=" << cached_config_hash.substr(0, 16) << "...");

        // T31: metrics event shipper. Every 60s, snapshot FimMetrics
        // counters + RSS/CPU/uptime, build an event agent_metrics, and
        // push it into the shared buffer. The Sender will ship it on
        // the next batch. The backend ingests it as a normal event with
        // service=agent, event=agent_metrics — queryable like any other.
        //
        // No port opened. Same channel as FIM events. KISS observability.
        // See "T13.9 Threading Model" comment in main() for lifetime guarantees.
        std::thread metrics_thread([&buffer, &ebpf_ptr, &cfg]() {
            LOG_INFO("[+] metrics shipper started (interval=60s)");
            // VMS rusage snapshot for CPU%
            uint64_t last_user_ns = 0, last_sys_ns = 0;
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                if (!g_running) break;
                try {
                    auto& c = logsoc::agent::metrics::FimMetrics::counters();
                    // RSS from /proc/self/status
                    int64_t rss_kb = 0;
                    {
                        std::ifstream f("/proc/self/status");
                        std::string line;
                        while (std::getline(f, line)) {
                            if (line.compare(0, 6, "VmRSS:") == 0) {
                                std::istringstream iss(line.substr(6));
                                iss >> rss_kb;
                                break;
                            }
                        }
                    }
                    // CPU% from getrusage diff
                    struct rusage ru;
                    getrusage(RUSAGE_SELF, &ru);
                    uint64_t user_ns = (uint64_t)ru.ru_utime.tv_sec * 1000000000ULL + (uint64_t)ru.ru_utime.tv_usec * 1000ULL;
                    uint64_t sys_ns  = (uint64_t)ru.ru_stime.tv_sec * 1000000000ULL + (uint64_t)ru.ru_stime.tv_usec * 1000ULL;
                    double cpu_pct = 0.0;
                    if (last_user_ns + last_sys_ns > 0) {
                        uint64_t du = user_ns - last_user_ns;
                        uint64_t ds = sys_ns  - last_sys_ns;
                        double secs = (du + ds) / 1e9;
                        // 60s interval window
                        cpu_pct = (secs / 60.0) * 100.0;
                        if (cpu_pct > 100.0) cpu_pct = 100.0;
                    }
                    last_user_ns = user_ns;
                    last_sys_ns  = sys_ns;
                    int64_t uptime_s = (int64_t)std::time(nullptr) - c.agent_start_time_unix.load();

                    json m;
                    m["event"] = "agent_metrics";
                    m["service"] = "agent";
                    m["severity"] = "info";
                    m["agent_version"] = AGENT_VERSION;
                    // Counters
                    m["counters"] = {
                        {"fd_resolved",       (uint64_t)c.fd_resolved},
                        {"fd_timeout",        (uint64_t)c.fd_timeout},
                        {"fd_eperm",          (uint64_t)c.fd_eperm},
                        {"fd_errors",         (uint64_t)c.fd_errors},
                        {"fd_dropped",        (uint64_t)c.fd_dropped},
                        {"fim_merged",        (uint64_t)c.fim_merged},
                        {"fim_dropped",       (uint64_t)c.fim_dropped},
                        {"fim_rate_limited",  (uint64_t)c.fim_rate_limited},
                        {"fim_shipped",       (uint64_t)c.fim_shipped},
                        {"net_packets",       (uint64_t)c.net_packets_captured},
                        {"net_packets_drop",  (uint64_t)c.net_packets_dropped},
                        {"net_events_pushed", (uint64_t)c.net_events_pushed},
                        {"cb_trips",          (uint64_t)c.cb_trips},
                        {"ship_errors",       (uint64_t)c.ship_errors},
                        {"parse_errors",      (uint64_t)c.parse_errors},
                    };
                    // Gauges
                    m["gauges"] = {
                        {"rss_kb",            rss_kb},
                        {"cpu_pct",           cpu_pct},
                        {"uptime_s",          uptime_s},
                        {"bpf_programs_attached", (uint64_t)(ebpf_ptr ? 17 : 0)},
                        {"bpf_links_active",  (uint64_t)(ebpf_ptr ? ebpf_ptr->priority_dropped() : 0)},
                    };
                    // Use drop_oldest_if_full: metrics are not critical,
                    // and a 60s gap is acceptable.
                    buffer.drop_oldest_if_full(m.dump());
                } catch (const std::exception& e) {
                    LOG_WARN("[T31] metrics ship failed: " + std::string(e.what()));
                }
            }
            LOG_INFO("[-] metrics shipper stopped");
        });

        std::thread heartbeat_thread([&data_dir, &config_path, &cached_config_hash, &cred, &buffer, &fallback_wal, &ebpf_mode, &ebpf_reason, &ebpf_ptr, &cfg, &app_collectors, &app_collectors_mtx, &fanotify_coll, &yara_engine, &yara_shipper, &hb_encryption_at_rest, &hb_encryption_method]() {
            while (g_running) {
                // Read the (possibly hot-reloaded) interval on each iteration.
                int hb_interval = g_hb_interval_sec.load(std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::seconds(hb_interval));
                long http_code = 0;
                int fwal_cnt = static_cast<int>(fallback_wal.count());
                uint64_t buf_dropped = buffer.dropped_total();
                uint64_t ringbuf_dropped = ebpf::get_drop_stats();
                // T30.2: ringbuf loss / total events for the backend dashboard
                uint64_t rb_lost  = ebpf::get_ringbuf_lost_events();
                uint64_t rb_total = ebpf::get_ringbuf_total_events();
                // T30.3: snapshot the enabled_probes map for the heartbeat
                // We read it from the local config (cfg.enabled_probes) which
                // is the canonical "desired" state. The rebuild_ebpf_probes()
                // call (T30.3, in apply_config_update) reattaches the kernel
                // links to match this map.
                std::vector<std::string> enabled_list;
                for (const auto& kv : cfg.enabled_probes) {
                    if (kv.second) enabled_list.push_back(kv.first);
                }
                // Build a legacy Credentials view for the heartbeat helper
                agent_v3::Credentials hb_cred;
                hb_cred.agent_id = cred.agent_id;
                hb_cred.central_url = cred.central_url;
                hb_cred.hmac_secret = cred.hmac_secret;
                hb_cred.token = cred.token;
                // v3.9.7: pass priority_dropped from eBPF collector (distinct from buf_dropped)
                // v3.10.0: pass agent version so dashboard reflects .deb upgrades
                // v3.21.0 (T66): pass disk encryption status (logsoc-web#15)
                // T30.2: pass ringbuf_lost/total for loss-rate dashboards
                // T30.3: pass enabled_probes list for hot-reload drift detection
                // T12.10: pass metrics snapshot (FIM + YARA + net) so the
                //   backend can render /api/v1/agents/{id}/metrics in
                //   Prometheus format without the agent listening on a port.
                agent_v3::MetricsSnapshot hb_metrics;
                // YaraShipper stats: file-content ship counters (shipped,
                // dropped, failed, etc.). The shipper is owned by main()
                // and captured by reference in the heartbeat closure.
                if (yara_shipper) {
                    auto ys = yara_shipper->stats_snapshot();
                    hb_metrics.yara_shipped           = ys.shipped;
                    hb_metrics.yara_dropped           = ys.dropped;
                    hb_metrics.yara_failed            = ys.failed;
                    hb_metrics.yara_skipped_size      = ys.skipped_size;
                    hb_metrics.yara_skipped_unreadable= ys.skipped_unreadable;
                    hb_metrics.yara_skipped_too_large = ys.skipped_too_large;  // T12.16
                    hb_metrics.yara_matched           = ys.matched;
                }
                // YaraEngine counters (rule count, scans, matches) — owned
                // by main() and captured by reference in the heartbeat
                // closure.
                if (yara_engine) {
                    hb_metrics.yara_rules_loaded = static_cast<uint64_t>(yara_engine->rule_count());
                    hb_metrics.yara_scans_total  = yara_engine->total_scans();
                    hb_metrics.yara_matches_total= yara_engine->total_matches();
                }
                // FimMetrics is a global singleton, no pointer needed
                auto fs = logsoc::agent::metrics::FimMetrics::snapshot();
                hb_metrics.fd_resolved         = fs.fd_resolved;
                hb_metrics.fd_timeout          = fs.fd_timeout;
                hb_metrics.fd_eperm            = fs.fd_eperm;
                hb_metrics.fd_not_found        = fs.fd_not_found;
                hb_metrics.fd_cb_open          = fs.fd_cb_open;
                hb_metrics.fd_errors           = fs.fd_errors;
                hb_metrics.fd_dropped          = fs.fd_dropped;
                hb_metrics.fim_merged          = fs.fim_merged;
                hb_metrics.fim_dropped         = fs.fim_dropped;
                hb_metrics.fim_rate_limited    = fs.fim_rate_limited;
                hb_metrics.fim_watchdog_pings  = fs.fim_watchdog_pings;
                hb_metrics.fim_shipped         = fs.fim_shipped;
                hb_metrics.net_packets_captured= fs.net_packets_captured;
                hb_metrics.net_packets_dropped = fs.net_packets_dropped;
                hb_metrics.net_events_pushed   = fs.net_events_pushed;
                hb_metrics.net_flush_errors    = fs.net_flush_errors;
                hb_metrics.cb_trips            = fs.cb_trips;
                std::string resp = agent_v3::perform_heartbeat(hb_cred, AGENT_VERSION,
                                                                 fwal_cnt,
                                                                 buf_dropped, ringbuf_dropped,
                                                                 0, 0,  // cpu_percent, mem_mb (placeholder)
                                                                 "ok",
                                                                 ebpf_mode, ebpf_reason,
                                                                 ebpf_ptr ? ebpf_ptr->priority_dropped() : (uint64_t)0,
                                                                 http_code,
                                                                 hb_encryption_at_rest,
                                                                 hb_encryption_method,
                                                                 rb_lost, rb_total,
                                                                 enabled_list,
                                                                 hb_metrics,
                                                                 // Host info fields
                                                                 cfg.os_name,
                                                                 cfg.os_version,
                                                                 cfg.arch,
                                                                 [](const std::vector<std::string>& v) -> std::string { std::string r; for (size_t i = 0; i < v.size(); ++i) { if (i > 0) r += ","; r += v[i]; } return r; }(cfg.ip_addresses),
                                                                 cfg.mac,
                                                                 cfg.cpu_model,
                                                                 cfg.memory_mb,
                                                                 cfg.disk_gb,
                                                                 // v4.9.0: config hash for hot-reload detection
                                                                 cached_config_hash);
                if (http_code == 403) {
                    // Revocation process: parse the 403 body for structured JSON.
                    // Backend returns: {"status":"revoked","action":"delete_identity",...}
                    // or {"status":"deleted","action":"delete_identity",...}
                    // If we get such a response, delete agent.identity and stop.
                    bool should_delete_identity = false;
                    std::string revoke_status;
                    if (!resp.empty()) {
                        try {
                            json j403 = json::parse(resp);
                            revoke_status = j403.value("status", std::string());
                            std::string action = j403.value("action", std::string());
                            if ((revoke_status == "revoked" || revoke_status == "deleted") && action == "delete_identity") {
                                should_delete_identity = true;
                            }
                        } catch (...) {
                            // Not JSON — treat as generic 403
                        }
                    }
                    if (should_delete_identity) {
                        LOG_ERROR("[HB] Agent " << revoke_status << " by admin. Deleting agent.identity and stopping.");
                        runtime_cred::delete_agent_identity(data_dir);
                        // Signal all threads to stop cleanly
                        g_running = false;
                        return;
                    }
                    LOG_WARN("[HB] HTTP 403 — will retry in 60s (no structured revoke signal)");
                    std::this_thread::sleep_for(std::chrono::seconds(60));
                    continue;
                }
                if (http_code == 404) {
                    LOG_ERROR("[HB] Agent not found on server (HTTP 404). Heartbeat stopping.");
                    return;
                }
                if (!resp.empty()) {
                    // Skip HTML responses (nginx errors, proxy pages, etc.)
                    std::string trimmed = resp;
                    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\n' || trimmed.front() == '\r' || trimmed.front() == '\t'))
                        trimmed.erase(trimmed.begin());
                    if (trimmed.empty() || trimmed[0] == '<') {
                        // HTML response — not JSON. Backoff and try again later.
                        static int hb_html_count = 0;
                        hb_html_count++;
                        if (hb_html_count <= 3 || hb_html_count % 10 == 0) {
                            LOG_WARN("[HB] Non-JSON (HTML) response from server, will retry (" + std::to_string(hb_html_count) + ")");
                        }
                    } else {
                        try {
                            json j = json::parse(resp);
                            if (j.contains("config")) {
                                // v3.12: apply config + rebuild collectors
                                // (SOC-AGENT#4). apply_config_update is bounded
                                // — only log_level, heartbeat_interval_sec,
                                // scan_paths, watch_paths are accepted. The
                                // rebuild helpers run in the heartbeat thread,
                                // so app_collectors / fanotify_coll updates
                                // happen on this same thread (no extra lock
                                // needed since the main thread doesn't touch
                                // them after start).
                                ConfigUpdateResult rur = apply_config_update(j["config"], cfg);
                                if (!rur.error.empty()) {
                                    LOG_WARN("[HB] config hot-reload rejected: " + rur.error);
                                } else if (!rur.log_level_applied
                                           && !rur.hb_interval_applied
                                           && rur.applied_scan_paths.empty()
                                           && rur.applied_watch_paths.empty()
                                           && rur.applied_journald_exclude_ids.empty()) {
                                    LOG_INFO("[HB] config object present but no hot-reloadable fields "
                                             "(log_level, heartbeat_interval_sec, scan_paths, watch_paths, journald_exclude_ids)");
                                } else {
                                    // v3.12: rebuild collectors if paths changed.
                                    // Each rebuild logs its own progress.
                                    if (!rur.applied_scan_paths.empty()) {
                                        try {
                                            cfg.scan_paths = rur.applied_scan_paths;
                                            // T13.9: pass app_collectors_mtx (mutex added to
                                            // serialize with shutdown).
                                            rebuild_app_collectors(app_collectors, buffer,
                                                                    rur.applied_scan_paths,
                                                                    cfg.app_collector_enabled,
                                                                    app_collectors_mtx);
                                        } catch (const std::exception& e) {
                                            LOG_ERROR("[HB-HR] rebuild_app_collectors failed: " + std::string(e.what()));
                                        }
                                    }
                                    if (!rur.applied_watch_paths.empty()) {
                                        try {
                                            rebuild_fanotify_collector(fanotify_coll, cfg, buffer,
                                                                        yara_engine.get(),
                                                                        rur.applied_watch_paths);
                                        } catch (const std::exception& e) {
                                            LOG_ERROR("[HB-HR] rebuild_fanotify_collector failed: " + std::string(e.what()));
                                        }
                                    }
                                }
                            }

                            // v4.9.0: full config hot-reload. The backend sends
                            // config_update when the agent's config_hash differs
                            // from the stored config_json on the backend. We write
                            // the new config to /etc/logsoc-agent/config.json (with
                            // backup) and restart if restart_required=true.
                            if (j.contains("config_update") && j["config_update"].is_object()) {
                                try {
                                    const auto& cu = j["config_update"];
                                    std::string new_hash = cu.value("config_hash", std::string());
                                    bool restart_required = cu.value("restart_required", true);
                                    if (cu.contains("config") && cu["config"].is_object()) {
                                        // Backup current config
                                        std::string config_dir_path = fs::path(config_path).parent_path().string();
                                        if (config_dir_path.empty()) config_dir_path = ".";
                                        std::string backup_path = config_path + ".bak";
                                        try {
                                            fs::copy_file(config_path, backup_path, fs::copy_options::overwrite_existing);
                                            LOG_INFO("[config-hot-reload] backed up " << config_path << " -> " << backup_path);
                                        } catch (const std::exception& e) {
                                            LOG_WARN("[config-hot-reload] backup failed: " << std::string(e.what()) << " — continuing anyway");
                                        }
                                        // Write new config
                                        std::string new_config_str = cu["config"].dump(4);
                                        {
                                            std::ofstream out(config_path, std::ios::trunc);
                                            if (!out) {
                                                LOG_ERROR("[config-hot-reload] failed to open " << config_path << " for writing");
                                            } else {
                                                out << new_config_str << std::endl;
                                                out.close();
                                                LOG_INFO("[config-hot-reload] wrote new config to " << config_path
                                                         << " (" << new_config_str.size() << " bytes)");
                                            }
                                        }
                                        // Update cached hash
                                        cached_config_hash = crypto::sha256_file(config_path);
                                        LOG_INFO("[config-hot-reload] new config_hash=" << cached_config_hash.substr(0, 16) << "...");

                                        if (restart_required) {
                                            LOG_INFO("[config-hot-reload] restart_required=true, exiting for systemd restart...");
                                            g_running = false;
                                            // Use quick_exit to avoid wal_writer blocking on destructor
                                            // systemd will restart the agent automatically
                                            std::quick_exit(0);
                                        } else {
                                            // Hot-reload: apply hot-reloadable fields from the new config
                                            ConfigUpdateResult rur = apply_config_update(cu["config"], cfg);
                                            if (!rur.error.empty()) {
                                                LOG_WARN("[config-hot-reload] hot-reload partial failure: " + rur.error);
                                            }
                                            if (!rur.applied_scan_paths.empty()) {
                                                try {
                                                    cfg.scan_paths = rur.applied_scan_paths;
                                                    rebuild_app_collectors(app_collectors, buffer,
                                                                            rur.applied_scan_paths,
                                                                            cfg.app_collector_enabled,
                                                                            app_collectors_mtx);
                                                } catch (const std::exception& e) {
                                                    LOG_ERROR("[config-hot-reload] rebuild_app_collectors failed: " + std::string(e.what()));
                                                }
                                            }
                                            if (!rur.applied_watch_paths.empty()) {
                                                try {
                                                    rebuild_fanotify_collector(fanotify_coll, cfg, buffer,
                                                                                yara_engine.get(),
                                                                                rur.applied_watch_paths);
                                                } catch (const std::exception& e) {
                                                    LOG_ERROR("[config-hot-reload] rebuild_fanotify_collector failed: " + std::string(e.what()));
                                                }
                                            }
                                            LOG_INFO("[config-hot-reload] hot-reload applied (no restart needed)");
                                        }
                                    }
                                } catch (const std::exception& e) {
                                    LOG_ERROR("[config-hot-reload] exception processing config_update: " + std::string(e.what()));
                                }
                            }

                            // T28: process pending_actions[] delivered by
                            // the backend. The agent is a pure sensor — it
                            // never decides to act on its own. Every action
                            // (kill, block_ip, quarantine, rmmod, fim_add)
                            // was approved (or dry-run) by a human via UI
                            // and stored in agent_actions table.
                            //
                            // The executor (action_executor.cpp) runs each
                            // action, captures the result, and ships it
                            // back as an event so the backend can update
                            // the row to succeeded/failed.
                            if (j.contains("pending_actions") &&
                                j["pending_actions"].is_array() &&
                                !j["pending_actions"].empty()) {
                                for (const auto& a : j["pending_actions"]) {
                                    try {
                                        std::string action_id = a.value("id", "");
                                        std::string action_type = a.value("action_type", "");
                                        bool dry_run = a.value("dry_run", true);
                                        std::string reason = a.value("reason", "");
                                        std::string target_summary = a.value("target_summary", "");
                                        std::string payload_str = a.contains("payload")
                                            ? a["payload"].dump()
                                            : "{}";
                                        if (action_id.empty() || action_type.empty()) {
                                            LOG_WARN("[T28] skipping action with empty id/type");
                                            continue;
                                        }
                                        LOG_INFO("[T28] executing action " << action_id.substr(0,8)
                                                 << " type=" << action_type
                                                 << " dry_run=" << (dry_run ? "true" : "false")
                                                 << " target=" << target_summary);
                                        auto result = logsoc::agent::t28::execute(
                                            action_type, action_id, payload_str, dry_run);
                                        LOG_INFO("[T28] action " << action_id.substr(0,8)
                                                 << " → " << result.status
                                                 << " (" << result.duration_ms << "ms)");
                                        // Build the action_executed event and
                                        // push it into the shared buffer. The
                                        // Sender will ship it on the next batch.
                                        json ae;
                                        ae["event"] = "action_executed";
                                        ae["service"] = "agent";
                                        ae["severity"] = (result.status == "succeeded")
                                            ? "info" : "warning";
                                        ae["action_id"] = action_id;
                                        ae["action_type"] = action_type;
                                        ae["dry_run"] = dry_run;
                                        ae["action_status"] = result.status;
                                        ae["result_message"] = result.result_message;
                                        ae["duration_ms"] = result.duration_ms;
                                        ae["target_summary"] = target_summary;
                                        ae["reason"] = reason;
                                        if (!result.stdout_.empty()) {
                                            ae["stdout"] = result.stdout_;
                                        }
                                        if (a.contains("payload") && a["payload"].is_object()) {
                                            // Propagate the most useful target
                                            // fields as top-level for dashboards.
                                            const auto& p = a["payload"];
                                            if (p.contains("pid"))   ae["target_pid"]   = p["pid"];
                                            if (p.contains("ip"))    ae["target_ip"]    = p["ip"];
                                            if (p.contains("path"))  ae["target_path"]  = p["path"];
                                            if (p.contains("module"))ae["target_module"]= p["module"];
                                        }
                                        // force_push: action_executed is critical
                                        // (audit trail) — never drop.
                                        buffer.force_push(ae.dump());

                                        // T9 fix: also POST the result to the
                                        // backend's /agents/{id}/action-report
                                        // endpoint so the agent_actions DB row
                                        // transitions delivered → succeeded/failed.
                                        // Without this, the row stays at
                                        // 'delivered' forever (only the CH
                                        // event records the outcome).
                                        // The POST is best-effort: if it
                                        // fails (network/HMAC), the audit
                                        // trail in CH is still complete.
                                        try {
                                            auto now_ar = std::chrono::system_clock::now();
                                            int64_t ts_ar = std::chrono::duration_cast<std::chrono::seconds>(
                                                now_ar.time_since_epoch()).count();
                                            std::string ts_str_ar = std::to_string(ts_ar);
                                            std::string sig_ar = agent_v3::compute_action_report_hmac(
                                                hb_cred.hmac_secret, hb_cred.agent_id, ts_str_ar);
                                            std::string path_ar = "/api/v1/agents/" + hb_cred.agent_id + "/action-report";
                                            std::string url_ar = hb_cred.central_url + path_ar;
                                            // Body: matches ActionReport Pydantic model.
                                            // We use json::dump() to ensure proper escaping
                                            // of any special chars in result_message / stdout.
                                            // status is one of 'succeeded'/'failed'/'cancelled'.
                                            json body_j;
                                            body_j["id"] = action_id;
                                            body_j["status"] = result.status;
                                            body_j["result_message"] = result.result_message;
                                            body_j["duration_ms"] = result.duration_ms;
                                            if (!result.stdout_.empty()) {
                                                body_j["stdout"] = result.stdout_.substr(0, 4096);
                                                // T13.8 A-16: signal truncation
                                                if (result.stdout_.size() > 4096) {
                                                    body_j["stdout_truncated"] = true;
                                                    body_j["stdout_orig_len"] = result.stdout_.size();
                                                }
                                            }
                                            std::string body_ar = body_j.dump();
                                            // Minimal curl POST (synchronous, 5s timeout).
                                            CURL* curl_ar = curl_easy_init();
                                            if (curl_ar) {
                                                struct curl_slist* hdr_ar = nullptr;
                                                hdr_ar = curl_slist_append(hdr_ar,
                                                    ("X-Agent-Id: " + hb_cred.agent_id).c_str());
                                                hdr_ar = curl_slist_append(hdr_ar,
                                                    ("X-Timestamp: " + ts_str_ar).c_str());
                                                hdr_ar = curl_slist_append(hdr_ar,
                                                    ("X-Signature: " + sig_ar).c_str());
                                                hdr_ar = curl_slist_append(hdr_ar,
                                                    "Content-Type: application/json");
                                                curl_easy_setopt(curl_ar, CURLOPT_URL, url_ar.c_str());
                                                curl_easy_setopt(curl_ar, CURLOPT_HTTPHEADER, hdr_ar);
                                                curl_easy_setopt(curl_ar, CURLOPT_POST, 1L);
                                                curl_easy_setopt(curl_ar, CURLOPT_POSTFIELDS, body_ar.c_str());
                                                curl_easy_setopt(curl_ar, CURLOPT_POSTFIELDSIZE, (long)body_ar.size());
                                                curl_easy_setopt(curl_ar, CURLOPT_TIMEOUT, 5L);
                                                curl_easy_setopt(curl_ar, CURLOPT_NOSIGNAL, 1L);
                                                CURLcode rc_ar = curl_easy_perform(curl_ar);
                                                long http_ar = 0;
                                                curl_easy_getinfo(curl_ar, CURLINFO_RESPONSE_CODE, &http_ar);
                                                curl_slist_free_all(hdr_ar);
                                                curl_easy_cleanup(curl_ar);
                                                if (rc_ar == CURLE_OK && http_ar == 200) {
                                                    LOG_INFO("[T28] action_report POST OK for "
                                                             << action_id.substr(0,8)
                                                             << " (http=" << http_ar << ")");
                                                } else {
                                                    LOG_WARN("[T28] action_report POST failed for "
                                                             << action_id.substr(0,8)
                                                             << " curl=" << curl_easy_strerror(rc_ar)
                                                             << " http=" << http_ar
                                                             << " (CH event still shipped, audit intact)");
                                                }
                                            }
                                        } catch (const std::exception& e_ar) {
                                            LOG_WARN(std::string("[T28] action_report exception: ") + e_ar.what()
                                                     + " (CH event still shipped, audit intact)");
                                        }
                                    } catch (const std::exception& e) {
                                        LOG_ERROR("[T28] action dispatch failed: " + std::string(e.what()));
                                    }
                                }
                            }

                            // T12.10c: process pending_commands[] delivered
                            // by the backend. Each entry is a one-shot
                            // administrative command (set_log_level,
                            // reload_policy, dump_fim_state, rotate_wal).
                            //
                            // The agent executes the command locally and
                            // ships the result back via:
                            //   1) POST /api/v1/agents/{id}/command-result
                            //      (synchronous, ~5s timeout) — primary path
                            //   2) An agent_command_result event shipped
                            //      through the normal shipper — fallback
                            //      when (1) fails.
                            // We never block the heartbeat on a slow
                            // command: the executor (T12.10d) has a 30s
                            // hard timeout per command, and we process
                            // commands sequentially (the next heartbeat
                            // picks up the next one).
                            if (j.contains("pending_commands") &&
                                j["pending_commands"].is_array() &&
                                !j["pending_commands"].empty()) {
                                for (const auto& c : j["pending_commands"]) {
                                    try {
                                        int cmd_id = c.value("id", 0);
                                        std::string command = c.value("command", "");
                                        if (cmd_id == 0 || command.empty()) {
                                            LOG_WARN("[T12.10c] skipping command with empty id/name");
                                            continue;
                                        }
                                        LOG_INFO("[T12.10c] executing command " << cmd_id
                                                 << " type=" << command);
                                        // payload is an optional object.
                                        // We pass a JSON string (dump) to
                                        // the executor so the executor
                                        // doesn't have to know about
                                        // nlohmann::json.
                                        std::string payload_str = "{}";
                                        if (c.contains("payload") && c["payload"].is_object()) {
                                            payload_str = c["payload"].dump();
                                        }
                                        // Execute (max 30s, runs in this
                                        // thread). The executor is
                                        // defensive: it logs and returns
                                        // ok=true with result_text=error
                                        // info if the command is unknown.
                                        auto cmd_result = logsoc::agent::t12_10c::execute(
                                            command, payload_str);
                                        LOG_INFO("[T12.10c] command " << cmd_id
                                                 << " → " << cmd_result.status
                                                 << " (" << cmd_result.duration_ms << "ms)");
                                        // 1) Synchronous POST to
                                        //    /api/v1/agents/{id}/command-result
                                        //    (best-effort, 5s timeout).
                                        try {
                                            auto now_cr = std::chrono::system_clock::now();
                                            int64_t ts_cr = std::chrono::duration_cast<std::chrono::seconds>(
                                                now_cr.time_since_epoch()).count();
                                            std::string ts_str_cr = std::to_string(ts_cr);
                                            // T12.10c: HMAC the body. We
                                            // reuse the same message format
                                            // as the heartbeat for
                                            // consistency. The HMAC
                                            // helpers take a vector key
                                            // (the secret is a string of
                                            // raw bytes), so we build the
                                            // vectors once.
                                            std::vector<uint8_t> key_cr(
                                                hb_cred.hmac_secret.begin(),
                                                hb_cred.hmac_secret.end());
                                            std::string body_hash_cr = sha256_hex(
                                                cmd_result.body_to_post);
                                            std::string sig_payload_cr =
                                                ts_str_cr + "." + body_hash_cr;
                                            std::vector<uint8_t> data_cr(
                                                sig_payload_cr.begin(),
                                                sig_payload_cr.end());
                                            std::vector<uint8_t> mac_cr =
                                                crypto::hmac_sha256(data_cr, key_cr);
                                            std::string sig_cr = hex_encode(mac_cr);
                                            std::string path_cr = "/api/v1/agents/" +
                                                hb_cred.agent_id + "/command-result";
                                            std::string url_cr = hb_cred.central_url + path_cr;
                                            CURL* curl_cr = curl_easy_init();
                                            if (curl_cr) {
                                                struct curl_slist* hdr_cr = nullptr;
                                                hdr_cr = curl_slist_append(hdr_cr,
                                                    ("X-Agent-Id: " + hb_cred.agent_id).c_str());
                                                hdr_cr = curl_slist_append(hdr_cr,
                                                    ("X-Timestamp: " + ts_str_cr).c_str());
                                                hdr_cr = curl_slist_append(hdr_cr,
                                                    ("X-Signature: " + sig_cr).c_str());
                                                hdr_cr = curl_slist_append(hdr_cr,
                                                    "Content-Type: application/json");
                                                curl_easy_setopt(curl_cr, CURLOPT_URL, url_cr.c_str());
                                                curl_easy_setopt(curl_cr, CURLOPT_HTTPHEADER, hdr_cr);
                                                curl_easy_setopt(curl_cr, CURLOPT_POST, 1L);
                                                curl_easy_setopt(curl_cr, CURLOPT_POSTFIELDS,
                                                    cmd_result.body_to_post.c_str());
                                                curl_easy_setopt(curl_cr, CURLOPT_POSTFIELDSIZE,
                                                    (long)cmd_result.body_to_post.size());
                                                curl_easy_setopt(curl_cr, CURLOPT_TIMEOUT, 5L);
                                                curl_easy_setopt(curl_cr, CURLOPT_NOSIGNAL, 1L);
                                                CURLcode rc_cr = curl_easy_perform(curl_cr);
                                                long http_cr = 0;
                                                curl_easy_getinfo(curl_cr, CURLINFO_RESPONSE_CODE, &http_cr);
                                                curl_slist_free_all(hdr_cr);
                                                curl_easy_cleanup(curl_cr);
                                                if (rc_cr == CURLE_OK && http_cr == 200) {
                                                    LOG_INFO("[T12.10c] command_result POST OK for "
                                                             << cmd_id << " (http=" << http_cr << ")");
                                                } else {
                                                    LOG_WARN("[T12.10c] command_result POST failed for "
                                                             << cmd_id << " curl=" << curl_easy_strerror(rc_cr)
                                                             << " http=" << http_cr
                                                             << " (CH event still shipped, audit intact)");
                                                }
                                            }
                                        } catch (const std::exception& e_cr) {
                                            LOG_WARN(std::string("[T12.10c] command_result exception: ") +
                                                     e_cr.what() + " (CH event still shipped, audit intact)");
                                        }
                                        // 2) Always also push the result
                                        //    through the normal shipper as
                                        //    a force_push event. This is
                                        //    the audit trail that survives
                                        //    if the POST fails.
                                        json ce;
                                        ce["event"] = "agent_command_result";
                                        ce["service"] = "agent";
                                        ce["severity"] = (cmd_result.status == "done") ? "info" : "warning";
                                        ce["command_id"] = cmd_id;
                                        ce["command"]    = command;
                                        ce["status"]     = cmd_result.status;
                                        ce["result_text"]= cmd_result.result_text;
                                        ce["error_text"] = cmd_result.error_text;
                                        ce["duration_ms"]= cmd_result.duration_ms;
                                        buffer.force_push(ce.dump());
                                    } catch (const std::exception& e) {
                                        LOG_ERROR("[T12.10c] command dispatch failed: " + std::string(e.what()));
                                    }
                                }
                            }
                        } catch (const std::exception& e) {
                            LOG_WARN("[HB] Invalid heartbeat response: " + std::string(e.what()));
                        }
                    }
                }
            }
        });

        LOG_INFO("[*] LogSOC Agent v3.11 running. Ctrl+C to stop.");

        // 9. Main loop
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        int loop_ticks = 0;
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            loop_ticks++;
            // T64.4.2: every 30s, check if policy.fim_watch_paths changed.
            // If yes, restart FanotifyCollector with the new paths.
            //
            // T12 audit fix #24: lock the policy mutex while we copy the
            // vector out. The copy is passed to rebuild_fanotify_collector
            // by value, so we can release the lock before the (potentially
            // slow) rebuild. The atomic dirty flag is set/cleared outside
            // the lock — it's just a signal.
            if (loop_ticks % 30 == 0 && cfg.policy.fim_watch_paths_dirty.exchange(false)) {
                try {
                    std::vector<std::string> paths_copy;
                    {
                        std::lock_guard<std::mutex> pl(cfg.policy.policy_mtx);
                        paths_copy = cfg.policy.fim_watch_paths;
                    }
                    LOG_INFO("[Main] applying policy.fim_watch_paths change ("
                             << paths_copy.size() << " paths)");
                    rebuild_fanotify_collector(
                        fanotify_coll, cfg, buffer,
                        (yara_engine ? yara_engine.get() : nullptr),
                        paths_copy);
                    LOG_INFO("[Main] FanotifyCollector rebuilt with new watch paths");
                } catch (const std::exception& e) {
                    LOG_WARN("[Main] FanotifyCollector rebuild failed: " << e.what());
                }
            }
            // T30.3: every 30s, check if policy.enabled_probes changed.
            // If yes, rebuild the eBPF links (destroy + reattach). The
            // source of truth is cfg.policy.enabled_probes (central
            // override). If empty, we fall back to the local config
            // (cfg.enabled_probes, the bootstrap default). The rebuild
            // is safe to call repeatedly; is_probe_enabled() in loader.cpp
            // does the actual filtering.
            //
            // T12 audit fix #24: lock around the copy of enabled_probes.
            if (loop_ticks % 30 == 0 && cfg.policy.enabled_probes_dirty.exchange(false)) {
                LOG_INFO("[T30.3] enabled_probes drift detected — rebuilding eBPF links");
                // Merge: central override wins over local if non-empty.
                std::unordered_map<std::string, bool> effective =
                    cfg.enabled_probes;  // local default
                {
                    std::lock_guard<std::mutex> pl(cfg.policy.policy_mtx);
                    for (const auto& kv : cfg.policy.enabled_probes) {
                        effective[kv.first] = kv.second;
                    }
                }
                // 1. Update the in-loader map
                ebpf::set_enabled_probes(effective);
                // 2. Destroy + reattach the kernel links
                int attached = ebpf::rebuild_ebpf_probes();
                LOG_INFO("[T30.3] rebuild done: " << attached << " probes attached");
            }
            // T4.8.9: every 5s, snapshot the NetworkCollector stats
            // into the unified FimMetrics counters. This is what makes
            // pcap metrics visible on the /metrics HTTP endpoint (port
            // 9011) without forcing FimMetricsServer to take a mutex
            // on NetworkCollector (which would block pcap_loop on a
            // metrics scrape). Cheap (4 atomic stores).
            if (loop_ticks % 5 == 0) {
                uint64_t cap=0, drop=0, push=0, err=0;
                net.get_stats(&cap, &drop, &push, &err);
                logsoc::agent::metrics::FimMetrics::set_net_stats(cap, drop, push, err);
            }
        }

        // 10. Shutdown
        LOG_INFO("[*] Stopping...");
        // Signal the in-memory buffer to stop accepting new pushes
        buffer.stop();
        // Flush any remaining in-memory events to fallback WAL (durable)
        std::optional<std::string> leftover_opt;
        while ((leftover_opt = buffer.pop()).has_value()) {
            fallback_wal.push(*leftover_opt);
        }
        LOG_INFO("[*] InMemoryBuffer drained (" << fallback_wal.count() << " events in FallbackWAL)");
        // T13.9: app_collectors stop is now safe WITHOUT the mutex because
        // heartbeat_thread is joined later (line ~5314). The mutex (added
        // above) only protects the heartbeat-thread rebuild path during
        // runtime; at shutdown the heartbeat thread is already gone, so
        // there's no concurrent access. Safe to iterate the vector here.
        for (auto& c : app_collectors) c->stop();
        if (journald_coll) journald_coll->stop();
        if (fanotify_coll) fanotify_coll->stop();
        sender.stop();
        puller.stop();  // T64.2.2: stop background policy puller
        // T13.9: ebpf_ptr cleanup moved to AFTER heartbeat_thread.join()
        // (below). The OLD code at this point did:
        //     if (ebpf_ptr) {
        //         ebpf_ptr->stop();
        //         delete ebpf_ptr;
        //         ebpf_ptr = nullptr;
        //     }
        // which is a USE-AFTER-FREE: the heartbeat thread reads
        // `ebpf_ptr->priority_dropped()` every cycle, but the raw ptr was
        // destroyed before heartbeat_thread.join() at line ~5314. Killed
        // audit A-14. See "T13.9 Threading Model" comment in main().
        // v4.8.0 (T4.8): stop the FIM pipeline (must be before sender.stop()
        // to drain any in-flight events into the buffer first).
        fim_shipper_stop.store(true);
        if (fim_shipper_thread.joinable()) fim_shipper_thread.join();
        // T13.3': stop the action recommender child + validator thread.
        // The validator must stop first (it can pop from a dead
        // child's queue, which is OK because pop_recommendation is
        // bounded). The child is stopped by its destructor (unique_ptr
        // goes out of scope after the join).
        action_validator_stop.store(true);
        if (action_validator_thread.joinable()) action_validator_thread.join();
        action_recommender_proc.reset();  // dtor calls child stop()
        action_validator_inst.reset();
        // fim_collector / fim_resolver destructors handle their own
        // thread joins + CB state persistence.
        // T12.11 (2026-06-16): FimMetricsServer removed — no thread to stop.
        net.stop();
        // T31: stop the metrics shipper thread (it's a 60s sleep loop,
        // so set g_running=false and join).
        if (metrics_thread.joinable()) metrics_thread.join();
        heartbeat_thread.join();
        // T13.9: destroy ebpf_ptr AFTER heartbeat_thread.join() to prevent UAF.
        // The heartbeat thread reads ebpf_ptr->priority_dropped() every cycle;
        // destroying it before the join would be a use-after-free (audit A-14).
        // ebpf_ptr is now a unique_ptr (was a raw ptr before T13.9), so we
        // call ->stop() then .reset() which invokes the EbpfCollector dtor.
        // T13.10: atomic_unique_ptr.reset() now takes care of stop() internally
        // (and takes the lock), so the explicit stop() before is redundant —
        // but we keep it for clarity (the lambda heartbeat closure cannot see
        // a half-reset state because reset() is atomic w.r.t. the lock).
        if (ebpf_ptr) {
            ebpf_ptr.reset();  // T13.10: stop() called inside atomic_unique_ptr::reset
        }
        // v3.10.0: stop YARA pull thread and release engine (YrFinalize inside dtor)
        if (yara_pull_thread.joinable()) yara_pull_thread.join();
        // T77 (v3.21.0): stop the YaraRulesetPuller (must run BEFORE
        // yara_engine.reset() because the puller holds a non-owning
        // pointer to the engine).
        if (yara_ruleset_puller) yara_ruleset_puller->stop();
        // v3.15 (T59): stop the YaraShipper before the yara_engine (the
        // shipper has no dependency on the engine, but the destructor is
        // RAII so the unique_ptr reset below will do it. We do it
        // explicitly first to flush any in-flight ship before the engine
        // dtor runs (defensive, no functional impact).
        if (yara_shipper) {
            yara_shipper->stop();
            yara_shipper.reset();
        }
        yara_engine.reset();
        curl_global_cleanup();
        // Best-effort zero of credentials in RAM
        cred.clear();
        LOG_INFO("[*] Agent stopped.");

    } catch (const std::exception& e) {
        LOG_ERROR("[!] Fatal: " + std::string(e.what()));
        return 1;
    }
    return 0;
}
