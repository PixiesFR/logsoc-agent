/**
 * agent_auth.hpp — LogSOC Agent v3.1 Authentication
 *
 * Flow v3.1:
 *   1. Agent demarre sans auth.json
 *   2. POST /api/v1/agents/register → 202 + request_id (pending)
 *   3. GET  /api/v1/agents/status?request_id=... toutes les N sec
 *      → 202 pending (continue attente)
 *      → 403 rejected (exit)
 *      → 200 active (reçoit token, hmac_secret, wal_secret)
 *   4. Écrit auth.json (0600)
 *   5. Démarrage normal (collect + send + heartbeat)
 *
 *   Si auth.json existe → charger + actif direct
 *   Si status devient revoked → supprime auth.json + exit
 */

#ifndef AGENT_AUTH_HPP
#define AGENT_AUTH_HPP
#include <string>
#include <vector>
#include <optional>
#include "json.hpp"

namespace agent_v3 {

    struct PendingState {
        std::string request_id;
        std::string agent_id;
        std::string central_url;
        long long   registered_at = 0;
    };

    struct Credentials {
        std::string agent_id;
        std::string token;
        std::string hmac_secret;
        std::string wal_secret;
        std::string central_url;
    };

    // Pending state (saved after register, removed after activation)
    bool load_pending_state(const std::string& directory, PendingState& out);
    bool save_pending_state(const std::string& directory, const PendingState& in);
    void remove_pending_state(const std::string& directory);

    bool load_credentials(const std::string& directory, Credentials& out);
    bool save_credentials(const std::string& directory, const Credentials& in);
    void clear_auth(const std::string& directory);
    void clear_all_auth(const std::string& directory);

    /** POST /api/v1/agents/register → retourne request_id en pending */
    bool perform_registration(const std::string& url, const std::string& hostname,
                              const std::string& version, std::string& out_request_id,
                              std::string& out_agent_id, std::string& out_central_url);

    /** GET /api/v1/agents/status poll loop. Bloque jusqu'à active ou erreur. */
    bool poll_activation_status(const std::string& url, const std::string& request_id,
                                const std::string& agent_id, Credentials& out,
                                int timeout_sec = 3600, int interval_sec = 10,
                                const std::string& directory = "");

    // T12.10 (2026-06-16): aggregate metrics snapshot for the
    // heartbeat payload. Combines:
    // - FimMetrics::CountersSnapshot (FIM pipeline + network + CB)
    // - YaraShipper::StatsSnapshot (YARA content shipping)
    // Each field is a .load() snapshot of the corresponding atomic
    // counter on the source thread, so the overall snapshot is
    // consistent-enough for monitoring (counters may interleave by
    // 1-2 events, no torn reads on x86-64).
    // This struct is plain old data so the heartbeat can copy it
    // cheaply on every poll. See src/agent/fim_metrics.hpp and
    // src/yara_shipper.hpp for the source of each field.
    struct MetricsSnapshot {
        // FimMetrics
        uint64_t fd_resolved = 0;
        uint64_t fd_timeout = 0;
        uint64_t fd_eperm = 0;
        uint64_t fd_not_found = 0;
        uint64_t fd_cb_open = 0;
        uint64_t fd_errors = 0;
        uint64_t fd_dropped = 0;
        uint64_t fim_merged = 0;
        uint64_t fim_dropped = 0;
        uint64_t fim_rate_limited = 0;
        uint64_t fim_watchdog_pings = 0;
        uint64_t fim_shipped = 0;
        uint64_t net_packets_captured = 0;
        uint64_t net_packets_dropped = 0;
        uint64_t net_events_pushed = 0;
        uint64_t net_flush_errors = 0;
        uint64_t cb_trips = 0;
        // YaraShipper
        uint64_t yara_shipped = 0;
        uint64_t yara_dropped = 0;
        uint64_t yara_failed = 0;
        uint64_t yara_skipped_size = 0;
        uint64_t yara_skipped_unreadable = 0;
        uint64_t yara_skipped_too_large = 0;  // T12.16: files > max_scan_size
        uint64_t yara_matched = 0;
        // YaraEngine (rule compiler/matcher, separate from shipper)
        uint64_t yara_rules_loaded = 0;
        uint64_t yara_scans_total = 0;
        uint64_t yara_matches_total = 0;
    };

    /** POST /api/v1/agents/heartbeat. Retourne la config fusionnée JSON. */
    std::string perform_heartbeat(const Credentials& cred,
                                const std::string& version,        // v3.10.0: agent self-version
                                int wal_segments, uint64_t buf_dropped, uint64_t ringbuf_dropped,
                                int cpu_percent, int mem_mb,
                                const std::string& network_status,
                                const std::string& ebpf_mode,
                                const std::string& ebpf_reason,
                                uint64_t priority_dropped,  // v3.9.7: distinct from buf_dropped
                                long& http_code,
                                // v3.21.0 / T66 (logsoc-web#15):
                                //   nullopt → no encryption status reported
                                //   true / false → known encrypted / unencrypted
                                const std::optional<bool>& encryption_at_rest = std::nullopt,
                                const std::string& encryption_detection_method = "",
                                // T30.2: ringbuf kernel-level loss tracking
                                // (events produced by eBPF but overwritten in
                                // the ring buffer before we could read them).
                                // These are independent of priority_dropped
                                // (which is the cheap userspace filter).
                                uint64_t ringbuf_lost_events = 0,
                                uint64_t ringbuf_total_events = 0,
                                // T30.3: list of eBPF probe names currently
                                // attached. Backend uses this to verify the
                                // hot-reload worked and to render a UI badge.
                                const std::vector<std::string>& enabled_probes_list = {},
                                // T12.10 (2026-06-16): optional metrics
                                // snapshot for the heartbeat payload.
                                // Replaces the to-be-removed /metrics HTTP
                                // server (T12.10d) with an outbound-only
                                // channel. Pass std::nullopt for callers
                                // that don't collect metrics yet (tests,
                                // legacy code paths).
                                const std::optional<MetricsSnapshot>& metrics = std::nullopt,
                                // Host info fields for dashboard display
                                const std::string& os_name = "",
                                const std::string& os_version = "",
                                const std::string& arch = "",
                                const std::string& host_ips = "",
                                const std::string& mac = "",
                                const std::string& cpu_model = "",
                                int memory_mb = 0,
                                int disk_gb = 0,
                                // v4.9.0: SHA-256 of the agent's current config.json.
                                // The backend compares this with its stored config_json
                                // hash and pushes the full config back if they differ.
                                // Empty string = not computed (backward compat).
                                const std::string& config_hash = "");

    /** Calcule HMAC-SHA256(timestamp + sha1(body)).
     *  T14.1 — H-06 prep: optional nonce parameter. If non-empty, the
     *  signed payload becomes f"{timestamp}.{nonce}.{sha256_hex(body)}"
     *  instead of f"{timestamp}.{sha256_hex(body)}". The nonce is a
     *  monotonically increasing counter (uint64) from Credentials.
     *
     *  This is the AGENT-SIDE prep work for H-06 closure. The actual
     *  replay protection requires the central to dedup nonces via
     *  Redis SET (TTL 60s, see T14.1 ticket). When the central team
     *  enables nonce verification, they will:
     *    1. Accept X-Nonce header on POST /api/v1/events/
     *    2. Compute the same signed payload with the nonce
     *    3. Reject the request if (agent_id, nonce) is already in the
     *       Redis SET within hmac_window_sec (60s).
     *
     *  Until then, the agent sends the nonce but the central ignores
     *  it. Zero risk, zero behavior change. The branch is
     *  `t14.1-hmac-nonce-prep` so it can be merged when R3 unblocks. */
    std::string compute_ingest_hmac(const Credentials& cred,
                                    const std::string& timestamp,
                                    const std::string& json_body,
                                    const std::string& nonce = "");

    /** v3.8.0 overload: same HMAC but with individual fields (from RuntimeCredentials) */
    std::string compute_ingest_hmac(const std::string& agent_id,
                                    const std::string& hmac_secret,
                                    const std::string& central_url,
                                    const std::string& timestamp,
                                    const std::string& json_body,
                                    const std::string& nonce = "");

    /** T64.2.2 (v3.20.0): HMAC for policy GET endpoint.
     *  Backend message format: f"{timestamp}.{agent_id}.{method}.{path}"
     *  See /home/hermes/logsoc-web/app/routers/agent_config.py _verify_hmac_get.
     *  No body to hash (GET request). */
    std::string compute_policy_get_hmac(const std::string& hmac_secret,
                                        const std::string& agent_id,
                                        const std::string& timestamp,
                                        const std::string& method,
                                        const std::string& path);

    /** T9 fix (v3.12.2): HMAC for action-report POST endpoint.
     *  Backend message format: f"{timestamp}.{agent_id}.POST./agents/{agent_id}/action-report"
     *  (no body hash, just like policy_get). Used by the agent to
     *  report the result of an action delivered in pending_actions[]. */
    std::string compute_action_report_hmac(const std::string& hmac_secret,
                                           const std::string& agent_id,
                                           const std::string& timestamp);

} // namespace agent_v3

#endif
