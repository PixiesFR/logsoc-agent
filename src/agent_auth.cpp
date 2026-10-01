#include "agent_auth.hpp"
#include "runtime_credentials.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <filesystem>
#include <ctime>
#include <optional>
#include <unistd.h>  // T14.6: gethostname() for heartbeat hostname field
#include <sys/stat.h>
#include <unistd.h>      // T12.14: geteuid() for M-04 owner check
#include <curl/curl.h>
#include "crypto.hpp"

using json = nlohmann::json;
using namespace crypto;

namespace agent_v3 {

static size_t string_write_cb(void* ptr, size_t sz, size_t n, void* ud) {
    auto* s = static_cast<std::string*>(ud);
    s->append((char*)ptr, sz * n);
    return sz * n;
}

/** Wrapper HTTP POST */
bool http_post(const std::string& url, const std::string& body,
               const std::vector<std::string>& hdrs,
               std::string& resp, long& http_code) {
    CURL* c = curl_easy_init();
    if (!c) return false;
    struct curl_slist* h = nullptr;
    h = curl_slist_append(h, "Content-Type: application/json");
    h = curl_slist_append(h, "X-Agent-Version: v3.7.0");  // ANOM-007: protocol versioning
    for (const auto& x : hdrs) h = curl_slist_append(h, x.c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);  // T12 audit fix #48: don't use SIGALRM for timeouts
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);        // VULN-014: enforce TLS verification
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);        // VULN-014: strict hostname verification
    #if LIBCURL_VERSION_NUM >= 0x075500 // curl >= 7.85.0
        curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https,http");  // VULN-013: SSRF fix
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https,http");
    #else
        curl_easy_setopt(c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    #endif
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, string_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    CURLcode r = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);
    return r == CURLE_OK;
}

/** Wrapper HTTP GET */
bool http_get(const std::string& url, const std::vector<std::string>& hdrs,
              std::string& resp, long& http_code) {
    CURL* c = curl_easy_init();
    if (!c) return false;
    struct curl_slist* h = nullptr;
    for (const auto& x : hdrs) h = curl_slist_append(h, x.c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);  // T12 audit fix #48
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);        // VULN-014: TLS verification
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);        // VULN-014: hostname verification
    #if LIBCURL_VERSION_NUM >= 0x075500 // curl >= 7.85.0
        curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https,http");  // VULN-013: SSRF fix
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https,http");
    #else
        curl_easy_setopt(c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    #endif
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, string_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    CURLcode r = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);
    return r == CURLE_OK;
}

/* ── JSON parse helper (strict, not .value/or) ── */
template<typename T>
T get_or(const json& j, const char* key, const T& def) {
    auto it = j.find(key);
    if (it != j.end() && !it->is_null()) return it->get<T>();
    return def;
}

/* ── Credentials I/O ── */

bool load_credentials(const std::string& directory, Credentials& out) {
    std::ifstream f(directory + "/auth.json");
    if (!f) return false;
    try {
        json j; f >> j;
        out.agent_id    = get_or(j, "agent_id", std::string());
        out.token       = get_or(j, "agent_token", std::string());
        out.hmac_secret = get_or(j, "hmac_secret", std::string());
        out.wal_secret  = get_or(j, "wal_secret", std::string());
        out.central_url = get_or(j, "central_url", std::string("https://logsoc.anytimeadmin.info"));
        if (!out.central_url.empty()) {
            while (!out.central_url.empty() && out.central_url.back() == '/')
                out.central_url.pop_back();
        }
        return !out.agent_id.empty() && !out.token.empty() && !out.hmac_secret.empty();
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] Parse error (auth.json): " << e.what() << "\n";
        return false;
    }
}

bool save_credentials(const std::string& directory, const Credentials& in) {
    // T12.13 (audit Nova M-04): even with umask(0077), the parent
    // directory could be world-writable, allowing a TOCTOU via symlink
    // replacement. Verify directory ownership + perms BEFORE we write
    // the credentials file. Best-effort: if stat fails (directory
    // doesn't exist yet) we let the open() below produce the real
    // error.
    #ifdef __linux__
    {
        struct stat st{};
        if (::stat(directory.c_str(), &st) == 0) {
            // Owner must be us (geteuid) or root, and group/other
            // must not have write access. 0o170 = owner-rwx, no
            // group/other perms — overly strict for a shared dir, so
            // we check just the dangerous bits: 0o022 (group-w, other-w).
            if (st.st_uid != ::geteuid() && st.st_uid != 0) {
                std::fprintf(stderr,
                    "[auth] credentials dir %s owned by uid=%u (expected %u or 0) — refusing to write\n",
                    directory.c_str(), (unsigned)st.st_uid, (unsigned)::geteuid());
                return false;
            }
            if ((st.st_mode & 022) != 0) {
                std::fprintf(stderr,
                    "[auth] credentials dir %s is group/other writable (mode=0%o) — refusing to write\n",
                    directory.c_str(), (unsigned)(st.st_mode & 0777));
                return false;
            }
        }
    }
    #endif
    json j;
    j["agent_id"]    = in.agent_id;
    j["agent_token"] = in.token;
    j["hmac_secret"] = in.hmac_secret;
    j["wal_secret"]  = in.wal_secret;
    j["central_url"]  = in.central_url;
    {
        #ifdef __linux__
        mode_t old_umask = umask(0077);  // VULN-008: fix TOCTOU — restrict before creation
        #endif
        std::ofstream f(directory + "/auth.json");
        #ifdef __linux__
        umask(old_umask);  // Restore umask after file creation
        #endif
        if (!f) return false;
        f << j.dump(2);
        f.flush();
        if (f.fail()) return false;
    }
    // permissions double-check best-effort
    #ifdef __linux__
    chmod((directory + "/auth.json").c_str(), 0600);
    #endif
    return true;
}

void clear_auth(const std::string& directory) {
    std::error_code ec;
    std::filesystem::remove(directory + "/auth.json", ec);
    // NE PAS supprimer pending.json — l'agent peut vouloir repoller
}

void clear_all_auth(const std::string& directory) {
    std::error_code ec;
    std::filesystem::remove(directory + "/auth.json", ec);
    std::filesystem::remove(directory + "/pending.json", ec);
    std::filesystem::remove(directory + "/agent_id.txt", ec);
}

/* ── Pending state ── */

bool load_pending_state(const std::string& directory, PendingState& out) {
    std::ifstream f(directory + "/pending.json");
    if (!f) return false;
    try {
        json j; f >> j;
        out.request_id     = get_or(j, "request_id", std::string());
        out.agent_id       = get_or(j, "agent_id", std::string());
        out.central_url    = get_or(j, "central_url", std::string());
        out.registered_at  = get_or(j, "registered_at", 0LL);
        return !out.request_id.empty() && !out.agent_id.empty();
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] Parse error (pending.json): " << e.what() << "\n";
        return false;
    }
}

bool save_pending_state(const std::string& directory, const PendingState& in) {
    json j;
    j["request_id"]     = in.request_id;
    j["agent_id"]       = in.agent_id;
    j["central_url"]    = in.central_url;
    j["registered_at"]  = in.registered_at;
    {
        #ifdef __linux__
        mode_t old_umask = umask(0077);
        #endif
        std::ofstream f(directory + "/pending.json");
        #ifdef __linux__
        umask(old_umask);
        #endif
        if (!f) return false;
        f << j.dump(2);
        f.flush();
        if (f.fail()) return false;
    }
    #ifdef __linux__
    chmod((directory + "/pending.json").c_str(), 0600);
    #endif
    return true;
}

void remove_pending_state(const std::string& directory) {
    std::error_code ec;
    std::filesystem::remove(directory + "/pending.json", ec);
}

/* ── Registration ── */

bool perform_registration(const std::string& url, const std::string& hostname,
                          const std::string& version,
                          std::string& out_request_id,
                          std::string& out_agent_id,
                          std::string& out_central_url) {
    json req;
    req["hostname"] = hostname;
    req["version"]  = version;
    req["platform"] = "linux-x86_64";
    std::string resp;
    long code;
    std::string normalized = url;
    while (!normalized.empty() && normalized.back() == '/') normalized.pop_back();
    out_central_url = normalized;

    std::cerr << "[AUTH] Registering agent with central " << out_central_url << "\n";
    if (!http_post(out_central_url + "/api/v1/agents/register", req.dump(), {}, resp, code)) {
        std::cerr << "[AUTH] Register POST failed: curl error\n";
        return false;
    }
    if (code != 200 && code != 202) {
        std::cerr << "[AUTH] Register failed HTTP " << code << " — " << resp << "\n";
        return false;
    }
    try {
        json j = json::parse(resp);
        out_request_id = get_or(j, "request_id", std::string());
        out_agent_id   = get_or(j, "agent_id", std::string());
        // v3.2 backend: agent_id is also used as request_id
        if (out_request_id.empty() && !out_agent_id.empty()) {
            out_request_id = out_agent_id;
        }
        if (out_request_id.empty() || out_agent_id.empty()) {
            std::cerr << "[AUTH] Register response missing request_id/agent_id\n";
            return false;
        }
        std::cerr << "[AUTH] Agent registered, status: pending, request_id: " << out_request_id << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] Register parse error: " << e.what() << "\n";
        return false;
    }
}

/* ── Poll activation ── */

bool poll_activation_status(const std::string& url,
                            const std::string& request_id,
                            const std::string& agent_id,
                            Credentials& out,
                            int timeout_sec, int interval_sec,
                            const std::string& directory) {
    auto start = std::time(nullptr);
    std::string normalized = url;
    while (!normalized.empty() && normalized.back() == '/') normalized.pop_back();
    std::cerr << "[AUTH] Polling activation every " << interval_sec << "s (max " << timeout_sec << "s)\n";

    while (true) {
        std::string resp;
        long code;
        std::string full_url = normalized + "/api/v1/agents/status?request_id=" + request_id;
        if (!http_get(full_url, {}, resp, code)) {
            std::cerr << "[AUTH] Poll network error\n";
            std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
            continue;
        }
        if (code == 202) {
            std::cerr << "[AUTH] Status: pending, waiting...\n";
        } else if (code == 403) {
            // Revocation process: parse structured JSON body.
            // If the server returns {"status":"revoked","action":"delete_identity",...}
            // or {"status":"deleted","action":"delete_identity",...}, the agent
            // must delete its identity file and stop.
            bool should_delete_identity = false;
            std::string revoke_status;
            try {
                json j403 = json::parse(resp);
                revoke_status = j403.value("status", std::string());
                std::string action = j403.value("action", std::string());
                if ((revoke_status == "revoked" || revoke_status == "deleted") && action == "delete_identity") {
                    should_delete_identity = true;
                }
            } catch (...) {
                // Not JSON or unparseable — treat as generic 403
            }
            if (should_delete_identity) {
                std::cerr << "[AUTH] Agent " << revoke_status << " by admin. Deleting agent.identity and stopping.\n";
                if (!directory.empty()) {
                    runtime_cred::delete_agent_identity(directory);
                }
                return false;
            }
            std::cerr << "[AUTH] Status: rejected (HTTP 403). Contact admin.\n";
            if (!directory.empty()) {
                remove_pending_state(directory);
                std::cerr << "[AUTH] Pending state cleared.\n";
            }
            return false;
        } else if (code == 404) {
            std::cerr << "[AUTH] Agent ID not found on server (HTTP 404). Will need to re-register.\n";
            return false;
        } else if (code == 200) {
            try {
                json j = json::parse(resp);
                std::string status = get_or(j, "status", std::string());
                if (status == "active") {
                    out.agent_id     = agent_id;
                    out.token          = get_or(j, "agent_token", std::string());
                    out.hmac_secret    = get_or(j, "hmac_secret", std::string());
                    out.wal_secret     = get_or(j, "wal_secret", std::string());
                    out.central_url    = normalized;
                    if (out.token.empty() || out.hmac_secret.empty() || out.wal_secret.empty()) {
                        std::cerr << "[AUTH] Activation response missing secrets\n";
                        return false;
                    }
                    std::cerr << "[AUTH] Activated as " << out.agent_id << "\n";
                    return true;
                } else if (status == "pending") {
                    std::cerr << "[AUTH] Status: pending, waiting...\n";
                    // Continue polling below
                } else if (status == "rejected") {
                    std::cerr << "[AUTH] Status: rejected. Contact admin.\n";
                    if (!directory.empty()) {
                        remove_pending_state(directory);
                        std::cerr << "[AUTH] Pending state cleared.\n";
                    }
                    return false;
                } else {
                    // "inactive" or any other unknown status: warn and retry
                    std::cerr << "[AUTH] Unexpected status: " << status << " — will retry in 60s\n";
                    std::this_thread::sleep_for(std::chrono::seconds(60));
                    if (std::time(nullptr) - start > timeout_sec) {
                        std::cerr << "[AUTH] Activation timeout after " << timeout_sec << "s\n";
                        return false;
                    }
                    continue;
                }
            } catch (const std::exception& e) {
                std::cerr << "[AUTH] Parse error: " << e.what() << "\n";
                return false;
            }
        } else {
            std::cerr << "[AUTH] Unexpected HTTP " << code << " — " << resp << " — retrying in 60s\n";
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (std::time(nullptr) - start > timeout_sec) {
                std::cerr << "[AUTH] Activation timeout after " << timeout_sec << "s\n";
                return false;
            }
            continue;
        }

        if (std::time(nullptr) - start > timeout_sec) {
            std::cerr << "[AUTH] Activation timeout after " << timeout_sec << "s\n";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
    }
}

/* ── Heartbeat ── */

std::string perform_heartbeat(const Credentials& cred,
                             const std::string& version,
                             int wal_segments, uint64_t buf_dropped, uint64_t ringbuf_dropped,
                             int cpu_percent, int mem_mb,
                             const std::string& network_status,
                             const std::string& ebpf_mode,
                             const std::string& ebpf_reason,
                             uint64_t priority_dropped,
                             long& http_code,
                             // v3.21.0 / T66: optional disk-encryption status
                             // (logsoc-web#15). nullopt = not detected; false
                             // = known unencrypted; true = known encrypted.
                             // detection_method is informational.
                             // Defaults are declared in the header; do NOT
                             // re-declare them here (gcc -fpermissive
                             // would otherwise reject the .cpp).
                             const std::optional<bool>& encryption_at_rest,
                             const std::string& encryption_detection_method,
                             uint64_t ringbuf_lost_events,
                             uint64_t ringbuf_total_events,
                             const std::vector<std::string>& enabled_probes_list,
                             // T12.10 (2026-06-16): optional metrics
                             // snapshot. std::nullopt = no metrics
                             // section in the body (legacy callers,
                             // tests). When provided, all counters
                             // are sent under stats.metrics.*
                             const std::optional<MetricsSnapshot>& metrics,
                             // Host info fields for dashboard display
                             const std::string& os_name,
                             const std::string& os_version,
                             const std::string& arch,
                             const std::string& host_ips,
                             const std::string& mac,
                             const std::string& cpu_model,
                             int memory_mb,
                             int disk_gb,
                             // v4.9.0: SHA-256 of the agent's current config.json.
                             // The backend compares this with its stored config_json
                             // hash and pushes the full config back if they differ.
                             const std::string& config_hash) {
    json body;
    body["timestamp"] = std::time(nullptr);
    // T14.6 (2026-06-19): send hostname in heartbeat body so the central
    // can detect OS renames / container restarts / VM migrations. The
    // agent_id stays stable (stored in agent.identity), hostname is an
    // updatable attribute. The central compares this with the stored
    // hostname and logs an audit event if they differ.
    {
        char hb_host[256] = {};
        if (gethostname(hb_host, sizeof(hb_host) - 1) == 0) {
            body["hostname"] = hb_host;
        }
    }
    // v3.10.0: report our own version to the central.
    // Lets the dashboard reflect .deb upgrades without a re-register.
    if (!version.empty()) body["agent_version"] = version;
    // v3.6: host info fields for dashboard display
    if (!os_name.empty())      body["os_name"]      = os_name;
    if (!os_version.empty())   body["os_version"]   = os_version;
    if (!arch.empty())         body["arch"]         = arch;
    if (!host_ips.empty())     body["host_ips"]     = host_ips;
    if (!mac.empty())          body["mac"]           = mac;
    if (!cpu_model.empty())    body["cpu_model"]    = cpu_model;
    if (memory_mb > 0)         body["memory_mb"]    = memory_mb;
    if (disk_gb > 0)           body["disk_gb"]      = disk_gb;
    body["stats"]["cpu_percent"]     = cpu_percent;
    body["stats"]["memory_mb"]       = mem_mb;
    body["stats"]["wal_segments"]    = wal_segments;
    body["stats"]["buf_dropped"]     = buf_dropped;          // v3.9.6: InMemoryBuffer userspace drops (oldest forced)
    body["stats"]["ringbuf_dropped"] = ringbuf_dropped;      // v3.9.6: eBPF ringbuf kernel drops
    body["stats"]["priority_dropped"] = priority_dropped;    // v3.9.7: eBPF events dropped by should_drop_by_priority (cheap drop, no JSON build)
    body["stats"]["network_status"]  = network_status;
    body["stats"]["ebpf_mode"]       = ebpf_mode;
    body["stats"]["ebpf_reason"]     = ebpf_reason;
    // Map ebpf_mode to ebpf_status for the backend AgentHeartbeatRequest schema
    if (!ebpf_mode.empty()) {
        if (ebpf_mode == "ringbuf" || ebpf_mode == "enabled" || ebpf_mode == "active" || ebpf_mode == "running") {
            body["ebpf_status"] = "enabled";
        } else if (ebpf_mode == "none" || ebpf_mode == "disabled" || ebpf_mode == "error" || ebpf_mode == "failed") {
            body["ebpf_status"] = "disabled";
        } else if (ebpf_mode == "unsupported" || ebpf_mode == "n/a") {
            body["ebpf_status"] = "unsupported";
        } else {
            body["ebpf_status"] = "pending";
        }
    }
    if (!ebpf_reason.empty()) {
        body["ebpf_reason"] = ebpf_reason;
    }
    // v3.21.0 / T66 (logsoc-web#15): report disk-encryption status so the
    // /compliance/suggestions endpoint can filter already-encrypted assets.
    // Only include if the caller provided a value (std::nullopt = no detection).
    if (encryption_at_rest.has_value()) {
        body["encryption_at_rest"] = *encryption_at_rest;
    }
    if (!encryption_detection_method.empty()) {
        body["encryption_detection_method"] = encryption_detection_method;
    }
    // T30.2: ringbuf loss / total events. Backend computes loss rate
    // (lost / total * 100) for dashboards and alerting.
    body["stats"]["ringbuf_lost_events"] = ringbuf_lost_events;
    body["stats"]["ringbuf_total_events"] = ringbuf_total_events;
    // T30.3: list of currently attached eBPF probe names. Backend
    // uses this to detect drift between desired and actual state
    // after a hot-reload.
    body["stats"]["enabled_probes"] = enabled_probes_list;
    // T12.10 (2026-06-16): rich metrics snapshot for the
    // dashboard. Replaces the to-be-removed /metrics HTTP server
    // (T12.10d). The backend exposes these under
    // /api/v1/agents/{id}/metrics in Prometheus format.
    // Schema: stats.metrics.<section>.<field> so the backend
    // can group by section without re-flattening.
    if (metrics.has_value()) {
        const auto& m = *metrics;
        auto& ms = body["stats"]["metrics"];
        // FIM pipeline (FdResolver + FimCollector)
        ms["fim"]["fd_resolved"]         = m.fd_resolved;
        ms["fim"]["fd_timeout"]          = m.fd_timeout;
        ms["fim"]["fd_eperm"]            = m.fd_eperm;
        ms["fim"]["fd_not_found"]        = m.fd_not_found;
        ms["fim"]["fd_cb_open"]          = m.fd_cb_open;
        ms["fim"]["fd_errors"]           = m.fd_errors;
        ms["fim"]["fd_dropped"]          = m.fd_dropped;
        ms["fim"]["fim_merged"]          = m.fim_merged;
        ms["fim"]["fim_dropped"]         = m.fim_dropped;
        ms["fim"]["fim_rate_limited"]    = m.fim_rate_limited;
        ms["fim"]["fim_watchdog_pings"]  = m.fim_watchdog_pings;
        ms["fim"]["fim_shipped"]         = m.fim_shipped;
        // NetworkCollector (pcap)
        ms["net"]["packets_captured"]    = m.net_packets_captured;
        ms["net"]["packets_dropped"]     = m.net_packets_dropped;
        ms["net"]["events_pushed"]       = m.net_events_pushed;
        ms["net"]["flush_errors"]        = m.net_flush_errors;
        // CircuitBreaker
        ms["fim"]["cb_trips"]            = m.cb_trips;
        // YARA content shipper
        ms["yara"]["shipped"]            = m.yara_shipped;
        ms["yara"]["dropped"]            = m.yara_dropped;
        ms["yara"]["failed"]             = m.yara_failed;
        ms["yara"]["skipped_size"]       = m.yara_skipped_size;
        ms["yara"]["skipped_unreadable"] = m.yara_skipped_unreadable;
        ms["yara"]["skipped_too_large"]  = m.yara_skipped_too_large;  // T12.16
        ms["yara"]["matched"]            = m.yara_matched;
        // YARA engine (rules loaded + scan/match counts)
        ms["yara"]["rules_loaded"]       = m.yara_rules_loaded;
        ms["yara"]["scans_total"]        = m.yara_scans_total;
        ms["yara"]["matches_total"]      = m.yara_matches_total;
    }
    // v4.9.0: send config_hash so the backend can detect if our local
    // config.json is stale. If we have a cached hash, send it; otherwise
    // we skip it (backend treats None as "agent doesn't support it yet").
    if (!config_hash.empty()) {
        body["config_hash"] = config_hash;
    }
    std::string body_str = body.dump();

    std::string ts = std::to_string(body["timestamp"].get<long long>());
    auto key_bytes = std::vector<uint8_t>(cred.hmac_secret.begin(), cred.hmac_secret.end());
    auto sig = hmac_sha256_str(ts + "." + sha256_hex(body_str), key_bytes);
    std::string sig_hex = hex_encode(sig);

    std::vector<std::string> hdrs = {
        "X-Agent-Id: "    + cred.agent_id,
        "X-Timestamp: "   + ts,
        "X-Signature: "   + sig_hex
    };
    std::string resp;
    http_code = 0;
    http_post(cred.central_url + "/api/v1/agents/heartbeat", body_str, hdrs, resp, http_code);
    return resp;
}

/* ── HMAC ingestion ── */

std::string compute_ingest_hmac(const Credentials& cred,
                                const std::string& timestamp,
                                const std::string& json_body,
                                const std::string& nonce) {
    std::string body_hash = sha256_hex(json_body);
    // T14.1 — H-06 prep: if nonce is provided, include it in the signed
    // payload. Format: f"{ts}.{nonce}.{body_hash}" instead of
    // f"{ts}.{body_hash}". Backward-compatible: if nonce is empty,
    // fall back to the original format (existing central versions
    // keep working — the X-Nonce header is sent but ignored).
    std::string sig_payload;
    if (!nonce.empty()) {
        sig_payload = timestamp + "." + nonce + "." + body_hash;
    } else {
        sig_payload = timestamp + "." + body_hash;
    }
    auto key_bytes = std::vector<uint8_t>(cred.hmac_secret.begin(), cred.hmac_secret.end());
    auto h = hmac_sha256_str(sig_payload, key_bytes);
    return hex_encode(h);
}

std::string compute_ingest_hmac(const std::string& /*agent_id*/,
                                const std::string& hmac_secret,
                                const std::string& /*central_url*/,
                                const std::string& timestamp,
                                const std::string& json_body,
                                const std::string& nonce) {
    std::string body_hash = sha256_hex(json_body);
    std::string sig_payload;
    if (!nonce.empty()) {
        sig_payload = timestamp + "." + nonce + "." + body_hash;
    } else {
        sig_payload = timestamp + "." + body_hash;
    }
    auto key_bytes = std::vector<uint8_t>(hmac_secret.begin(), hmac_secret.end());
    auto h = hmac_sha256_str(sig_payload, key_bytes);
    return hex_encode(h);
}

/* T64.2.2 (v3.20.0): HMAC for policy GET endpoint.
 * Backend message: f"{timestamp}.{agent_id}.{method}.{path}"
 * No body, no body-hash. Returns lowercase hex SHA-256. */
std::string compute_policy_get_hmac(const std::string& hmac_secret,
                                    const std::string& agent_id,
                                    const std::string& timestamp,
                                    const std::string& method,
                                    const std::string& path) {
    std::string message = timestamp + "." + agent_id + "." + method + "." + path;
    auto key_bytes = std::vector<uint8_t>(hmac_secret.begin(), hmac_secret.end());
    auto h = hmac_sha256_str(message, key_bytes);
    return hex_encode(h);
}

/* T9 fix (v3.12.2): HMAC for action-report POST.
 * Backend format: f"{timestamp}.{agent_id}.POST./api/v1/agents/{agent_id}/action-report"
 * No body, no body-hash. See logsoc-web/app/routers/agents.py::action_report
 * and _hmac.verify_agent_hmac — the message is f"{ts}.{agent_id}.{method}.{path}"
 * where path is the full URL path INCLUDING the /api/v1 prefix. */
std::string compute_action_report_hmac(const std::string& hmac_secret,
                                       const std::string& agent_id,
                                       const std::string& timestamp) {
    std::string path = "/api/v1/agents/" + agent_id + "/action-report";
    std::string message = timestamp + "." + agent_id + ".POST." + path;
    auto key_bytes = std::vector<uint8_t>(hmac_secret.begin(), hmac_secret.end());
    auto h = hmac_sha256_str(message, key_bytes);
    return hex_encode(h);
}

} // namespace agent_v3
