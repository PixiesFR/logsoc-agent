// yara_shipper.cpp — T58 v3.14.0
//
// Implementation of YaraShipper::ship_one (HTTP POST to central /yara/scan).
// Uses libcurl (already linked into soc_agent).
//
// T12.16 (audit Nova C-05): the HTTP /metrics server that previously
// lived in this file has been REMOVED. Metrics are now pushed in the
// heartbeat payload (see hb_metrics fields populated in agent.cpp).
// FimMetricsServer was already gone since T12.11.

#include "yara_shipper.hpp"
#include <curl/curl.h>
#include <zlib.h>  // T4.8.25: in-process gzip compression
#include "json.hpp"
#include <openssl/sha.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

namespace logsoc::agent::yara {

using json = nlohmann::json;

namespace {

// libcurl write callback: append to a std::string.
size_t curl_write_to_string(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

// Base64-encode bytes (used to send file content + SHA256 to central).
std::string base64_encode(const std::vector<uint8_t>& data) {
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t triple = (uint32_t)data[i] << 16;
        if (i + 1 < data.size()) triple |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < data.size()) triple |= (uint32_t)data[i + 2];
        out.push_back(kAlphabet[(triple >> 18) & 0x3f]);
        out.push_back(kAlphabet[(triple >> 12) & 0x3f]);
        out.push_back(i + 1 < data.size() ? kAlphabet[(triple >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < data.size() ? kAlphabet[triple & 0x3f] : '=');
    }
    return out;
}

// SHA256 hex of bytes.
std::string sha256_hex(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        // T12.13 (audit Nova H-04): use snprintf for defense-in-depth.
        // Buffer math: sizeof(hex) - (i*2) shrinks the bound each iter
        // so we never write past the end even if SHA256_DIGEST_LENGTH
        // ever changed. snprintf is harmless here vs sprintf (size is
        // always 2 + null) but matches the project's coding standard.
        std::snprintf(hex + i * 2, sizeof(hex) - static_cast<size_t>(i * 2), "%02x", hash[i]);
    }
    return std::string(hex, SHA256_DIGEST_LENGTH * 2);
}

// Gzip-compress in-process via zlib (T4.8.25).
//
// Previous implementation forked `gzip -c -9` per ship. At 1000 ships/min
// that's 1000 fork/exec per minute = ~1% CPU on a single core, plus
// process creation latency per ship. Replaced with a direct zlib
// deflate() call which costs ~10µs per MB of input. The compressed output
// is fully gzip-compatible (zlib with windowBits=15+16 emits a proper
// gzip header/trailer so the backend can decompress with stdlib gzip).
//
// Fallback: if zlib fails for any reason (extremely unlikely, OOM only),
// we return the original data uncompressed. The HTTP layer will still
// ship it, just without the "is_gzipped" flag.
std::vector<uint8_t> gzip_compress(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;

    z_stream strm{};
    // windowBits = 15 + 16 = gzip format (RFC 1952). Without the +16,
    // zlib would emit a zlib wrapper (RFC 1950) that gzip can't read.
    if (deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return data;
    }

    std::vector<uint8_t> out;
    out.reserve(data.size() / 3 + 1024);  // typical gzip ratio ~30%

    strm.next_in  = const_cast<Bytef*>(data.data());
    strm.avail_in = static_cast<uInt>(data.size());

    int ret = Z_OK;
    while (ret == Z_OK) {
        // Grow output if needed. Chunk size of 64KB keeps reallocs low.
        size_t old_size = out.size();
        out.resize(old_size + 64 * 1024);
        strm.next_out  = out.data() + old_size;
        strm.avail_out = static_cast<uInt>(out.size() - old_size);
        ret = deflate(&strm, Z_FINISH);
        out.resize(strm.total_out);  // shrink to actual bytes written
    }

    deflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        // Compression failed mid-stream; return raw data so we still ship.
        return data;
    }
    return out;
}

}  // namespace


void YaraShipper::ship_one(PendingScan job) {
    if (cfg_.endpoint.empty() || cfg_.auth_token.empty()) {
        LOG_DEBUG("[YaraShipper] no endpoint/token configured, skipping ship");
        return;
    }

    // v3.16 (T60a): read the file content on the ship thread (NOT in
    // the FIM event loop). If the file was modified between the FIM
    // event and now, or the path is no longer readable (deleted,
    // permissions changed), we skip with skipped_unreadable++.
    {
        // T12.14 (audit Nova H-07): cap the file size we are willing
        // to read into memory BEFORE opening the file, based on the
        // file_size captured at FIM-event time. Without this guard,
        // a 4MB file (current FIM scan cap) times N concurrent
        // pending events = unbounded memory growth. 8MB hard cap is
        // generous for YARA matching + gzip + base64 + JSON envelope.
        constexpr size_t MAX_SHIP_FILE_SIZE = 8ULL * 1024 * 1024;
        if (job.file_size > MAX_SHIP_FILE_SIZE) {
            stats_.skipped_too_large++;
            return;
        }
        std::ifstream f(job.path, std::ios::binary);
        if (!f) {
            stats_.skipped_unreadable++;
            return;
        }
        job.content.assign(std::istreambuf_iterator<char>(f),
                           std::istreambuf_iterator<char>());
        if (job.content.size() != job.file_size) {
            // File was modified between event and read (race). Skip.
            stats_.skipped_unreadable++;
            return;
        }
    }

    // 1. Compute SHA256 of original content
    std::string sha = sha256_hex(job.content);

    // 2. Optionally gzip
    bool is_gzipped = false;
    std::vector<uint8_t> payload = job.content;
    if (job.content.size() >= cfg_.gzip_threshold) {
        auto gz = gzip_compress(job.content);
        if (gz.size() < job.content.size()) {
            payload = std::move(gz);
            is_gzipped = true;
        }
    }

    // 3. Build JSON body
    json body = {
        {"agent_id", cfg_.agent_id},
        {"file_path", job.path},
        {"file_inode", job.inode},
        {"file_size", job.file_size},
        {"content_b64", base64_encode(payload)},
        {"is_gzipped", is_gzipped},
        {"heuristic_score", job.heuristic},
        {"file_sha256", sha},
    };
    std::string body_str = body.dump();

    // 4. Compute HMAC signature (header X-Logsoc-Signature)
    // The auth_token is the agent_token; HMAC-SHA256 over body with token as key.
    // Note: central may use a different scheme (HMAC over timestamp+body, etc).
    // For T58 MVP, we just send the body + Authorization Bearer.
    //
    // T12 audit fix #28: the previous code was missing a closing quote
    // on the auth_header string literal:
    //   std::string auth_header = "Authorization: Bearer *** + cfg_.auth_token;
    // Without the closing ", the string literal extended all the way to
    // the next " in the file (~400 bytes of C++ source code, including
    // semicolons and braces), and cfg_.auth_token was never appended.
    // The code happened to compile because the parser kept scanning for
    // a closing quote and never hit a syntax error before the next ".
    //
    // Result: the Authorization header sent to central was a multi-line
    // C++ source blob, NOT the actual bearer token. The backend rejected
    // these requests as 401 (token mismatch). This was never observed
    // because yara_ship_content is OFF by default on Hestia
    // (not in the config) — the YaraShipper is never instantiated.
    // If anyone toggles yara_ship_content: true, the ship silently
    // fails auth.
    //
    // Fix: properly close the string literal + concatenate the token.
    std::string auth_header = "Authorization: Bearer " + cfg_.auth_token;

    // 5. POST via libcurl
    CURL* curl = curl_easy_init();
    if (!curl) {
        stats_.failed++;
        return;
    }
    std::string response;
    long http_code = 0;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header.c_str());
    headers = curl_slist_append(headers, "X-Logsoc-Agent: soc-agent/3.14");

    curl_easy_setopt(curl, CURLOPT_URL, cfg_.endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_str.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);  // T4.8.22: don't hang on a dead central
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    // T4.8.22 SECURITY: enable SSL verification by default. The previous
    // code disabled peer+host verification which made ship content
    // vulnerable to MITM (any attacker on the network could intercept
    // the base64-encoded file payload). We use the libcurl default CA
    // bundle (CURLOPT_CAINFO not set → libcurl uses system default at
    // /etc/ssl/certs/ca-certificates.crt on Debian/Ubuntu).
    //
    // For dev/test environments with a self-signed central, operators
    // can override via config (future: cfg.tls_insecure_skip_verify
    // boolean, defaults to false). The previous behavior of "always
    // insecure" was a security regression for a SOC product.
    if (cfg_.tls_insecure_skip_verify) {
        LOG_WARN("[YaraShipper] TLS verification DISABLED via config — INSECURE");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        LOG_WARN("[YaraShipper] ship failed: curl=" << curl_easy_strerror(rc)
                 << " path=" << job.path);
        stats_.failed++;
        return;
    }

    if (http_code < 200 || http_code >= 300) {
        LOG_WARN("[YaraShipper] ship HTTP " << http_code
                 << " path=" << job.path << " body=" << response.substr(0, 200));
        stats_.failed++;
        return;
    }

    // 6. Parse response, update matched counter
    try {
        auto resp = json::parse(response);
        if (resp.contains("match_count") && resp["match_count"].get<int>() > 0) {
            stats_.matched++;
            LOG_INFO("[YaraShipper] MATCH path=" << job.path
                     << " count=" << resp["match_count"]);
        }
    } catch (...) {
        // ignore parse errors
    }

    stats_.shipped++;
    // Rate limit (soft)
    std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.min_interval_ms));
}

// ── T12.16 (audit Nova C-05): MetricsServer REMOVED ────────────────
//
// The standalone HTTP server that exposed /metrics and / on a TCP port
// has been deleted. Two reasons:
//   1. The same metrics are ALREADY pushed in the heartbeat payload
//      (T12.10: yara_shipped / yara_dropped / yara_failed / etc. are
//      populated in hb_metrics and sent every heartbeat interval).
//      The HTTP server was purely redundant.
//   2. Even with bind allowlist (loopback + RFC1918 + link-local),
//      any TCP listener on an EDR/SIEM agent is an attack surface
//      that the agent doesn't need. The central scrapes via the
//      heartbeat (HTTPS) — no inbound port required.
//
// The metrics_port and metrics_bind_address fields of ShipperConfig
// are removed too. Configs that still carry them are silently
// ignored (the JSON keys just don't bind to anything anymore).
// FimMetricsServer was already removed in T12.11 — this commit
// finishes the cleanup.


void YaraShipper::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;  // already running
    }
    ship_thread_ = std::thread([this]() { this->ship_loop(); });
    // T12.16: HTTP metrics server removed (audit Nova C-05). Metrics
    // are now pushed in the heartbeat payload (see hb_metrics fields
    // in agent.cpp).
    LOG_INFO("[YaraShipper] started (endpoint=" << cfg_.endpoint
             << " agent_id=" << cfg_.agent_id
             << " max_queue=" << cfg_.max_queue_size
             << " threshold=" << cfg_.heuristic_threshold << ")");
}

void YaraShipper::stop() {
    if (!running_.exchange(false)) return;
    cv_.notify_all();
    if (ship_thread_.joinable()) ship_thread_.join();
    // T12.16: no metrics server to stop.
    LOG_INFO("[YaraShipper] stopped (shipped=" << stats_.shipped.load()
             << " dropped=" << stats_.dropped.load()
             << " failed=" << stats_.failed.load() << ")");
}

}  // namespace logsoc::agent::yara
