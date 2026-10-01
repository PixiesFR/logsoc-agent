// runtime_credentials.cpp — LogSOC Agent v3.8.0
//
// Credentials in RAM only. No disk serialization of secrets.
// Boot flow: load agent_id from identity file → POST /activate → fill creds in RAM

#include "runtime_credentials.hpp"
#include "crypto.hpp"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <sys/stat.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>
#include <filesystem>

namespace runtime_cred {

namespace fs = std::filesystem;
using json = nlohmann::json;

static size_t string_write_cb(void* ptr, size_t sz, size_t n, void* ud) {
    auto* s = static_cast<std::string*>(ud);
    s->append((char*)ptr, sz * n);
    return sz * n;
}

static std::string get_mac_address() {
    struct ifaddrs* ifa_list = nullptr;
    if (getifaddrs(&ifa_list) != 0) return "00:00:00:00:00:00";

    std::string mac;
    for (auto* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_flags & IFF_LOOPBACK) continue;
        // Try to get MAC from interface name
        std::string path = "/sys/class/net/" + std::string(ifa->ifa_name) + "/address";
        std::ifstream f(path);
        if (f) {
            std::getline(f, mac);
            if (!mac.empty() && mac != "00:00:00:00:00:00") {
                // Remove trailing newline/carriage return
                while (!mac.empty() && (mac.back() == '\n' || mac.back() == '\r'))
                    mac.pop_back();
                if (mac != "00:00:00:00:00:00") break;
            }
            mac.clear();
        }
    }
    freeifaddrs(ifa_list);
    if (mac.empty()) mac = "00:00:00:00:00:00";
    return mac;
}

static std::string get_hostname() {
    char buf[256]{};
    gethostname(buf, sizeof(buf));
    return std::string(buf);
}

static std::string get_machine_id() {
    std::ifstream f("/etc/machine-id");
    if (!f) return "no-machine-id";
    std::string id;
    std::getline(f, id);
    // Trim
    while (!id.empty() && (id.back() == '\n' || id.back() == '\r'))
        id.pop_back();
    return id;
}

std::string RuntimeCredentials::compute_device_fingerprint() {
    std::string mac = get_mac_address();
    std::string hostname = get_hostname();
    std::string machine_id = get_machine_id();
    std::string input = mac + hostname + machine_id;
    return crypto::sha256_hex(input);
}

bool RuntimeCredentials::load_from_server(const std::string& url, const std::string& id, long* out_http_code) {
    // POST /api/v1/agents/{id}/activate
    // Body: {"device_fingerprint": "<computed>"}
    agent_id = id;
    device_fingerprint = compute_device_fingerprint();

    json req;
    req["device_fingerprint"] = device_fingerprint;

    std::string endpoint = url;
    // Normalize: strip trailing slash
    while (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();
    endpoint += "/api/v1/agents/" + id + "/activate";

    std::string resp;
    long http_code = 0;

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[AUTH] curl_easy_init failed\n";
        return false;
    }

    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    std::string body = req.dump();

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, string_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "[AUTH] activate POST failed: curl error\n";
        if (out_http_code) *out_http_code = 0;
        return false;
    }

    if (http_code != 200 && http_code != 201) {
        std::cerr << "[AUTH] activate POST failed: HTTP " << http_code
                  << " — " << resp << "\n";
        if (out_http_code) *out_http_code = http_code;
        return false;
    }

    try {
        json j = json::parse(resp);
        token = j.value("agent_token", std::string());
        hmac_secret = j.value("hmac_secret", std::string());
        wal_fallback_key = j.value("wal_fallback_key", std::string());
        central_url = j.value("central_url", url);
        // Trim trailing slash
        while (!central_url.empty() && central_url.back() == '/') central_url.pop_back();

        if (token.empty() || hmac_secret.empty()) {
            std::cerr << "[AUTH] activate response missing token/hmac_secret\n";
            return false;
        }
        std::cerr << "[AUTH] Re-activated agent " << agent_id << " via /activate\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] activate parse error: " << e.what() << "\n";
        return false;
    }
}

bool RuntimeCredentials::load_from_legacy_auth_json(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    try {
        json j;
        f >> j;
        agent_id     = j.value("agent_id", std::string());
        token        = j.value("agent_token", std::string());
        hmac_secret  = j.value("hmac_secret", std::string());
        wal_fallback_key = j.value("wal_secret", std::string());  // Use wal_secret as fallback key
        central_url  = j.value("central_url", std::string("https://logsoc.anytimeadmin.info"));
        while (!central_url.empty() && central_url.back() == '/') central_url.pop_back();

        device_fingerprint = compute_device_fingerprint();
        return !agent_id.empty() && !token.empty() && !hmac_secret.empty();
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] Legacy auth.json parse error: " << e.what() << "\n";
        return false;
    }
}

void RuntimeCredentials::clear() {
    // Best-effort zeroing of sensitive fields
    for (auto& c : token) c = '\0';
    for (auto& c : hmac_secret) c = '\0';
    for (auto& c : wal_fallback_key) c = '\0';
    token.clear();
    hmac_secret.clear();
    wal_fallback_key.clear();
    // Non-sensitive fields can just be cleared normally
    agent_id.clear();
    central_url.clear();
    device_fingerprint.clear();
}

bool save_agent_identity(const std::string& directory, const std::string& agent_id) {
    fs::create_directories(directory);
    std::string path = directory + "/agent.identity";
#ifdef __linux__
    mode_t old = umask(0077);
#endif
    std::ofstream f(path);
#ifdef __linux__
    umask(old);
#endif
    if (!f) return false;
    f << agent_id;
    f.flush();
    if (f.fail()) return false;
#ifdef __linux__
    chmod(path.c_str(), 0600);
#endif
    return true;
}

bool load_agent_identity(const std::string& directory, std::string& agent_id) {
    std::string path = directory + "/agent.identity";
    // T12.13 (audit Nova M-15): the identity file is what links this
    // agent's hostname to a server-side record. If a local attacker can
    // swap it for another agent's UUID, the central will mis-attribute
    // events. Refuse to load if the file is world-writable or owned by
    // someone other than us/root.
    #ifdef __linux__
    {
        struct stat st{};
        if (::stat(path.c_str(), &st) == 0) {
            if (st.st_uid != ::geteuid() && st.st_uid != 0) {
                std::fprintf(stderr,
                    "[runtime_cred] agent.identity %s owned by uid=%u (expected %u or 0) — refusing to load\n",
                    path.c_str(), (unsigned)st.st_uid, (unsigned)::geteuid());
                return false;
            }
            if ((st.st_mode & 022) != 0) {
                std::fprintf(stderr,
                    "[runtime_cred] agent.identity %s is group/other writable (mode=0%o) — refusing to load\n",
                    path.c_str(), (unsigned)(st.st_mode & 0777));
                return false;
            }
        }
    }
    #endif
    std::ifstream f(path);
    if (!f) return false;
    std::getline(f, agent_id);
    // Trim whitespace
    while (!agent_id.empty() && (agent_id.back() == '\n' || agent_id.back() == '\r' || agent_id.back() == ' '))
        agent_id.pop_back();
    return !agent_id.empty();
}

bool delete_agent_identity(const std::string& directory) {
    std::string path = directory + "/agent.identity";
    std::error_code ec;
    bool removed = std::filesystem::remove(path, ec);
    if (ec) {
        std::fprintf(stderr, "[runtime_cred] failed to delete %s: %s\n",
                     path.c_str(), ec.message().c_str());
        return false;
    }
    if (removed) {
        std::fprintf(stderr, "[runtime_cred] deleted %s (agent revoked/deleted by admin)\n",
                     path.c_str());
    }
    return true;
}

} // namespace runtime_cred