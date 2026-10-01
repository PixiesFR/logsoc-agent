#pragma once
// runtime_credentials.hpp — LogSOC Agent v3.8.0
//
// Credentials live in RAM only. NO serialization to disk.
// At boot: load_from_server() via POST /api/v1/agents/{id}/activate
// Migration: load_from_legacy_auth_json() from v3.7 auth.json

#ifndef RUNTIME_CREDENTIALS_HPP
#define RUNTIME_CREDENTIALS_HPP

#include <string>
#include <vector>

namespace runtime_cred {

struct RuntimeCredentials {
    std::string agent_id;
    std::string token;
    std::string hmac_secret;
    std::string central_url;
    std::string wal_fallback_key;      // AES key for FallbackWAL (base64 or hex)
    std::string device_fingerprint;

    RuntimeCredentials() = default;

    // Load from server: POST /api/v1/agents/{id}/activate
    // Body: {"device_fingerprint": "<computed>"}
    // On success, fills all fields from server response.
    // out_http_code: if non-null, receives the HTTP status code on failure.
    bool load_from_server(const std::string& url, const std::string& id, long* out_http_code = nullptr);

    // Migration path: load from v3.7 auth.json file
    // Returns true if the file existed and was parsed successfully.
    bool load_from_legacy_auth_json(const std::string& path);

    // Best-effort zero-out of sensitive fields
    void clear();

    // Compute device fingerprint: SHA256(MAC + hostname + /etc/machine-id)
    static std::string compute_device_fingerprint();

    bool empty() const { return agent_id.empty() && token.empty(); }
};

// Save only the agent_id to a 0600 file (for re-auth at next boot)
bool save_agent_identity(const std::string& directory, const std::string& agent_id);

// Load agent_id from identity file (for re-auth at next boot)
bool load_agent_identity(const std::string& directory, std::string& agent_id);

// Delete the agent.identity file (used when admin revokes/deletes the agent)
bool delete_agent_identity(const std::string& directory);

} // namespace runtime_cred

#endif