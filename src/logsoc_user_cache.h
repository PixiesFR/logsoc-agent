// logsoc_user_cache.h — T13.5 noise fix, 2026-06-17.
//
// Shared header for wal_writer_process, fim_scanner_process, and
// action_recommender_process. All three call getpwnam("logsoc") /
// getgrnam("logsoc") inside child_entry(), which is called once per
// privilege-separated fork. On hosts where NSS uses systemd-userdb
// (Ubuntu 22.04+ with DynamicUser support), every getpwnam opens the
// abstract socket /run/systemd/userdb/io.systemd.DynamicUser. Under
// AppArmor enforce, that abstract socket is unmachable (kernel
// returns "disconnected path" before any rule can match), so we
// see ~6 DENIED per second in dmesg.
//
// The fix: cache the getpwnam/getgrnam results by name. Since the
// agent only ever resolves a small fixed set of usernames (typically
// just "logsoc"), the cache grows to 1 entry and is hit on every
// fork after the first one.
//
// Thread-safety: the agent is multi-threaded (multiple eBPF / FIM
// threads can fork privilege-separated children concurrently). The
// cache uses a mutex.

#pragma once
#include <pwd.h>
#include <grp.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <utility>

namespace logsoc {

struct UserGroup {
    uid_t uid = 0;
    gid_t gid = 0;
    bool valid = false;
};

// Resolve a (user, group) pair by name, with caching. Both names are
// typically fixed strings ("logsoc", "logsoc") so the cache is
// effectively a single-entry hot path.
//
// Returns UserGroup{uid=0, gid=0, valid=false} if either lookup
// fails. Callers should check `valid` before using the result.
inline UserGroup resolve_user_group(const std::string& user,
                                    const std::string& group) {
    // Cache key is (user, group) — typically the same string twice.
    static std::unordered_map<std::string, UserGroup> cache;
    static std::mutex cache_mtx;

    const std::string key = user + ":" + group;
    {
        std::lock_guard<std::mutex> lock(cache_mtx);
        auto it = cache.find(key);
        if (it != cache.end()) return it->second;
    }

    UserGroup ug;
    // Use getpwnam_r for thread safety. 4096-byte buffer; retry on
    // ERANGE with 16384 bytes (matches src/ebpf/loader.cpp:196).
    struct passwd pwd;
    struct passwd* pw_result = nullptr;
    char pw_buf[4096];
    int rc = ::getpwnam_r(user.c_str(), &pwd, pw_buf, sizeof(pw_buf),
                          &pw_result);
    if (rc == ERANGE) {
        std::vector<char> pw_big(16384);
        rc = ::getpwnam_r(user.c_str(), &pwd, pw_big.data(),
                          pw_big.size(), &pw_result);
    }
    if (rc != 0 || !pw_result) {
        // Leave ug.valid = false; cache the failure too so we don't
        // re-spam NSS on every fork.
        std::lock_guard<std::mutex> lock(cache_mtx);
        cache[key] = ug;
        return ug;
    }
    ug.uid = pw_result->pw_uid;
    ug.gid = pw_result->pw_gid;
    ug.valid = true;

    // Override gid if a separate group name was provided.
    if (!group.empty() && group != user) {
        struct group grp;
        struct group* gr_result = nullptr;
        char gr_buf[4096];
        int grc = ::getgrnam_r(group.c_str(), &grp, gr_buf,
                               sizeof(gr_buf), &gr_result);
        if (grc == ERANGE) {
            std::vector<char> gr_big(16384);
            grc = ::getgrnam_r(group.c_str(), &grp, gr_big.data(),
                               gr_big.size(), &gr_result);
        }
        if (grc == 0 && gr_result) {
            ug.gid = gr_result->gr_gid;
        }
    }

    std::lock_guard<std::mutex> lock(cache_mtx);
    cache[key] = ug;
    return ug;
}

} // namespace logsoc
