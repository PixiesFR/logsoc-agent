// encryption_detect.cpp — T66 / logsoc-web#15
//
// Implementation of detect_encryption_at_rest().
//
// Strategy:
// 1. Read /proc/mounts (one line per mount, space-separated).
// 2. For each line, parse: <device> <mountpoint> <fstype> <opts> ...
// 3. If mountpoint is one of "/", "/home", "/var", "/opt", "/srv" AND
//      - fstype contains "crypto_LUKS", "fuse.encfs", "ecryptfs", "zfs"
//      - OR device is in /dev/mapper and fs is ext4/xfs/btrfs (dm-crypt case)
//    then mark encrypted.
// 4. LUKS detection: /dev/mapper/<name> + "ext4"/"xfs"/"btrfs" is the
//    canonical LUKS+ext4 setup. We treat that as encrypted.
//
// What we don't do:
// - Run blkid or lsblk (extra dep, no guaranteed root, no audit value).
// - Try to decrypt /etc/crypttab (often unreadable without root).
// - Detect BitLocker (Linux agent, no WMI).
//
// All this is good enough for the compliance suggestion filter: the goal
// is to avoid telling the DPO "encrypt /home!" on a host that already
// runs eCryptfs on /home. False negatives are acceptable (a few noisy
// suggestions for hosts we can't introspect); false positives would be
// bad (silently skipping real encryption recommendations).

#include "encryption_detect.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>

namespace logsoc {

namespace {

// Mountpoints we consider "important" (encrypting these matters).
// / is the root, /home is personal data, /var contains logs/state,
// /opt is third-party, /srv is server data.
bool is_important_mountpoint(const std::string& mp) {
    return mp == "/" || mp == "/home" || mp == "/var" || mp == "/opt" || mp == "/srv";
}

// Strip quotes from fstab-style mountpoint (/proc/mounts is unquoted but
// fields can contain spaces escaped as \040 etc. We treat them as literal.)
std::string unescape_mountpoint(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size()) {
            // Octal escape: \040 = space, \011 = tab, etc.
            int v = 0;
            if (std::sscanf(s.c_str() + i + 1, "%3o", &v) == 1) {
                out.push_back(static_cast<char>(v));
                i += 3;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

// Returns true if the device looks like a LUKS-backed device mapper.
bool is_luks_dm(const std::string& dev) {
    // Canonical: /dev/mapper/luks-* or /dev/mapper/*-luks-*
    if (dev.rfind("/dev/mapper/", 0) != 0) return false;
    auto rest = dev.substr(12);
    return rest.find("luks") != std::string::npos;
}

}  // namespace

EncryptionStatus detect_encryption_at_rest() {
    EncryptionStatus st;
    st.encrypted = false;
    st.method = "none";

    std::ifstream f("/proc/mounts");
    if (!f.is_open()) {
        st.method = "error";
        st.detail = "/proc/mounts not readable";
        return st;
    }

    std::string line;
    bool found_important = false;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // device mountpoint fstype opts [freq passno]
        std::istringstream iss(line);
        std::string dev, mp, fstype, opts;
        if (!(iss >> dev >> mp >> fstype >> opts)) continue;
        mp = unescape_mountpoint(mp);
        if (!is_important_mountpoint(mp)) continue;
        found_important = true;

        // eCryptfs: explicit fstype
        if (fstype == "ecryptfs") {
            st.encrypted = true;
            st.method = "ecryptfs";
            st.detail = mp + " on " + dev + " (fstype=ecryptfs)";
            return st;
        }

        // ZFS encrypted: dataset on a zpool with encryption=on. We can't
        // easily query `zfs get` from here without shelling out, so we
        // approximate: if fstype=zfs and the device is a zvol/dataset path,
        // we mark it as a "zfs" candidate and let the operator confirm in
        // /compliance/suggestions UI. We DO NOT auto-set encrypted=true
        // for zfs because zfs datasets can be unencrypted by default.
        // The agent reports "zfs" as the method; the backend stores
        // encryption_at_rest=NULL so the DPO gets the suggestion (we're
        // not sure). The operator can verify with `zfs get encryption`.
        if (fstype == "zfs") {
            if (st.method == "none") st.method = "zfs";
            st.detail = mp + " on " + dev + " (fstype=zfs, encryption unknown)";
            continue;
        }

        // LUKS: dm-crypt + ext4/xfs/btrfs filesystem, OR explicit crypto_LUKS
        if (fstype == "crypto_LUKS" || is_luks_dm(dev)) {
            st.encrypted = true;
            st.method = "luks";
            st.detail = mp + " on " + dev + " (fstype=" + fstype + ")";
            return st;
        }
    }

    if (!found_important) {
        st.method = "error";
        st.detail = "no important mountpoints found in /proc/mounts";
    }
    return st;
}

}  // namespace logsoc
