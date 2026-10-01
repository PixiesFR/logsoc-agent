// encryption_detect.hpp — T66 / logsoc-web#15
//
// Detects whether the local filesystem is encrypted at rest by inspecting
// /proc/mounts and (when available) the output of `lsblk`.
//
// Detected mechanisms:
//   - LUKS (dm-crypt): /dev/mapper/* with TYPE=crypto_LUKS
//   - eCryptfs:        filesystem type ecryptfs mounted on / or /home
//   - ZFS encrypted:   zfs dataset with keylocation=file:// or prompt (heuristic)
//   - TrueCrypt/VeraCrypt: TYPE=vfat + hint in /dev/mapper/disks/by-label
//   - BitLocker:       not detectable without WMI (Linux-only stub)
//
// We intentionally avoid shelling out to blkid/lsblk by default — that needs
// root and a long PATH scan. /proc/mounts is enough for the common cases
// (LUKS-mounted root, eCryptfs home, etc.).
//
// Cost: 1 read of /proc/mounts, O(mounts) string scan. Negligible.

#pragma once

#include <string>
#include <utility>

namespace logsoc {

struct EncryptionStatus {
    // True if any "important" mount (root, /home, /var, /opt) is on an
    // encrypted device. False if we positively confirmed it is NOT.
    // nullopt if detection failed (insufficient privileges, unsupported
    // setup, etc.) — backend will keep the previous value.
    bool encrypted = false;
    std::string method;   // "luks", "ecryptfs", "zfs", "veracrypt", "none", "error"
    std::string detail;   // free-form detail (e.g. "root on /dev/mapper/luks-...")
};

// Inspect /proc/mounts. Cheap. Returns EncryptionStatus.
// On error (no /proc, read failure): method="error", encrypted=false.
EncryptionStatus detect_encryption_at_rest();

}  // namespace logsoc
