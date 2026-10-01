#pragma once
// fallback_wal.hpp — Fallback WAL for LogSOC Agent v3.8.0
//
// Writes encrypted events to disk ONLY when the downstream API is down.
// Binary format per record:
//   [4B magic][1B version][1B type][8B event_id_hash][4B iv_len][iv][4B tag_len][tag][4B payload_len][payload]
//
// Rotation: 5 MB per segment, max 5 segments, chmod 0600.
// Thread-safe (internal mutex). No fork/pipe/setuid.

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>
#include <filesystem>
#include <unordered_set>
#include <unordered_map>

namespace fallback_wal {

constexpr uint32_t FWAL_MAGIC   = 0x4657414C;  // "FWAL"
constexpr uint8_t  FWAL_VERSION = 2;
constexpr uint8_t  FWAL_TYPE_EVENT = 1;
constexpr size_t   FWAL_MAX_SEGMENT_SIZE = 5 * 1024 * 1024;  // 5 MB
constexpr size_t   FWAL_MAX_SEGMENTS     = 5;

struct FallbackEvent {
    uint64_t event_id_hash;          // hash of raw event for dedup/mark_sent
    std::string raw_event;           // plaintext event (decrypted on read)
};

class FallbackWAL {
public:
    // aes_key must be 32 bytes (AES-256-GCM)
    FallbackWAL(const std::string& data_dir,
                const std::vector<uint8_t>& aes_key,
                const std::string& agent_id);

    // Push a raw event for later sending. Encrypts and writes to current segment.
    // Returns true on success.
    bool push(const std::string& raw_event);

    // Pop up to n events from the oldest segment. Returns decrypted events.
    std::vector<FallbackEvent> pop_batch(size_t n);

    // Mark an event as sent by its event_id_hash. If the segment becomes empty
    // after all its events are marked, it is deleted.
    void mark_sent(uint64_t event_id_hash);

    // Number of events across all segments (approximate).
    size_t count() const;

    // Total bytes on disk (all segments).
    size_t size() const;

    // Remove segments older than max_age_sec.
    void cleanup_old_segments(size_t max_age_sec);

    // Health check: always returns true (no child process to monitor).
    bool is_alive() const { return true; }

private:
    std::string data_dir_;
    std::vector<uint8_t> aes_key_;
    std::string agent_id_;
    mutable std::mutex mutex_;

    // Current open segment file descriptor
    int current_fd_ = -1;
    std::string current_segment_name_;
    size_t current_segment_size_ = 0;
    size_t current_segment_records_ = 0;

    // Helper: encrypt an event using AES-256-GCM
    bool encrypt_event(const std::string& raw_event, uint64_t event_id_hash,
                       std::vector<uint8_t>& out);

    // Helper: decrypt records from a segment file
    // T12 audit fix #18: optional tombstone set — hashes present here are
    // skipped on read. The set is built once per segment by load_tombstones()
    // and cached for the lifetime of the process (cleared on segment removal
    // by mark_sent). Cost: O(1) lookup per record, vs the previous O(n²)
    // rewrite-the-whole-segment strategy.
    std::vector<FallbackEvent> decrypt_segment(const std::string& seg_path,
                                               const std::unordered_set<uint64_t>* tombstones = nullptr);

    // Helper: load the tombstone side-car for a segment into a cache.
    // Side-car format: fwal_<ts>_<seq>.tomb, one 8-byte little-endian
    // hash per line, append-only. The file may not exist (no tombstones
    // yet) — that returns an empty set. fs::last_write_time is used to
    // invalidate the cache if the file changes (shouldn't happen in
    // normal flow but defends against external writes).
    const std::unordered_set<uint64_t>& get_tombstones(const std::string& seg_path);

    // Helper: append a hash to a segment's tombstone side-car.
    // Returns true on success.
    bool append_tombstone(const std::string& seg_path, uint64_t event_id_hash);

    // Helper: get side-car path for a segment file
    std::string tombstone_path(const std::string& seg_path) const {
        return seg_path + ".tomb";
    }

    // Tombstone cache: seg_path -> {set of hashes, last mtime}
    struct TombCache {
        std::unordered_set<uint64_t> hashes;
        std::filesystem::file_time_type mtime;
    };
    std::unordered_map<std::string, TombCache> tomb_cache_;

    // Helper: rotate to a new segment if current is full
    void maybe_rotate();

    // Helper: open a new segment file
    bool open_new_segment();

    // Helper: close current segment
    void close_current_segment();

    // Helper: list segment files sorted by name (oldest first)
    std::vector<std::filesystem::path> list_segments() const;

    // Helper: enforce max segments (delete oldest)
    void enforce_max_segments();

    // L-09 audit fix: enforce a 500MB total WAL directory quota.
    // If exceeded, purge oldest segments until under the limit.
    // Uses std::filesystem::space() for available disk check and
    // sums segment sizes for quota enforcement.
    void enforce_quota();

    // Compute a hash for event dedup
    static uint64_t hash_event(const std::string& raw_event);
};

} // namespace fallback_wal