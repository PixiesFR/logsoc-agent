// fallback_wal.cpp — Fallback WAL for LogSOC Agent v3.8.0
//
// Writes encrypted events to disk ONLY when the downstream API is down.
// Binary format per record:
//   [4B magic][1B version][1B type][8B event_id_hash]
//   [4B iv_len][iv][4B tag_len][tag][4B payload_len][payload]
//
// Rotation: 5 MB per segment, max 5 segments, chmod 0600.
// Thread-safe (internal mutex). No fork/pipe/setuid.

#include "fallback_wal.hpp"
#include "crypto.hpp"
#include "debug.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <atomic>

namespace fallback_wal {

namespace fs = std::filesystem;
using namespace crypto;

// ── Binary helpers (little-endian) ──

static void write_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

static void write_u64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

static uint32_t read_u32(const uint8_t*& p, const uint8_t* end) {
    if (p + 4 > end) throw std::runtime_error("fallback_wal: unexpected EOF reading u32");
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    p += 4;
    return v;
}

static uint64_t read_u64(const uint8_t*& p, const uint8_t* end) {
    if (p + 8 > end) throw std::runtime_error("fallback_wal: unexpected EOF reading u64");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    p += 8;
    return v;
}

// FNV-1a 64-bit hash for fast dedup
uint64_t FallbackWAL::hash_event(const std::string& raw_event) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : raw_event) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

// ── Constructor ──

FallbackWAL::FallbackWAL(const std::string& data_dir,
                         const std::vector<uint8_t>& aes_key,
                         const std::string& agent_id)
    : data_dir_(data_dir), aes_key_(aes_key), agent_id_(agent_id)
{
    if (aes_key_.size() != 32) {
        throw std::runtime_error("FallbackWAL: aes_key must be 32 bytes");
    }
    fs::create_directories(data_dir_);
    // Ensure 0600 on directory
    chmod(data_dir_.c_str(), 0700);
    // Clean up any stale segments on startup
    enforce_max_segments();
}

// ── Push an event ──

bool FallbackWAL::push(const std::string& raw_event) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (raw_event.empty()) return true;  // skip empty

    maybe_rotate();

    // L-09: enforce 500MB WAL quota before writing
    enforce_quota();

    // Open a new segment if needed
    if (current_fd_ < 0) {
        if (!open_new_segment()) return false;
    }

    uint64_t eid_hash = hash_event(raw_event);
    std::vector<uint8_t> record;
    if (!encrypt_event(raw_event, eid_hash, record)) {
        LOG_ERROR("[FWAL] encrypt_event failed");
        return false;
    }

    // Write to current segment
    ssize_t written = ::write(current_fd_, record.data(), record.size());
    if (written != static_cast<ssize_t>(record.size())) {
        LOG_ERROR("[FWAL] write failed: " << strerror(errno));
        close_current_segment();
        return false;
    }
    ::fsync(current_fd_);
    current_segment_size_ += record.size();
    current_segment_records_++;

    return true;
}

// ── Pop batch of events ──

std::vector<FallbackEvent> FallbackWAL::pop_batch(size_t n) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Flush current segment so it can be read
    close_current_segment();

    auto segs = list_segments();
    if (segs.empty()) return {};

    // Read from the oldest segment. Load its tombstone set so already-
    // sent events are skipped at decrypt time (T12 fix #18).
    const std::string& seg_path = segs.front().string();
    const auto& tombstones = get_tombstones(seg_path);
    auto events = decrypt_segment(seg_path, &tombstones);
    if (events.empty()) {
        // Empty or corrupt segment, remove it. Also clean the tomb cache.
        try { fs::remove(seg_path); } catch (...) {}
        tomb_cache_.erase(seg_path);
        try { fs::remove(tombstone_path(seg_path)); } catch (...) {}
        return {};
    }

    // Return at most n events
    if (events.size() > n) {
        events.resize(n);
    }
    return events;
}

// ── Mark sent ──

void FallbackWAL::mark_sent(uint64_t event_id_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    close_current_segment();

    // T12 audit fix #18: previous implementation re-decrypted the whole
    // segment, removed the matching event, re-encrypted all remaining
    // events, deleted the old file, and wrote a new one. That's O(n)
    // per mark_sent, and pop_batch + mark_sent is called per-event in
    // the happy path → O(n²) for n events in the queue. A 1000-event
    // queue means 1M decrypt+encrypt ops on hot path, often 1-5s of
    // pure CPU inside the sender thread (starving the rest of the
    // pipeline).
    //
    // New strategy:
    //   1. Append the hash to a side-car file (O(1) write, 8 bytes).
    //      The side-car is one file per segment: <seg>.tomb.
    //   2. pop_batch() filters events against the side-car at decrypt
    //      time (O(1) lookup per record via an in-memory cache).
    //   3. Lazy cleanup: when pop_batch() decrypts a segment and finds
    //      it fully tombstoned, it deletes the segment + side-car
    //      IN PLACE OF returning an empty result. So the O(n) decrypt
    //      for cleanup is paid at most once per segment, not once per
    //      mark_sent. Total cost over the lifetime of a segment of
    //      n events: O(n) writes (mark_sent) + O(n) decrypts (final
    //      cleanup) = O(n), vs the previous O(n²).
    //
    // mark_sent itself is now: 1 O(1) cache lookup + 1 O(1) append
    // (8 bytes write + fsync). Constant time, regardless of segment
    // size. This is the key win.
    //
    // Trade-off: a segment stays on disk with tombstoned records
    // taking space until all events are marked sent. Bounded by
    // FWAL_MAX_SEGMENTS (5) × FWAL_MAX_SEGMENT_SIZE (5MB) = 25MB max.
    auto segs = list_segments();
    for (const auto& seg : segs) {
        std::string seg_str = seg.string();
        // Load (or get from cache) the tombstone set.
        const auto& tombstones = get_tombstones(seg_str);
        if (tombstones.count(event_id_hash) > 0) {
            // Already tombstoned, nothing to do.
            return;
        }

        // Append the tombstone. The append ALSO invalidates the cache
        // entry, but the next get_tombstones() (e.g. on next pop_batch)
        // will re-read from disk. We don't reload here to keep mark_sent
        // O(1).
        //
        // The hash may not actually be in this segment (event could be
        // in a later segment). The tombstone entry is then a harmless
        // dead entry (8 bytes wasted). Lazy cleanup at pop_batch will
        // reconcile this when the segment is fully consumed.
        append_tombstone(seg_str, event_id_hash);
        return;
    }
    // No segment files (empty WAL) — nothing to mark.
}

// ── Count ──

size_t FallbackWAL::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    auto segs = list_segments();
    for (const auto& seg : segs) {
        // Estimate from file size (rough)
        try {
            total += fs::file_size(seg) / 256;  // avg ~256 bytes per record
        } catch (...) {}
    }
    total += current_segment_records_;
    return total;
}

// ── Size on disk ──

size_t FallbackWAL::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = current_segment_size_;
    for (const auto& seg : list_segments()) {
        try { total += fs::file_size(seg); } catch (...) {}
    }
    return total;
}

// ── Cleanup old segments ──

void FallbackWAL::cleanup_old_segments(size_t max_age_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto segs = list_segments();
    for (const auto& seg : segs) {
        try {
            auto ftime = fs::last_write_time(seg);
            // M-03 audit fix: portable file_time_type → system_clock conversion.
            // C++17 does not define a direct conversion. Use duration arithmetic:
            // file_clock and system_clock both measure time since their respective
            // epochs. We compute the age as (file_time_type::clock::now() - ftime),
            // which is a duration, then compare that to max_age_sec.
            auto file_now = fs::file_time_type::clock::now();
            auto age_dur = std::chrono::duration_cast<std::chrono::seconds>(file_now - ftime);
            if (static_cast<size_t>(age_dur.count()) > max_age_sec) {
                fs::remove(seg);
                LOG_INFO("[FWAL] Cleaned up old segment: " << seg.filename().string());
            }
        } catch (const std::exception& e) {
            LOG_WARN("[FWAL] cleanup error: " << e.what());
        }
    }
}

// ── Private helpers ──

bool FallbackWAL::encrypt_event(const std::string& raw_event, uint64_t event_id_hash,
                                 std::vector<uint8_t>& out) {
    // Encrypt with AES-256-GCM
    std::vector<uint8_t> plaintext(raw_event.begin(), raw_event.end());
    auto enc = aes_gcm_encrypt(plaintext, aes_key_);

    // Serialize: [4B magic][1B version][1B type][8B event_id_hash]
    //            [4B iv_len][iv][4B tag_len][tag][4B payload_len][payload]
    out.clear();
    out.reserve(4 + 1 + 1 + 8 + 4 + enc.nonce.size() + 4 + enc.tag.size()
                + 4 + enc.ciphertext.size());

    write_u32(out, FWAL_MAGIC);
    out.push_back(FWAL_VERSION);
    out.push_back(FWAL_TYPE_EVENT);
    write_u64(out, event_id_hash);
    write_u32(out, static_cast<uint32_t>(enc.nonce.size()));
    out.insert(out.end(), enc.nonce.begin(), enc.nonce.end());
    write_u32(out, static_cast<uint32_t>(enc.tag.size()));
    out.insert(out.end(), enc.tag.begin(), enc.tag.end());
    write_u32(out, static_cast<uint32_t>(enc.ciphertext.size()));
    out.insert(out.end(), enc.ciphertext.begin(), enc.ciphertext.end());

    return true;
}

std::vector<FallbackEvent> FallbackWAL::decrypt_segment(const std::string& seg_path,
                                                       const std::unordered_set<uint64_t>* tombstones) {
    std::vector<FallbackEvent> events;

    std::ifstream f(seg_path, std::ios::binary | std::ios::ate);
    if (!f) return events;

    auto file_size = f.tellg();
    if (file_size <= 0) return events;
    f.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(static_cast<size_t>(file_size));
    f.read(reinterpret_cast<char*>(data.data()), data.size());
    if (!f) return events;

    const uint8_t* ptr = data.data();
    const uint8_t* end = ptr + data.size();

    while (ptr < end) {
        // Read and verify magic
        if (ptr + 4 > end) break;
        uint32_t magic = 0;
        for (int i = 0; i < 4; ++i) magic |= static_cast<uint32_t>(ptr[i]) << (8 * i);
        ptr += 4;
        if (magic != FWAL_MAGIC) break;

        // Read version and type
        if (ptr + 2 > end) break;
        uint8_t version = *ptr++;
        uint8_t type = *ptr++;
        (void)version; (void)type;

        // Read event_id_hash
        if (ptr + 8 > end) break;
        uint64_t eid_hash = read_u64(ptr, end);

        // Read IV (always, so we can advance ptr consistently)
        if (ptr + 4 > end) break;
        uint32_t iv_len = read_u32(ptr, end);
        if (ptr + iv_len > end) break;
        std::vector<uint8_t> iv(ptr, ptr + iv_len);
        ptr += iv_len;

        // Read tag
        if (ptr + 4 > end) break;
        uint32_t tag_len = read_u32(ptr, end);
        if (ptr + tag_len > end) break;
        std::vector<uint8_t> tag(ptr, ptr + tag_len);
        ptr += tag_len;

        // Read ciphertext
        if (ptr + 4 > end) break;
        uint32_t payload_len = read_u32(ptr, end);
        if (ptr + payload_len > end) break;
        std::vector<uint8_t> ciphertext(ptr, ptr + payload_len);
        ptr += payload_len;

        // T12 audit fix #18: skip tombstoned records (O(1) lookup in
        // the side-car cache). The record is still consumed off the
        // stream so the next magic aligns correctly.
        if (tombstones && tombstones->count(eid_hash) > 0) {
            continue;
        }

        // Decrypt
        try {
            auto plain = aes_gcm_decrypt(ciphertext, iv, tag, aes_key_);
            FallbackEvent ev;
            ev.event_id_hash = eid_hash;
            ev.raw_event = std::string(plain.begin(), plain.end());
            events.push_back(std::move(ev));
        } catch (const std::exception& e) {
            LOG_WARN("[FWAL] Decrypt failed in segment: " << e.what());
            break;  // corrupt segment, stop reading
        }
    }

    return events;
}

// ── Tombstone helpers (T12 fix #18) ──

const std::unordered_set<uint64_t>& FallbackWAL::get_tombstones(const std::string& seg_path) {
    // Returns a reference to the cached set. If the cache has an entry
    // but the file mtime changed (external write), re-read.
    auto it = tomb_cache_.find(seg_path);
    std::string tomb = tombstone_path(seg_path);

    if (it != tomb_cache_.end()) {
        try {
            if (fs::exists(tomb) && fs::last_write_time(tomb) == it->second.mtime) {
                return it->second.hashes;
            }
        } catch (...) {
            // fall through to re-read
        }
    }

    TombCache& cache = tomb_cache_[seg_path];
    cache.hashes.clear();
    try {
        if (fs::exists(tomb)) {
            cache.mtime = fs::last_write_time(tomb);
            std::ifstream f(tomb, std::ios::binary);
            if (f) {
                while (f) {
                    uint64_t h;
                    f.read(reinterpret_cast<char*>(&h), sizeof(h));
                    if (f.gcount() == sizeof(h)) {
                        cache.hashes.insert(h);
                    }
                }
            }
        } else {
            // No file = empty set. Use current time as mtime sentinel.
            cache.mtime = fs::file_time_type::clock::now();
        }
    } catch (const std::exception& e) {
        LOG_WARN("[FWAL] get_tombstones failed: " << e.what());
    }
    return cache.hashes;
}

bool FallbackWAL::append_tombstone(const std::string& seg_path, uint64_t event_id_hash) {
    std::string tomb = tombstone_path(seg_path);
    // Open in append mode, create if missing. fsync after each write —
    // tombstones are durable indicators that the event was sent, so a
    // crash before fsync would cause a duplicate send on restart. The
    // server dedupes by event_id_hash so it's not catastrophic, but
    // we prefer correctness.
    int fd = ::open(tomb.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        LOG_ERROR("[FWAL] append_tombstone open failed: " << strerror(errno));
        return false;
    }
    ssize_t w = ::write(fd, &event_id_hash, sizeof(event_id_hash));
    ::fsync(fd);
    ::close(fd);
    if (w != sizeof(event_id_hash)) {
        LOG_ERROR("[FWAL] append_tombstone write failed: " << strerror(errno));
        return false;
    }
    // Invalidate the cache so the next get_tombstones() re-reads.
    tomb_cache_.erase(seg_path);
    return true;
}

void FallbackWAL::maybe_rotate() {
    if (current_segment_size_ >= FWAL_MAX_SEGMENT_SIZE) {
        close_current_segment();
        enforce_max_segments();
    }
}

bool FallbackWAL::open_new_segment() {
    close_current_segment();  // close any open file

    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    static std::atomic<int> seq{0};
    std::string fname = "fwal_" + std::to_string(ms) + "_" + std::to_string(seq++) + ".fwal";
    fs::path seg_path = fs::path(data_dir_) / fname;

    int fd = ::open(seg_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        LOG_ERROR("[FWAL] Cannot create segment: " << seg_path.string() << " error: " << strerror(errno));
        return false;
    }
    chmod(seg_path.c_str(), 0600);

    current_fd_ = fd;
    current_segment_name_ = seg_path.string();
    current_segment_size_ = 0;
    current_segment_records_ = 0;

    LOG_VERBOSE("[FWAL] Opened new segment: " << fname);
    return true;
}

void FallbackWAL::close_current_segment() {
    if (current_fd_ >= 0) {
        ::fsync(current_fd_);
        ::close(current_fd_);
        current_fd_ = -1;
    }
}

std::vector<fs::path> FallbackWAL::list_segments() const {
    std::vector<fs::path> segs;
    if (!fs::exists(data_dir_)) return segs;
    for (const auto& entry : fs::directory_iterator(data_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".fwal") {
            segs.push_back(entry.path());
        }
    }
    std::sort(segs.begin(), segs.end());
    return segs;
}

void FallbackWAL::enforce_max_segments() {
    auto segs = list_segments();
    while (segs.size() >= FWAL_MAX_SEGMENTS) {
        try {
            fs::remove(segs.front());
            LOG_INFO("[FWAL] Removed oldest segment: " << segs.front().filename().string());
        } catch (const std::exception& e) {
            LOG_WARN("[FWAL] Cannot remove segment: " << e.what());
        }
        segs.erase(segs.begin());
    }
}

// L-09 audit fix: enforce a 500MB total WAL directory quota.
// If the total size of all segments exceeds the quota, purge
// oldest segments until under the limit. This prevents the WAL
// from filling the disk on prolonged API outages.
constexpr size_t FWAL_QUOTA_BYTES = 500ULL * 1024 * 1024;  // 500 MB

void FallbackWAL::enforce_quota() {
    // Already under mutex_ in push(), no need to lock again.
    auto segs = list_segments();
    size_t total = current_segment_size_;
    for (const auto& seg : segs) {
        try { total += fs::file_size(seg); } catch (...) {}
    }
    while (total > FWAL_QUOTA_BYTES && !segs.empty()) {
        try {
            size_t seg_size = 0;
            try { seg_size = fs::file_size(segs.front()); } catch (...) {}
            fs::remove(segs.front());
            LOG_INFO("[FWAL] Quota purge: removed segment " << segs.front().filename().string());
            total -= seg_size;
        } catch (const std::exception& e) {
            LOG_WARN("[FWAL] Quota purge failed: " << e.what());
            break;  // can't remove more, stop trying
        }
        // Also remove the tombstone side-car if it exists
        try { fs::remove(tombstone_path(segs.front().string())); } catch (...) {}
        tomb_cache_.erase(segs.front().string());
        segs.erase(segs.begin());
    }
}

} // namespace fallback_wal