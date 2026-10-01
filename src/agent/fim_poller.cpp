// fim_poller.cpp — T4.8.8 — FIM periodic poller (fallback for SSH root eBPF invisibility)
#include "fim_poller.hpp"
#include "fim_collector.hpp"

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

namespace logsoc::agent::fim {

FimPoller::FimPoller(const Config& cfg, FimCollector& collector)
    : cfg_(cfg), collector_(&collector) {
    if (cfg_.watch_paths.empty()) {
        std::cerr << "[FimPoller] disabled (no watch_paths)\n";
        return;
    }
    thread_ = std::thread(&FimPoller::run, this);
    std::cerr << "[FimPoller] started, watch_paths=" << cfg_.watch_paths.size()
              << " poll_interval=" << cfg_.poll_interval.count() << "s\n";
}

// T13.2a: callback mode. The callback is invoked synchronously on the
// poller thread for each detected change. The caller is responsible for
// non-blocking forwarding (e.g., a bounded queue + dedicated
// dispatcher thread that does the IPC send).
FimPoller::FimPoller(const Config& cfg, EventCallback cb)
    : cfg_(cfg), callback_(std::move(cb)) {
    if (cfg_.watch_paths.empty()) {
        std::cerr << "[FimPoller/cb] disabled (no watch_paths)\n";
        return;
    }
    thread_ = std::thread(&FimPoller::run, this);
    std::cerr << "[FimPoller/cb] started, watch_paths=" << cfg_.watch_paths.size()
              << " poll_interval=" << cfg_.poll_interval.count() << "s\n";
}

FimPoller::~FimPoller() {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
}

int FimPoller::poll_now() {
    int n = 0;
    for (const auto& path : cfg_.watch_paths) {
        check_path(path);
    }
    polls_.fetch_add(1, std::memory_order_relaxed);
    return n;
}

void FimPoller::run() {
    // First poll: just take a snapshot, don't publish events for the
    // initial state. We want to detect CHANGES from this point on.
    {
        std::lock_guard<std::mutex> lock(state_mtx_);
        for (const auto& path : cfg_.watch_paths) {
            std::string sha = compute_sha256(path);
            if (!sha.empty()) {
                last_sha_[path] = sha;
            }
        }
    }
    std::cerr << "[FimPoller] initial snapshot taken for "
              << last_sha_.size() << " paths\n";

    while (!stop_.load()) {
        for (const auto& path : cfg_.watch_paths) {
            check_path(path);
        }
        polls_.fetch_add(1, std::memory_order_relaxed);

        // Sleep in small slices so we can be killed quickly.
        auto remaining = cfg_.poll_interval;
        while (remaining.count() > 0 && !stop_.load()) {
            auto slice = std::min(std::chrono::seconds(1), remaining);
            std::this_thread::sleep_for(slice);
            remaining -= slice;
        }
    }
    std::cerr << "[FimPoller] stopped\n";
}

void FimPoller::check_path(const std::string& path) {
    // Stat first: detect deletion
    struct stat st;
    bool exists = (::stat(path.c_str(), &st) == 0);

    std::string current_sha;
    if (exists) {
        current_sha = compute_sha256(path);
    }

    std::lock_guard<std::mutex> lock(state_mtx_);
    auto it = last_sha_.find(path);
    if (it == last_sha_.end()) {
        // First time we see this path
        last_sha_[path] = current_sha;  // empty if doesn't exist
        return;  // don't publish on initial discovery
    }

    if (it->second != current_sha) {
        // Change detected
        FimEvent ev;
        ev.abs_path = path;
        ev.basename = path;
        ev.pid = 0;
        ev.ktime_ns = 0;
        std::snprintf(ev.operation, sizeof(ev.operation), "%s",
                      exists ? "write" : "delete");
        ev.resolution = "poller_fallback";
        collector_ ? collector_->publish_external(ev) : callback_(ev);
        changes_.fetch_add(1, std::memory_order_relaxed);
        std::cerr << "[FimPoller] change detected: " << path
                  << " sha=" << (current_sha.empty() ? "(gone)" : current_sha.substr(0, 12))
                  << "\n";
        it->second = current_sha;
    }
}

std::string FimPoller::compute_sha256(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    // OpenSSL 3.0 EVP API (SHA256_* is deprecated since 3.0)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    char buf[8192];
    // T12 audit fix #34: check EVP_DigestUpdate return. In practice
    // it only fails on OOM (which would have already crashed the
    // process), but defensive checks are cheap and help future
    // debugging. If the update fails mid-stream, the resulting hash
    // is wrong but the file is still considered "changed" (vs the
    // previous SHA) — false positive, not a security issue.
    while (f) {
        f.read(buf, sizeof(buf));
        std::streamsize got = f.gcount();
        if (got > 0 && EVP_DigestUpdate(ctx, buf, static_cast<size_t>(got)) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    // T12 audit fix #35: check EVP_DigestFinal_ex return. If it
    // fails, outlen may be 0 and out is uninitialized. Returning ""
    // signals "hash failed" to the caller, which treats the file
    // as changed and publishes a FIM event with no SHA — better
    // than publishing a bogus hash.
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < outlen; i++) {
        std::snprintf(hex + i * 2, 3, "%02x", out[i]);
    }
    return std::string(hex, outlen * 2);
}

}  // namespace logsoc::agent::fim
