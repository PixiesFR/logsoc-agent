// debug.hpp — Runtime logging for LogSOC Agent v3.11
// Supports stream-style (<<) syntax: LOG_INFO("val=" << x << " ok");
#pragma once
#include <atomic>
#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

// Log levels: 0=ERROR, 1=WARN, 2=INFO, 3=VERBOSE, 4=DEBUG, 5=TRACE
// v3.11: atomic for safe runtime mutation via hot-reload (SOC-AGENT#4).
//   Uses memory_order_relaxed for the read path in LOG_* macros — the value
//   is just a verbosity threshold, no ordering required.
inline std::atomic<int> g_log_level{2}; // Default: INFO and above

inline std::string log_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

// Stream-style LOG macros using ostringstream — supports << syntax
// Usage: LOG_INFO("value=" << x << " done");
// v3.11: g_log_level is atomic<int>; use .load(relaxed) for the threshold
//   check. operator>= is not defined on std::atomic<int>.
#define LOG_ERROR(msg) do { std::ostringstream _log_ss; _log_ss << msg; std::cerr << log_timestamp() << " [ERROR] " << _log_ss.str() << "\n"; } while(0)
#define LOG_WARN(msg)  do { std::ostringstream _log_ss; _log_ss << msg; std::cerr << log_timestamp() << " [WARN] "  << _log_ss.str() << "\n"; } while(0)
#define LOG_INFO(msg)  do { if (g_log_level.load(std::memory_order_relaxed) >= 2) { std::ostringstream _log_ss; _log_ss << msg; std::cerr << log_timestamp() << " [INFO] " << _log_ss.str() << "\n"; } } while(0)
#define LOG_VERBOSE(msg) do { if (g_log_level.load(std::memory_order_relaxed) >= 3) { std::ostringstream _log_ss; _log_ss << msg; std::cerr << log_timestamp() << " [VERBOSE] " << _log_ss.str() << "\n"; } } while(0)
#define LOG_DEBUG(msg) do { if (g_log_level.load(std::memory_order_relaxed) >= 4) { std::ostringstream _log_ss; _log_ss << msg; std::cerr << log_timestamp() << " [DEBUG] " << _log_ss.str() << "\n"; } } while(0)
#define LOG_TRACE(msg) do { if (g_log_level.load(std::memory_order_relaxed) >= 5) { std::ostringstream _log_ss; _log_ss << msg; std::cerr << log_timestamp() << " [TRACE] " << _log_ss.str() << "\n"; } } while(0)