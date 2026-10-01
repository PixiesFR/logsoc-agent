// T12.10d unit test — agent command executor
//
// Verifies:
//   - set_log_level: changes g_log_level and returns done
//   - bad payload: returns error with descriptive error_text
//   - unknown command: returns error
//   - missing payload object: returns error
//   - body_to_post is always valid JSON with status + duration_ms
#include "../src/agent/t12_10c_commands.hpp"
#include "../src/debug.hpp"   // g_log_level
#include "../src/json.hpp"
#include <cassert>
#include <cstdio>
#include <string>

using logsoc::agent::t12_10c::CommandResult;
using logsoc::agent::t12_10c::execute;
using nlohmann::json;

int main() {
    int passed = 0, failed = 0;
    auto check = [&](bool cond, const char* msg) {
        if (cond) { ++passed; printf("  ok: %s\n", msg); }
        else      { ++failed; printf("  FAIL: %s\n", msg); }
    };

    // ── 1. set_log_level valid ──
    {
        auto r = execute("set_log_level", R"({"level": 4})");
        check(r.status == "done", "set_log_level(level=4) → done");
        check(r.error_text.empty(), "set_log_level(level=4) → no error_text");
        check(r.result_text == "log_level=4", "set_log_level(level=4) → result_text=log_level=4");
        check(g_log_level.load() == 4, "g_log_level was updated to 4");
        check(!r.body_to_post.empty(), "body_to_post is populated");
        // body_to_post must be valid JSON
        bool parse_ok = false;
        try { (void)json::parse(r.body_to_post); parse_ok = true; } catch (...) {}
        check(parse_ok, "body_to_post is valid JSON");
    }

    // ── 2. set_log_level bad level ──
    {
        auto r = execute("set_log_level", R"({"level": 99})");
        check(r.status == "error", "set_log_level(level=99) → error");
        check(!r.error_text.empty(), "set_log_level(level=99) → error_text set");
        check(r.result_text.empty(), "set_log_level(level=99) → result_text empty");
    }

    // ── 3. set_log_level missing level ──
    {
        auto r = execute("set_log_level", R"({})");
        check(r.status == "error", "set_log_level({}) → error (missing level)");
        check(r.error_text.find("level") != std::string::npos,
              "error_text mentions 'level'");
    }

    // ── 4. unknown command ──
    {
        auto r = execute("set_color_purple", R"({"r": 255})");
        check(r.status == "error", "unknown command → error");
        check(r.error_text.find("unknown") != std::string::npos,
              "error_text mentions 'unknown'");
    }

    // ── 5. bad payload JSON ──
    {
        auto r = execute("set_log_level", "not-json");
        check(r.status == "error", "bad payload → error");
        check(r.error_text.find("bad payload") != std::string::npos,
              "error_text mentions 'bad payload'");
    }

    // ── 6. payload is array, not object ──
    {
        auto r = execute("set_log_level", R"([1,2,3])");
        check(r.status == "error", "non-object payload → error");
    }

    // ── 7. empty payload string ──
    {
        auto r = execute("reload_policy", "");
        check(r.status == "done", "empty payload on no-arg command → done");
    }

    // ── 8. reset log level (level=6) ──
    {
        auto r = execute("set_log_level", R"({"level": 6})");
        check(r.status == "done", "set_log_level(level=6=reset) → done");
    }

    // ── 9. body_to_post always has status ──
    {
        auto r = execute("nonexistent", "{}");
        check(r.body_to_post.find("\"status\"") != std::string::npos,
              "body_to_post contains status field even on error");
    }

    // ── 10. duration_ms is non-negative ──
    {
        auto r = execute("reload_policy", "{}");
        check(r.duration_ms >= 0, "duration_ms >= 0");
    }

    printf("\n=== t12_10c_commands tests: %d passed, %d failed ===\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
