// T12.10d — Agent command executor
//
// Generic command dispatcher for the backend → agent channel
// (POST /api/v1/agents/{id}/command). The agent picks up
// pending commands on its heartbeat, calls execute() here, and
// ships the result back via /command-result.
//
// Supported commands:
//   set_log_level(level=0..5 or 6 for reset)
//   reload_policy     (forces a re-pull of the central policy)
//   dump_fim_state    (logs the current FIM policy + watch paths)
//   rotate_wal        (closes and reopens the fallback WAL file)
//
// Each command has a hard 30s timeout (we never block the
// heartbeat forever). Unknown commands are rejected with
// status=error and a descriptive error_text.

#pragma once

#include <string>

namespace logsoc::agent::t12_10c {

struct CommandResult {
    // "done" or "error"
    std::string status;
    // For set_log_level: the new level. For dump_fim_state: the
    // JSON dump. For others: "" or a short message.
    std::string result_text;
    // Filled when status == "error". Empty otherwise.
    std::string error_text;
    // Time spent in execute() in milliseconds.
    int duration_ms = 0;
    // Pre-rendered JSON body for POST /command-result.
    // Format: {"id": <cmd_id>, "status": "done|error",
    //          "result_text": "...", "error_text": "..."}
    // cmd_id is filled in by the caller (agent.cpp heartbeat
    // handler), NOT here.
    std::string body_to_post;
};

// Execute a command. payload_json is the raw JSON string from
// the heartbeat's pending_commands[].payload field (always an
// object: "{}" if absent).
//
// NEVER throws. On parse errors, returns status="error" with a
// descriptive error_text.
CommandResult execute(const std::string& command,
                     const std::string& payload_json);

}  // namespace logsoc::agent::t12_10c
