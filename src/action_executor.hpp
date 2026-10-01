/* action_executor.hpp — T28 defensive action executor.
 *
 * The agent is a pure sensor. It NEVER decides to act on its own.
 * Every defensive action (kill, block_ip, quarantine, rmmod, fim_add)
 * arrives via the heartbeat response and is dispatched here.
 *
 * If the action has dry_run=true, the executor LOGS what it WOULD do
 * and returns a "dry_run" status. The backend records the result in
 * the action_executed event and the operator can review the
 * would-be-impact before approving for real.
 *
 * If dry_run=false, the executor performs the action and reports
 * success/failure.
 *
 * T12.12: NO action site spawns a shell anymore. Every action is a
 * direct syscall, a libmnl netlink call, or a fanotify_mark(2) on
 * the shared collector fd. This removes a class of injection bugs
 * and a /bin/sh dependency.
 */
#pragma once
#include <string>
#include <vector>

namespace logsoc::agent::t28 {

struct ActionResult {
    std::string status;          // "succeeded" | "failed" | "cancelled"
    std::string result_message;  // human-readable
    std::string stdout_;         // captured (truncated to 4KB)
    int         exit_code = -1;  // child process exit code (-1 = not run)
    int         duration_ms = 0; // wall clock
};

// Execute one action delivered via heartbeat. payload fields are validated
// upstream by the backend (_validate_payload in actions.py). The agent
// performs a SECOND validation pass here (defence in depth).
//
// action_type is one of:
//   kill_pid         payload: {pid: int, signal: int}
//   block_ip         payload: {ip: "1.2.3.4", via: "nftables"|"iptables"}
//   unblock_ip       payload: {ip: "1.2.3.4"}
//   quarantine_file  payload: {path: "/tmp/x", dest: "/var/lib/logsoc/q/"}
//   unquarantine_file payload: {path: "/tmp/x"}
//   rmmod            payload: {module: "evil_ko"}
//   fim_add          payload: {path: "/etc/shadow", recursive: false}
//   fim_remove       payload: {path: "/etc/shadow"}
//
// dry_run=true: log + return ActionResult with status="succeeded" (intent only)
// dry_run=false: actually run the command, capture output
ActionResult execute(const std::string& action_type,
                     const std::string& action_id,
                     const std::string& payload_json,
                     bool dry_run);

}  // namespace logsoc::agent::t28
