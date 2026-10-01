/* fim_watch.hpp — T12.12: bridge for action_executor → FanotifyCollector.
 *
 * The T28 dispatcher (action_executor.cpp) needs to add or remove
 * fanotify watches at runtime when the backend pushes a "fim_add" /
 * "fim_remove" action. The actual fanotify fd is owned by the
 * FanotifyCollector (agent.cpp), which holds it privately.
 *
 * This header exposes two thin C-linkage shims that the dispatcher
 * can call. The implementations live in agent.cpp (where the
 * collector instance is in scope) and forward the call to the
 * collector's public add_watch / remove_watch methods.
 *
 * Design choice (KISS):
 *   - Pointer to the collector is exposed via g_fanotify_collector
 *     (set once in main() right after construction, read-only after).
 *   - No mutex: the add_watch/remove_watch ops are short syscalls
 *     on the fanotify fd. Concurrent calls with the run() loop
 *     (which calls read() on the same fd) are safe: fanotify_mark
 *     is independent of read()/poll() on the same fd in the kernel.
 *   - No factory / no class hierarchy / no DI: the action_executor
 *     is downstream of main(), it doesn't construct anything.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Add a fanotify watch on `path`. If `recursive` is true, walk the
// directory tree (bounded depth 8, same as the collector's startup
// walk) and mark each file. Returns 0 on success, -1 on error
// (sets errno).
//
// The path is stat()ed; if it does not exist or is not accessible,
// the function returns -1 with errno=ENOENT or errno=EACCES.
//
// Note: the directory walk here is a stripped-down reimplementation
// of the collector's startup walk. It does NOT share the cfg_.fim.*
// knobs (ignore_paths, fanotify_file_mask) because the action payload
// is operator-driven, not policy-driven. We use the same file mask
// as the collector for consistency (FAN_MODIFY | FAN_CREATE | ...).
int t28_fim_watch_add(const char* path, int recursive);

// Remove the watch on `path`. If `recursive` is true, walk the tree
// and remove each file's mark. Returns 0 on success, -1 on error.
int t28_fim_watch_remove(const char* path, int recursive);

#ifdef __cplusplus
}  // extern "C"
#endif
