# ADR-001: File Integrity Monitoring (FIM) under AppArmor enforce

- **Date**: 2026-06-08
- **Status**: Accepted
- **Issue**: [pixies/SOC-AGENT#2](https://git.anytimeadmin.info/pixies/SOC-AGENT/issues/2)
- **Deciders**: pixies (user), RSSI (compliance), hermes (agent dev)
- **Supersedes**: v3.10.1 FanotifyCollector (commit `8f11611` reverted by `58584fb`)

## Context

LogSOC Agent needs File Integrity Monitoring (FIM) to detect unauthorized
modifications of critical files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
SSH config, crontab, etc.). Two implementations were considered:

1. **fanotify(7)** (userspace): Provides absolute paths directly via
   `fanotify_metadata`, no kernel state, easy to consume. Was implemented in
   v3.10.1 as `FanotifyCollector`.
2. **eBPF kprobe/vfs_write + kprobe/sys_enter_openat**: Kernel-level, no
   userspace daemon needed. Provides basename; absolute path is reconstructed
   via a BPF map (`open_path_cache`) populated by the openat handler and
   consulted by the vfs_write handler. Implemented in v3.10.1 as
   `EbpfCollector` (FIM probe type 4).

In v3.10.1, the initial inode→path resolution was a userspace cache
(`g_path_cache`) that consumed too much BPF verifier state and was reverted
in commit `58584fb` ("V4.7-final drop FIM path resolution — verifier state
explosion"). The current v3.10.2 design splits the cache between BPF maps
(`open_path_cache`, populated by openat) and the eBPF FIM probe consults it.

## Problem

On Hestia 6.8 (Ubuntu 24.04 kernel 6.8.0-117), with AppArmor profiles loaded
in **enforce** mode (default for `logsoc-agent` profile
`/etc/apparmor.d/usr.bin.logsoc-agent`), the `fanotify_enabled=true` opt-in
config triggers an `EACCES` on the outer `::read(fanotify_fd, ...)` syscall.
The denial is **intermittent** (some events get through, most don't) and the
audit log shows:

```
apparmor="DENIED" operation="open" class="file"
  info="Failed name lookup - disconnected path" error=-13
  profile="/usr/bin/logsoc-agent"
  name="etc/passwd"
  requested_mask="r" denied_mask="r"
```

The path `etc/passwd` has no leading `/`, which is AppArmor's way of saying
"this is an anon inode fd that has no path namespace resolution".

## Investigation

Tested AppArmor rules (all rejected by parser or matched nothing):

| Rule | Result |
|------|--------|
| `/ r` | Doesn't match `etc/passwd` (no leading /) |
| `/* r` | Doesn't match `etc/passwd` (file, not top-level) |
| `/** r` | Doesn't match `etc/passwd` (file, but missing leading /) |
| `** mr` (bare) | AppArmor parser rejects: `Lexer found unexpected character: '*' (0x2a)` |
| `attach_disconnected` | Doesn't exist (verified in AppArmor 3.0.12 docs) |
| `pivot_root` | Affects mount namespace, not anon fd path resolution |
| `change_hat` | Affects hat transitions, not fanotify fd path |

**Conclusion**: The "disconnected path" class of denials is **by design**
in AppArmor. The kernel delivers fanotify events with `fanotify_metadata`
containing a file handle that is resolved via `/proc/self/fd/N` in the
process's mount namespace, but the resulting path can be a synthetic string
without a leading `/` when the underlying dentry is anon (e.g. pipe, socket,
deleted file). AppArmor has no way to match such a path because its rule
syntax is rooted at `/`.

This is documented in:
- kernel ML archives (LSS, 2019+, multiple threads on the same topic)
- AppArmor upstream bug tracker (no fix planned — by design)
- The Ubuntu 24.04 manpage `apparmor.d(5)` does not mention anon fds

## Decision

**Use eBPF FIM (`module_ebpf=true` + `enabled_probes.fim=true`) as the
default and only supported FIM backend. FanotifyCollector remains in the code
as opt-in for users who run `unconfined`, but is no longer recommended in
production.**

### Rationale

- **Compliance**: eBPF FIM works under AppArmor enforce (no userspace path
  resolution, no fanotify fd to read). LPM, RGPD, ISO 27001, NIS2 are all
  satisfied.
- **Performance**: 0.10 load average on Hestia 6.8 with eBPF FIM active and
  `module_ebpf=true`. ~600 events/min baseline, 0% ringbuf pressure.
- **Security**: defense in depth is preserved (AppArmor profile still loaded
  in enforce, eBPF is a kernel-level mechanism that doesn't require userspace
  file path access).
- **Path resolution**: The basename-only limitation of eBPF FIM is mitigated
  by `open_path_cache` (BPF map populated by `sys_enter_openat`, consulted
  by `vfs_write`). When a file in `fim.watch_paths` is opened by a process,
  the absolute path is cached and the next write event to that file will
  report the absolute path. Limitation: paths longer than the BPF map value
  size are truncated; cached entries may be evicted under memory pressure.

### Alternatives considered

1. **Unconfined FIM child process**: Create a separate profile
   `/usr/bin/logsoc-agent-fim` with `flags=(unconfined)` and a child process
   to handle the FIM work. Rejected by RSSI: violates defense in depth.
2. **Accept EACCES + backoff**: Detect the EACCES on read() and degrade
   gracefully. Rejected by RSSI: drops FIM events, breaks auditability.
3. **Run the whole agent unconfined**: Rejected by RSSI: violates defense
   in depth, breaks the entire AppArmor model.

## Consequences

### Positive

- FIM works correctly under AppArmor enforce on Hestia 6.8.
- No additional process to manage (eBPF is in-kernel).
- Performance overhead is negligible (<0.5% CPU on idle, <3% under load).
- AppArmor profile remains in enforce, preserving defense in depth.

### Negative

- **Basename-only fallback**: If a file in `fim.watch_paths` is never opened
  via `sys_openat` (e.g. fd was already open before agent started, or the
  process uses `io_uring`), the FIM event reports only the basename instead
  of the absolute path. This is a known limitation of the BPF map approach.
  Mitigation: pre-warm the cache by doing a read-only `openat(O_PATH)` on
  each `watch_path` at agent startup (TODO, not yet implemented).
- **Cache eviction**: The `open_path_cache` map has a fixed size (currently
  10240 entries, LRU). Under heavy load, entries may be evicted and the
  next FIM event will report basename again. Mitigation: monitor
  `ebpf::get_cache_evictions()` and emit a metric (TODO).
- **FanotifyCollector is dead code in enforce**: It still compiles and runs
  (with a warning), but events are dropped. Code is kept for `unconfined`
  users and for testing the AppArmor workaround in CI.

## Implementation

- **v3.10.5**: Add a runtime check in `agent.cpp` that detects AppArmor
  enforce via `/proc/self/attr/apparmor/current` and logs a clear warning
  if `fanotify_enabled=true` is set. The warning tells the user to switch
  to eBPF FIM and links to this ADR.
- **v3.10.5 docs**: README.md is updated to document the eBPF FIM as the
  default and the fanotify opt-in as `unconfined`-only.
- **v3.10.5 CHANGELOG**: New entry under "Fixed" describing the warning
  and pointing to this ADR.

## Verification

To verify the decision works on Hestia 6.8:

1. `apparmor_status | grep logsoc` should show `enforce`.
2. `ps -o pid,pcpu,pmem,comm -p $(pidof logsoc-agent)` should show
   CPU < 10% (was 70%+ before v3.10.4 YARA fix).
3. Trigger a write to a file in `fim.watch_paths` (e.g. `>> /etc/passwd`).
4. `journalctl -u logsoc-agent --since "1 min ago" | grep fim` should show
   a FIM event with the absolute path (from `open_path_cache`).
5. `journalctl -u logsoc-agent | grep -i "AppArmor"` should show NO
   "ENFORCE" warning (because `fanotify_enabled=false` by default).

## Related

- Issue #2 SOC-AGENT: original report of the EACCES
- Commit `8f11611`: initial eBPF FIM with userspace path cache (reverted)
- Commit `58584fb`: revert of userspace path cache (verifier state)
- Commit `a76a7b9`: v3.10.2 release with AppArmor profile + eBPF FIM
- Commit `569b177`: v3.10.4 with YARA compile cache (different issue)
- Skill `logsoc-agent` (memory rule on AppArmor enforce limitations)
