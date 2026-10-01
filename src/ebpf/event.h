/* event.h — common event struct for all eBPF probes
 * V4.4: added comm[16] to all unions for human-readable process names
 * V4.5: added type 7 (o_inode) mini-event from kretprobe vfs_open to populate
 *       userspace inode→path cache (FIM basename → absolute path resolution).
 * V4.6: type 7 rewritten as fexit/vfs_open + bpf_d_path kfunc. The struct now
 *       carries the absolute path string directly, dropping the pid-keyed
 *       pending path logic in userspace.
 * V4.8 (T4.8.1): type 5 (open tracepoint) REMOVED, open_path_cache map
 *       REMOVED. Added type 8 (write_fd) from __x64_sys_write kprobe to
 *       capture (fd, ktime_ns) for userspace merging with type 4 (fim).
 *       Userspace path resolution now happens via /proc/<pid>/fd/<fd>.
 *
 * V4.8.31 (T12 audit fix #16) — completed event type table. The previous
 * header only documented types 1, 2, 3, 4, 6, 8 (with 5 explicitly
 * REMOVED). The loader and skel_soc.c actually use types 1-17. New types
 * 9-17 share the execve-like `e` union layout (comm[16] + args[80]) but
 * with a type-specific interpretation of the args bytes. See comments
 * below and the corresponding case blocks in src/ebpf/loader.cpp.
 */
#ifndef __EVENT_H__
#define __EVENT_H__

struct event {
    u32 type;   /* see EVENT TYPE TABLE below */
    u32 pid;
    u32 uid;
    u32 _pad;
    u64 ktime_ns;   /* V4.8: monotonically increasing timestamp (ns) for userspace matching */
    union {
        struct { u32 fd; u32 _pad2; u64 count; char payload[256]; } w;              /* type 1: write + content preview */
        struct { char comm[16]; char args[80]; } e;                                  /* type 2: execve, also reused for 9-17 */
        struct { char comm[16]; u32 src_ip; u32 dst_ip; u16 dst_port; u16 _pad3; } c; /* type 3: connect */
        struct { char comm[16]; u64 inode; char filename[64]; } f;                   /* type 4: fim (basename, fd resolved userspace) */
        struct { char comm[16]; char filename[64]; } u_unlink;                       /* type 6: unlink */
        struct { s32 fd; s32 _pad_w; } wf;                                           /* type 8: write_fd (fd + ktime_ns for merging with type 4) */
        /* type 5 (open) REMOVED in V4.8 — see docs/ebpf-fim-v5.md */
    } u;

    /* EVENT TYPE TABLE (T12 audit fix #16)
     *
     * type 1  : write          — sys_enter_write, payload preview in u.w.payload
     * type 2  : execve         — sys_enter_execve, args in u.e.args
     * type 3  : connect        — inet_sock_set_state TCP, IPs in u.c
     * type 4  : fim            — fanotify FAN_MODIFY, basename in u.f.filename
     * type 5  : (REMOVED)      — open tracepoint, see V4.8 notes
     * type 6  : unlink         — sys_enter_unlinkat, filename in u_unlink
     * type 7  : (V4.5/V4.6)    — vfs_open kfunc fexit, path string in args (replaced by type 13)
     * type 8  : write_fd       — __x64_sys_write kprobe, fd+ktime for FIM merge
     * type 9  : fork           — sched_process_fork, child pid+comm
     * type 10 : ptrace         — sys_enter_ptrace, request+pid
     * type 11 : commit_creds   — commit_creds kprobe, new uid
     * type 12 : bpf            — sys_enter_bpf, cmd+attr
     * type 13 : vfs_open       — kprobe/vfs_open, filename in args
     * type 14 : inet_csk_accept— inet_csk_accept kprobe, dst_port in args
     * type 15 : bind           — kprobe/bind, addr+port in args
     * type 16 : tcp_v4_connect — kprobe/tcp_v4_connect, IPs+port in args
     * type 17 : modload        — kprobe/do_init_module, modname+comm in args
     *           (T12 fix #14: layout is p[0..63]=modname, p[64..79]=comm,
     *            no overflow. Was p[66..81] in v4.8.30 — wrote 2 bytes
     *            past args[80].)
     *
     * Types 9-17 share the u.e layout (comm[16] + args[80]) and
     * reinterpret the args bytes per type. See case blocks in
     * src/ebpf/loader.cpp for the exact byte layout.
     */
};

#endif
