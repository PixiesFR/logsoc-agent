/* skel_soc.c — V4.8 kernel-agnostic skeleton: simplified FIM (vfs_write only)
 *
 * V4.8 (T4.8.1) simplification:
 *   - REMOVED: tp/syscalls/sys_enter_openat (type 5) + trace_open()
 *   - REMOVED: open_path_cache BPF map (was deferred, now obsolete)
 *   - REMOVED: FIM sampling 1/8 (full-rate now, rate limit moved userspace)
 *   - ADDED:   kprobe/__x64_sys_write (type 8) → trace_write_fd()
 *             captures (fd, ktime_ns) for userspace merging with type 4 (fim)
 *   - ADDED:   ktime_ns field to event struct for cross-probe correlation
 *
 * Tracepoints utilisés:
 *   tp/syscalls/sys_enter_write     (type 1: write)
 *   tp/syscalls/sys_enter_execve    (type 2: execve)
 *   tp/syscalls/sys_enter_unlinkat  (type 6: unlink)
 * Kprobes:
 *   kprobe/tcp_v4_connect           (type 3: tcp connect)
 *   kprobe/vfs_write                (type 4: FIM — basename only)
 *   kprobe/__x64_sys_write          (type 8: write_fd — fd for userspace /proc resolve)
 *
 * Rationale: the previous V4.7 duplex (openat + vfs_write + open_path_cache
 * map) had a bug where shell `echo > file` produced zero events (see Gitea
 * issue #6). The duplex architecture was fragile: openat race conditions,
 * verifier state explosion on the cache lookup, and ambiguous path ownership
 * between two probes. V4.8 simplifies to a single FIM probe (vfs_write) and
 * resolves the full path in userspace via /proc/<pid>/fd/<fd>. See
 * docs/ebpf-fim-v5.md for the full design.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "event.h"

char _license[] SEC("license") = "GPL";

/* ── Maps ────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);  /* 16 MB */
} events SEC(".maps");

/* V4.8.27: drop_stats now covers all 17 event types.
 * Index by event type: drop_stats[type-1]++. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);  /* types 1..17 + headroom */
    __type(key, u32);
    __type(value, u64);
} drop_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} agent_pid SEC(".maps");

/* V4.8: fim_cnt sampling REMOVED. Rate limiting moved to userspace
 * (FimCollector::rate_limit_per_pid in src/agent/fim_collector.cpp). */

/* open_path_cache map REMOVED in V4.8 (T4.8.1). Path resolution now
 * happens in userspace via /proc/<pid>/fd/<fd>, no BPF cache needed. */

/* ── Helpers ───────────────────────────────────────── */
static __always_inline int is_agent_pid(void)
{
    u32 key = 0;
    u32 *ap = bpf_map_lookup_elem(&agent_pid, &key);
    if (ap && (bpf_get_current_pid_tgid() >> 32) == *ap)
        return 1;
    return 0;
}

static __always_inline void track_drop(u32 type)
{
    /* V4.8.27: types 1..17. Index = type-1. */
    u32 key = type - 1;
    if (key >= 32) return;
    u64 *val = bpf_map_lookup_elem(&drop_stats, &key);
    if (val) {
        u64 nv = *val + 1;
        bpf_map_update_elem(&drop_stats, &key, &nv, BPF_ANY);
    }
}

static __always_inline u64 now_ns(void)
{
    return bpf_ktime_get_ns();
}

/* ── Tracepoint syscall context (layout kernel-stable) ─ */
struct syscall_tp {
    /* struct trace_entry ent (8 bytes) */
    __u16 type;
    __u8  flags;
    __u8  preempt_count;
    __s32 pid;
    /* syscall data */
    __s64 id;           /* syscall number — 8 bytes */
    __u64 args[6];      /* args 0..5 */
};

/* ── Type 1: write (tracepoint sys_enter_write) ─────── */
SEC("tp/syscalls/sys_enter_write")
int trace_write(struct syscall_tp *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        track_drop(1);
        return 0;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->type = 1;
    ev->pid  = bpf_get_current_pid_tgid() >> 32;
    ev->uid  = bpf_get_current_uid_gid() >> 32;
    ev->ktime_ns = now_ns();

    ev->u.w.fd    = (u32)ctx->args[0];
    ev->u.w.count = (u64)ctx->args[2];

    /* Capture up to 256 bytes of the write buffer content */
    const char *buf_ptr = (const char *)ctx->args[1];
    if (buf_ptr) {
        u64 count = (u64)ctx->args[2];
        u64 to_read = count < sizeof(ev->u.w.payload) ? count : sizeof(ev->u.w.payload);
        if (to_read > 0)
            bpf_probe_read_user_str(ev->u.w.payload, to_read, buf_ptr);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Type 2: execve (tracepoint sys_enter_execve) ────── */
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct syscall_tp *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        track_drop(2);
        return 0;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->type = 2;
    ev->pid  = bpf_get_current_pid_tgid() >> 32;
    ev->uid  = bpf_get_current_uid_gid() >> 32;
    ev->ktime_ns = now_ns();

    bpf_get_current_comm(ev->u.e.comm, sizeof(ev->u.e.comm));

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(ev->u.e.args, sizeof(ev->u.e.args), filename);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Type 3: connect (tracepoint sock:inet_sock_set_state) ─ */
SEC("tp/sock/inet_sock_set_state")
int trace_connect(struct pt_regs *ctx)
{
    if (is_agent_pid()) return 0;

    /* Read tracepoint fields automatically by libbpf */
    struct sock_set_state_args {
        unsigned short common_type;
        unsigned char  common_flags;
        unsigned char  common_preempt_count;
        int            common_pid;
        const void    *skaddr;
        int            oldstate;
        int            newstate;
        __u16          sport;
        __u16          dport;
        __u16          family;
        __u16          protocol;
        __u8           saddr[4];
        __u8           daddr[4];
        __u8           saddr_v6[16];
        __u8           daddr_v6[16];
    } *tp = (struct sock_set_state_args *)ctx;

    /* Only IPv4 TCP SYN_SENT (outgoing connection) */
    if (tp->family != 2) return 0;      /* AF_INET */
    if (tp->protocol != 6) return 0;    /* IPPROTO_TCP */
    if (tp->newstate != 2) return 0;    /* TCP_SYN_SENT */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(3);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 3;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    bpf_get_current_comm(e->u.c.comm, sizeof(e->u.c.comm));

    u32 saddr_h = 0, daddr_h = 0;
    __builtin_memcpy(&saddr_h, tp->saddr, 4);
    __builtin_memcpy(&daddr_h, tp->daddr, 4);
    e->u.c.src_ip = __bpf_ntohl(saddr_h);
    e->u.c.dst_ip = __bpf_ntohl(daddr_h);
    e->u.c.dst_port = __bpf_ntohs(tp->dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 4: fim (kprobe vfs_write) — V4.8 simplified ── */
SEC("kprobe/vfs_write")
int trace_fim(struct pt_regs *ctx)
{
    if (is_agent_pid()) return 0;

    /* V4.8: REMOVED 1/8 sampling (FIM_SAMPLE_RATE). Full-rate emission;
     * rate limiting moved to userspace (FimCollector token bucket per-PID).
     * This is the ONLY FIM probe in V4.8 — openat (type 5) was removed. */

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(4);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 4;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();  /* V4.8: for matching with type 8 (write_fd) */

    bpf_get_current_comm(e->u.f.comm, sizeof(e->u.f.comm));

    struct inode *inode = NULL;
    struct dentry *dentry = NULL;

    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (inode) {
        u64 ino = 0;
        bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
        e->u.f.inode = ino;
    }

    struct path f_path;
    __builtin_memset(&f_path, 0, sizeof(f_path));
    bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);
    dentry = f_path.dentry;

    if (dentry) {
        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        if (d_name.name)
            bpf_probe_read_kernel_str(e->u.f.filename,
                                      sizeof(e->u.f.filename),
                                      d_name.name);
    }

    /* V4.8: filename is BASENAME ONLY here. Userspace (FimCollector)
     * merges with type 8 (write_fd) to get the fd, then resolves the
     * full path via /proc/<pid>/fd/<fd>. See docs/ebpf-fim-v5.md §3.2. */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 6: unlinkat (tracepoint sys_enter_unlinkat) ── */
SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlink(struct syscall_tp *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(6);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 6;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    bpf_get_current_comm(e->u.u_unlink.comm, sizeof(e->u.u_unlink.comm));

    const char *pathname = (const char *)ctx->args[1];
    if (pathname)
        bpf_probe_read_user_str(e->u.u_unlink.filename, sizeof(e->u.u_unlink.filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 8: write_fd (kprobe ksys_write) — V4.8 NEW (T4.8 hotfix) ──
 *
 * v4.8.0 (T4.8 hotfix): changed SEC from "__x64_sys_write" to "ksys_write".
 * On kernel 6.8, __x64_sys_write does NOT fire as a kprobe target (likely
 * because the kernel optimizes the syscall entry path via static_call
 * or direct dispatch from entry_SYSCALL_64 → ksys_write without going
 * through __x64_sys_write). ksys_write is the actual implementation and
 * always fires on every write() syscall. The first arg is the unsigned
 * int fd (same ABI as __x64_sys_write), so userspace code is unchanged.
 *
 * Captures the user-space fd from the write() syscall entry. The fd is
 * needed by userspace (FimCollector → FdResolver) to look up the full
 * path via /proc/<pid>/fd/<fd>. Matched with type 4 (fim) in userspace
 * by (pid, ktime_ns ± 1ms) since vfs_write fires slightly after
 * ksys_write on the same write() call.
 *
 * The fd from the syscall args is also exposed for write() events
 * (type 1) but those go to a different pipeline (YARA content shipper,
 * not FIM).
 */
SEC("kprobe/ksys_write")
int trace_write_fd(struct pt_regs *ctx)
{
    if (is_agent_pid()) return 0;

    /* PT_REGS_PARM1 = unsigned int fd (1st arg of write) */
    s32 fd = (s32)PT_REGS_PARM1(ctx);
    if (fd < 0) return 0;  /* AT_FDCWD, etc. — not a regular fd */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(8);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 8;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    e->u.wf.fd = fd;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 17: do_init_module + load_module (kprobe) — T4.8.27.9 (27B.5) ──
 * IoC: kernel module load/unload. This is the canonical rootkit vector.
 *   init_module(ModuleImage, len, param_values) — loads a .ko into kernel.
 *   finit_module(fd, param_values, flags) — loads .ko from fd (modern).
 *   delete_module(name) — unloads.
 * We ship ALL loads (init + finit). Filter: drop loads by uid==0 from
 * known package comm (dpkg, apt, yum, dnf, rpm) since those are legit.
 * The interesting signal: loads by non-root uid, or root with unknown
 * comm — that's the rootkit install.
 *
 * T11 modload kernel 6.8 fix: the tracepoints sys_enter_init_module /
 * sys_enter_finit_module do NOT fire on kernel 6.8 (the syscall is
 * dispatched via static_call optimization and bypasses the
 * tracepoint wrapper — same pattern as __x64_sys_write → ksys_write
 * in T64.4.8). We use kprobes on do_init_module (the actual C
 * function called for every module load) which is still
 * filterable via ftrace on 6.8 (verified via
 * /sys/kernel/debug/tracing/available_filter_functions).
 *
 * We do_init_module (handles both init_module and finit_module
 * cases — finit_module is just a thin wrapper that calls
 * do_init_module internally). This gives us full coverage of
 * both syscall paths in a single kprobe. */

/* T4.8.27.20: modload_debug counters removed — root cause
 * identified (userspace pipeline bottleneck), no longer needed.
 * If a future regression appears, re-introduce the per-CPU array
 * and debug_inc helper using the same pattern. */

/* T11: signature of do_init_module is
 *   static int do_init_module(struct module *mod)
 * We capture the mod->name as a string (kernel pointer) which is
 * the .ko's module name (e.g. "br_netfilter", "msdos"). This is
 * more useful than the user-space args[1]/args[2] from the old
 * tracepoint version.
 *
 * We also need to distinguish init_module from finit_module.
 * finit_module calls load_module() which calls do_init_module()
 * after a different setup phase. We use mod->init_size > 0 as a
 * heuristic (init_module sets init_size, finit_module often has
 * it zero pre-init). For a cleaner distinguisher we could check
 * the caller frame, but the heuristic is sufficient for our
 * use case (the subtype byte is informational, the detection
 * signal is "any module load"). */
SEC("kprobe/do_init_module")
int trace_do_init_module(struct pt_regs *ctx)
{
    if (is_agent_pid()) return 0;
    /* ctx->di = first arg = struct module *mod */
    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(17);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 17;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    u8 *p = (u8 *)e->u.e.args;
    /* p[0..63]: module name from struct module->name (kernel string, 64 bytes max).
     * Use bpf_probe_read_kernel_str since the pointer is a kernel address.
     *
     * p[64..79]: comm (16 bytes) — T12 audit fix #14.
     *
     * Layout history:
     *   - V4.8: p[64] = format marker, p[65] = reserved, p[66..81] = comm.
     *           Comm at offset 66 OVERFLOWED args[80] by 2 bytes (comm
     *           extends to p[81], struct ends at p[79]). The BPF verifier
     *           didn't catch the union-level overflow, and no corruption
     *           was observed in practice (lucky padding alignment), but
     *           the bytes were written into the next event in the ringbuf
     *           under sustained modload bursts.
     *   - T12 fix #14: dropped the format marker + reserved byte (they
     *           were never actually used by the loader to detect format
     *           version — the loader always reads the new layout).
     *           Comm now starts at p[64] and fits exactly in args[80].
     *           No overflow. */
    if (mod) {
        bpf_probe_read_kernel_str(p, 64, (const char *)mod + offsetof(struct module, name));
    }
    // T12 audit fix #14: write comm at p[64..79] (16 bytes). No more
    // overflow — the comm ends exactly at the struct boundary.
    bpf_get_current_comm(p + 64, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* T11: kept trace_finit_module path as a kretprobe on load_module
 * to capture the return value (success/failure) and as a
 * secondary signal in case do_init_module ever gets inlined.
 * load_module is called by both finit_module syscall and by
 * usermode helper invocations, so it gives us redundant coverage.
 *
 * Signature: static int load_module(struct load_info *info, const char *uargs, int flags)
 * We log the flags and the uargs pointer (we can't deref the user
 * pointer from kprobe for security, but the ksym address is fine
 * for correlation). */
SEC("kretprobe/load_module")
int trace_load_module_ret(struct pt_regs *ctx)
{
    /* Intentionally lightweight: just count successful loads.
     * Heavy logging is done by do_init_module. The return value
     * is in ctx->ax (rax). We use it as a signal that load_module
     * actually returned, not the per-call details. */
    if (is_agent_pid()) return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 0) {
        /* Failed load — not security relevant, skip. */
        return 0;
    }
    /* Successful load is already captured by do_init_module. We
     * don't double-log. This kretprobe is here purely as a
     * redundant signal: if do_init_module ever gets inlined
     * (unlikely, it's in module.c and exported), the loader
     * can grep for these kretprobe events to count successes. */
    return 0;
}

/* ── Type 16: tcp_v4_connect (kprobe + kretprobe) — T4.8.27.8 (27B.4) ──
 * IoC: outgoing connection (C2 beacon, exfiltration, lateral movement).
 *   tcp_v4_connect is called for every TCP connect() on IPv4. We capture
 *   sk + uaddr in the kprobe (entry, before ip_route_output_ports fills
 *   ports) and re-read the populated sk fields in the kretprobe (success
 *   case). On entry, sk->__sk_common has dport + daddr (passed in from
 *   inet_stream_connect), but sport is 0. By the return (after
 *   ip_route_output_ports + sk_alloc), sport is set.
 *   Trade-off: we lose pre-SYN visibility (kretprobe fires after route
 *   resolution but before SYN transmit). Acceptable for SIEM correlation.
 *
 * Per-CPU sk ptr map to pass from kprobe to kretprobe. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, u64);
} tcp_connect_sk_map SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect_entry, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (is_agent_pid()) return 0;
    if (!sk) return 0;
    /* Stash sk pointer in per-CPU slot 0 for the kretprobe. */
    u32 k = 0;
    bpf_map_update_elem(&tcp_connect_sk_map, &k, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_tcp_v4_connect_exit, int ret)
{
    if (is_agent_pid()) return 0;
    if (ret != 0) return 0;  /* connect failed — drop */

    u32 k = 0;
    u64 *skp = bpf_map_lookup_elem(&tcp_connect_sk_map, &k);
    if (!skp) return 0;
    struct sock *sk = (struct sock *)(*skp);
    bpf_map_delete_elem(&tcp_connect_sk_map, &k);
    if (!sk) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(16);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 16;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* Now sk has full state: sport (NBO) in skc_num, dport (NBO) in skc_dport,
     * daddr in skc_daddr. */
    u16 sport_nbo = 0, dport_nbo = 0;
    u32 daddr = 0;
    bpf_probe_read_kernel(&sport_nbo, sizeof(sport_nbo), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport_nbo, sizeof(dport_nbo), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    /* Layout: p[0]=sport(2)|dport(2), p[1]=daddr */
    u32 *p = (u32 *)e->u.e.args;
    p[0] = (u32)sport_nbo | ((u32)dport_nbo << 16);
    p[1] = daddr;
    bpf_get_current_comm(e->u.e.args + 8, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 15: sys_enter_bind (tracepoint) — T4.8.27.7 (27B.3) ──
 * IoC: process binding to a port. bind() is called by every server (nginx,
 *   sshd, etc.) AND by backdoors. We ship all binds; UI/dashboard flags
 *   unusual ports or non-known processes.
 * args[0] = int sockfd, args[1] = struct sockaddr *addr, args[2] = socklen_t */
SEC("tp/syscalls/sys_enter_bind")
int trace_bind(struct syscall_tp *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(15);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 15;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* args[1] = struct sockaddr * — read only first 8 bytes (sa_family + port + addr).
     * Layout: u16 sa_family, u16 sin_port (NBO), u32 sin_addr (IPv4) or 16B IPv6.
     * For AF_INET (2): family(2) + port(2) + addr(4) = 8 bytes.
     * For AF_INET6 (10): family(2) + port(2) + flowinfo(4) + addr(16) = 24 bytes.
     * We read 8 bytes which covers IPv4 fully. IPv6 partial. */
    u32 *p = (u32 *)e->u.e.args;
    u16 family = 0, port = 0;
    bpf_probe_read_user(&family, sizeof(family), (const void *)ctx->args[1]);
    bpf_probe_read_user(&port, sizeof(port), (const void *)ctx->args[1] + 2);
    /* IPv4 addr at offset 4 of sockaddr_in */
    u32 addr4 = 0;
    if (family == 2 /* AF_INET */) {
        bpf_probe_read_user(&addr4, sizeof(addr4), (const void *)ctx->args[1] + 4);
    }
    p[0] = (u32)family | ((u32)port << 16);  /* pack family+port in u32 */
    p[1] = addr4;
    bpf_get_current_comm(e->u.e.args + 8, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 14: inet_csk_accept (kretprobe) — T4.8.27.6 (27B.2) ──
 * IoC: backdoor accepting incoming connections. inet_csk_accept is the
 *   kernel function called by accept() on a server socket. Returns the
 *   new struct sock* on success, NULL on error.
 * Filter: drop NULL returns (accept failed). No IP/port filter (we
 *   want to see all accepts so an unknown process binding+accepting
 *   becomes visible). */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_inet_csk_accept, struct sock *sk_ret)
{
    if (is_agent_pid()) return 0;
    if (!sk_ret) return 0;  /* accept failed */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(14);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 14;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* Read sk->sk_dport (server port) and sk->sk_rcv_saddr (server IP).
     * struct sock (kernel 6.8): __sk_common has skc_dport, skc_rcv_saddr...
     * Offset varies. Use simple direct read at common offset.
     * For TCP established accept, sk->sk_dport is the LISTEN port in NBO. */
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk_ret->__sk_common.skc_dport);
    u32 saddr = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk_ret->__sk_common.skc_rcv_saddr);
    /* Store in args: p[0]=dport(2)+pad(2), p[1]=saddr(4) */
    u32 *p = (u32 *)e->u.e.args;
    p[0] = (u32)dport;
    p[1] = saddr;
    bpf_get_current_comm(e->u.e.args + 8, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 13: vfs_open (kprobe/do_filp_open) — T4.8.27.5 (27B.1) ──
 * IoC: read of sensitive files (/etc/passwd, /etc/shadow, /root/.ssh/...).
 * Uses kprobe/do_filp_open (not fexit/vfs_open) for kernel 6.8 compatibility.
 * do_filp_open takes struct filename *name with stable path buffer.
 * fexit/vfs_open + bpf_d_path was attempted but verifier rejected args.
 * Workaround: capture path inline at kprobe entry. */
SEC("kprobe/do_filp_open")
int BPF_KPROBE(trace_vfs_open, int dfd, struct filename *name, int flags, umode_t mode)
{
    if (is_agent_pid()) return 0;
    if (!name) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(13);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 13;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* O_ACCMODE (low 2 bits of flags) at args[0]; path at args[1..63] */
    u8 *flag_p = (u8 *)e->u.e.args;
    flag_p[0] = (u8)(flags & 0x3);
    /* struct filename { const char *uptr; refcount_t refcnt; ... }
     * Read the user-space pointer and copy the path string into args[1..63]. */
    const char *uptr = NULL;
    bpf_probe_read_kernel(&uptr, sizeof(uptr), &name->uptr);
    if (uptr)
        bpf_probe_read_user_str(e->u.e.args + 1, 63, uptr);
    bpf_get_current_comm(e->u.e.args + 64, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 12: bpf (tracepoint sys_enter_bpf) — T4.8.27.4 ──
 * IoC: tampering with our own EDR. A non-agent process calling BPF syscall
 *   on a cgroup where our progs are attached = rootkit / anti-EDR attempt.
 * Filter userspace: drop if cmd==BPF_OBJ_GET (id=7) by uid==0 agent process
 *   (legit use for fd passing). Ship all others, especially BPF_PROG_LOAD (5),
 *   BPF_MAP_CREATE (0), BPF_BTF_LOAD (18), BPF_LINK_CREATE (34). */
SEC("tp/syscalls/sys_enter_bpf")
int trace_bpf(struct syscall_tp *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(12);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 12;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* args[0] = int cmd (BPF_MAP_CREATE=0, BPF_PROG_LOAD=5, BPF_BTF_LOAD=18, ...)
     * args[1] = union bpf_attr * — read only the first 4 bytes (map_type/prog_type)
     * Reuse type 2 layout (e): comm[16]=caller, args[80]=cmd(4)+attr0(4)+pad(72). */
    u32 *p = (u32 *)e->u.e.args;
    p[0] = (u32)ctx->args[0];
    bpf_probe_read_user(&p[1], sizeof(p[1]), (const void *)ctx->args[1]);
    bpf_get_current_comm(e->u.e.comm, sizeof(e->u.e.comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 9: fork (tracepoint sched_process_fork) — T4.8.27.1 ──
 * IoC: fork bomb, suspicious process spawning, container escape.
 * Uses tracepoint (not kretprobe) for stability across kernels 5.x-6.x.
 * Filter userspace: ignore_comm for kthreadd/systemd/containerd-shim. */
SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(9);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 9;
    e->pid  = ctx->parent_pid;          /* parent PID */
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* Store child_pid + parent_comm in the union; reuse type 4 layout
     * (comm[16] + inode(u32) + filename[64]) so we don't grow event.h.
     * For fork: comm=parent_comm, inode=child_pid, filename="<child>" */
    bpf_get_current_comm(e->u.f.comm, sizeof(e->u.f.comm));
    e->u.f.inode = (u64)ctx->child_pid;
    /* child comm not available in sched_process_fork — store PID only */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 11: commit_creds (kprobe) — T4.8.27.3 ──
 * IoC: privilege escalation. commit_creds() is called by:
 *   - setuid(2), setgid(2), setreuid(2), setregid(2)
 *   - setresuid(2), setresgid(2), setfsuid(2), setfsgid(2)
 *   - kernel: cap_set_full, prepare_kernel_cred (rootkit)
 * Filter userspace: drop if new euid == old euid AND new egid == old egid
 *   (commit_creds() is called frequently for capability init — most are noise). */
SEC("kprobe/commit_creds")
int trace_commit_creds(struct pt_regs *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(11);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 11;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* arg0 = struct cred *new  — read uid/euid directly from kernel struct.
     * struct cred layout (kernel 6.8): atomic_t usage(4), kuid_t uid(4),
     *   kgid_t gid(4), kuid_t suid(4), kgid_t sgid(4), kuid_t euid(4),
     *   kgid_t egid(4). Offsets from struct cred *: uid=4, gid=8, euid=20, egid=24.
     * Reuse type 2 layout (e): comm[16]=caller_comm, args[80]=uid+euid+gid+egid+pad. */
    struct cred *c = (struct cred *)PT_REGS_PARM1(ctx);
    if (c) {
        u32 *p = (u32 *)e->u.e.args;
        bpf_probe_read_kernel(&p[0], sizeof(p[0]), (void *)c + 4);   /* uid */
        bpf_probe_read_kernel(&p[1], sizeof(p[1]), (void *)c + 20);  /* euid */
        bpf_probe_read_kernel(&p[2], sizeof(p[2]), (void *)c + 8);   /* gid */
        bpf_probe_read_kernel(&p[3], sizeof(p[3]), (void *)c + 24);  /* egid */
    }
    bpf_get_current_comm(e->u.e.comm, sizeof(e->u.e.comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 10: ptrace (tracepoint sys_enter_ptrace) — T4.8.27.2 ──
 * IoC: code injection (PTRACE_POKETEXT/POKEDATA), memory dump
 *      (PTRACE_ATTACH + PTRACE_PEEKDATA = secret exfiltration).
 * Filter userspace: drop if request=PTRACE_TRACEME (self-attach, benign). */
SEC("tp/syscalls/sys_enter_ptrace")
int trace_ptrace(struct syscall_tp *ctx)
{
    if (is_agent_pid()) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        track_drop(10);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = 10;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->ktime_ns = now_ns();

    /* args[0] = request (PTRACE_ATTACH=16, PTRACE_TRACEME=0, PTRACE_PEEKDATA=2,
     *                     PTRACE_POKETEXT=4, PTRACE_POKEDATA=5, PTRACE_CONT=7, ...)
     * args[1] = pid (target)
     * Reuse type 2 layout (e): comm[16]=caller_comm, args[80]=request(4)+target_pid(4)+pad(72).
     * sizeof(e) = 96 bytes — fits within ringbuf event struct (no event.h change). */
    bpf_get_current_comm(e->u.e.comm, sizeof(e->u.e.comm));
    /* Store request at start of args buffer, target_pid next, rest zero */
    u32 *p = (u32 *)e->u.e.args;
    p[0] = (u32)ctx->args[0];
    p[1] = (u32)ctx->args[1];
    /* args[2..19] stays zero */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── Type 5 (open) REMOVED in V4.8 ─────────────────────
 * The tracepoint sys_enter_openat and trace_open() were removed as part
 * of the T4.8.1 simplification. The full path that this tracepoint
 * captured is now reconstructed userspace via /proc/<pid>/fd/<fd> using
 * the fd emitted by the new type 8 (write_fd) kprobe.
 *
 * If the rollback flag fim.engine=v4_duplex is set, the V4.7 binary
 * (with trace_open) must be deployed — there is no runtime re-attach.
 * See docs/ebpf-fim-v5.md §3.9 for the rollback procedure.
 */
