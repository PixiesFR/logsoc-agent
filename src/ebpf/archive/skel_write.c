/* skel_write.c — kprobe on __x64_sys_write, capture PID, fd, count */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/__x64_sys_write")
int trace_write(struct pt_regs *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = 1;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;
    e->u.w.fd    = (u32)PT_REGS_PARM1(ctx);
    e->u.w.count = (u64)PT_REGS_PARM3(ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
