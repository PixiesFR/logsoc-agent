/* skel_execve.c — kprobe on __x64_sys_execve, capture comm, args, PID, UID */
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

SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx)
{
    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->type = 2;
    ev->pid   = bpf_get_current_pid_tgid() >> 32;
    ev->uid   = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(ev->u.e.comm, sizeof(ev->u.e.comm));

    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    if (filename)
        bpf_probe_read_user_str(ev->u.e.args, sizeof(ev->u.e.args), filename);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
