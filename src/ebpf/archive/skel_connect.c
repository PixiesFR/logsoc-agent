/* skel_connect.c — kprobe on tcp_connect, capture src_ip, dst_ip, dst_port, PID */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "event.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int trace_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = 3;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;

    u32 saddr, daddr;
    u16 dport;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    e->u.c.src_ip   = __bpf_ntohl(saddr);
    e->u.c.dst_ip   = __bpf_ntohl(daddr);
    e->u.c.dst_port = __bpf_ntohs(dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
