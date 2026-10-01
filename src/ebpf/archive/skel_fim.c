/* skel_fim.c — kprobe on vfs_write, capture inode, filename (from dentry), UID */
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

SEC("kprobe/vfs_write")
int trace_fim(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = 4;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid() >> 32;

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
        struct qstr d_name;
        __builtin_memset(&d_name, 0, sizeof(d_name));
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        if (d_name.name)
            bpf_probe_read_kernel_str(e->u.f.filename, sizeof(e->u.f.filename), d_name.name);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
