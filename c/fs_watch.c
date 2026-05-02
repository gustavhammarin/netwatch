//go:build ignore

#include "vmlinux.h"            
#include <bpf/bpf_helpers.h>   
#include <bpf/bpf_tracing.h>    
#include <bpf/bpf_core_read.h>   

struct fs_event {
    __u32 pid;
    __u8 comm[16];
    __u8 filename[256];
    __u8 op;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} fs_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct fs_event *e;
    e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);

    e->op = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";