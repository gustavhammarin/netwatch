//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct syscall_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u8 comm[16];
    __u8 name[24];
    __u8 category[24];
    __u8 path[256];
    __s64 arg0;
    __s64 arg1;
    __s64 arg2;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} syscall_events SEC(".maps");

static __always_inline int submit_syscall(struct trace_event_raw_sys_enter *ctx, const char *name, const char *category, const char *path) {
    struct syscall_event *e = bpf_ringbuf_reserve(&syscall_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->arg0 = ctx->args[0];
    e->arg1 = ctx->args[1];
    e->arg2 = ctx->args[2];
    __builtin_memset(e->path, 0, sizeof(e->path));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->name, 0, sizeof(e->name));
    __builtin_memset(e->category, 0, sizeof(e->category));
    bpf_probe_read_kernel_str(&e->name, sizeof(e->name), name);
    bpf_probe_read_kernel_str(&e->category, sizeof(e->category), category);

    if (path) {
        bpf_probe_read_user_str(&e->path, sizeof(e->path), path);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#define TRACE_NO_PATH(fn, syscall_name, cat) \
SEC("tracepoint/syscalls/sys_enter_" syscall_name) \
int trace_##fn(struct trace_event_raw_sys_enter *ctx) { \
    return submit_syscall(ctx, syscall_name, cat, 0); \
}

#define TRACE_PATH(fn, syscall_name, cat, path_arg) \
SEC("tracepoint/syscalls/sys_enter_" syscall_name) \
int trace_##fn(struct trace_event_raw_sys_enter *ctx) { \
    return submit_syscall(ctx, syscall_name, cat, (const char *)ctx->args[path_arg]); \
}

TRACE_PATH(execve, "execve", "process", 0)
TRACE_PATH(execveat, "execveat", "process", 1)
TRACE_PATH(openat, "openat", "filesystem", 1)
TRACE_PATH(openat2, "openat2", "filesystem", 1)
TRACE_PATH(creat, "creat", "filesystem", 0)
TRACE_PATH(unlink, "unlink", "filesystem", 0)
TRACE_PATH(unlinkat, "unlinkat", "filesystem", 1)
TRACE_PATH(rename, "rename", "filesystem", 0)
TRACE_PATH(renameat, "renameat", "filesystem", 1)
TRACE_PATH(renameat2, "renameat2", "filesystem", 1)
TRACE_PATH(mkdir, "mkdir", "filesystem", 0)
TRACE_PATH(mkdirat, "mkdirat", "filesystem", 1)
TRACE_PATH(chmod, "chmod", "filesystem", 0)
TRACE_PATH(fchmodat, "fchmodat", "filesystem", 1)
TRACE_PATH(chown, "chown", "filesystem", 0)
TRACE_PATH(fchownat, "fchownat", "filesystem", 1)
TRACE_NO_PATH(bpf, "bpf", "kernel")
TRACE_NO_PATH(init_module, "init_module", "kernel")
TRACE_NO_PATH(finit_module, "finit_module", "kernel")
TRACE_NO_PATH(delete_module, "delete_module", "kernel")
TRACE_NO_PATH(setuid, "setuid", "privilege")
TRACE_NO_PATH(setgid, "setgid", "privilege")
TRACE_NO_PATH(setresuid, "setresuid", "privilege")
TRACE_NO_PATH(setresgid, "setresgid", "privilege")
TRACE_NO_PATH(capset, "capset", "privilege")
TRACE_PATH(mount, "mount", "namespace", 0)
TRACE_PATH(umount2, "umount2", "namespace", 0)
TRACE_NO_PATH(unshare, "unshare", "namespace")
TRACE_NO_PATH(setns, "setns", "namespace")
TRACE_NO_PATH(clone, "clone", "namespace")
TRACE_NO_PATH(clone3, "clone3", "namespace")
TRACE_NO_PATH(socket, "socket", "network")
TRACE_NO_PATH(connect, "connect", "network")
TRACE_NO_PATH(bind, "bind", "network")
TRACE_NO_PATH(listen, "listen", "network")
TRACE_NO_PATH(accept4, "accept4", "network")

char __license[] SEC("license") = "GPL";
