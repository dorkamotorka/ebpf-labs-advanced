//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define ARGSIZE 256

struct event {
    u32 pid;
    u32 tgid;
    char filename[ARGSIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);

    struct event e = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid  = pid_tgid >> 32;
    e.tgid = (u32)pid_tgid;

    bpf_core_read_user_str(e.filename, sizeof(e.filename), filename_ptr);

    // Optional debug
    bpf_printk("execve: pid=%d tgid=%d file=%s\n", e.pid, e.tgid, e.filename);

    // Emit to perf buffer (one record on the current CPU)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
