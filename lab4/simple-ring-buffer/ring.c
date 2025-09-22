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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space on the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // If the buffer is full, just drop the event
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = pid_tgid >> 32;
    e->tgid = (u32)pid_tgid;

    // Copy filename directly into the ring-buffered event
    const char *filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_core_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

    // (Optional) debug message visible via /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("execve: pid=%d tgid=%d file=%s\n", e->pid, e->tgid, e->filename);

    // Submit to ring buffer 
    bpf_ringbuf_submit(e, 0);
    return 0;
}
