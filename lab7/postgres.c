//go:build ignore

#include "vmlinux.h"
#include "postgres.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Instead of allocating on bpf stack, we allocate on a per-CPU array map due to BPF stack limit of 512 bytes
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

// Instead of allocating on bpf stack, we allocate on a per-CPU array map due to BPF stack limit of 512 bytes
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

// To transfer read parameters from enter to exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // pid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");

// Map to share l7 events with the userspace application
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;      // Extract PID from the lower 32 bits

    // Store an active read struct for later usage
    struct read_args args = {};
    args.fd = ctx->args[0];
    args.buf = (char *)ctx->args[1];
    args.size = ctx->args[2];
    long res = bpf_map_update_elem(&active_reads, &pid, &args, BPF_ANY);
    if (res < 0) {
        bpf_printk("Failed to update active_reads eBPF map");     
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;      // Extract PID from the lower 32 bits

    // Retrieve the active read struct from the enter of read syscall
    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &pid);
    if (!read_info) {
        return 0;
    }

    // Ensure we always clean up the args for this PID
    bpf_map_delete_elem(&active_reads, &pid);

    __s64 ret = ctx->ret; // syscall return (bytes or -errno)
    // If read failed or read zero bytes, nothing to copy/emit
    if (ret <= 0) {
        return 0;
    }
    // Cap the copy size to both the actual bytes read and our buffer cap
    __u32 to_copy = ret;
    if (to_copy > MAX_PAYLOAD_SIZE) {
	    to_copy = MAX_PAYLOAD_SIZE;
    }

    // Retrieve the active L7 event struct from the eBPF map (check above the map definition, why we use per-CPU array map for this purpose)
    // This event struct is then forwarded to the userspace application
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }

    if (read_info->buf) {
        // bpf_probe_read_user() is correct for copying raw bytes from user space
        long r = bpf_probe_read_user(e->payload, to_copy, read_info->buf);
        if (r != 0) {
		bpf_printk("Failed to read the data from buffer");
		return 0;
        }
    }

    // Forward L7 event to userspace application
    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        bpf_printk("failed write to l7_events");
    }

    return 0;
}
