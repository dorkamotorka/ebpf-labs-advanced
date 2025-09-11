//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define ARGSIZE 256 

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp(struct trace_event_raw_sys_enter *ctx) {
    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);

    u8 filename[ARGSIZE];
    bpf_core_read_user_str(&filename, sizeof(filename), filename_ptr);

    bpf_printk("Tracepoint (CO-RE) triggered for execve syscall with parameter filename: %s\n", filename);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp(struct bpf_raw_tracepoint_args *ctx) {
    // There is no method to attach a raw_tp or tp_btf directly to a single syscall...
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    unsigned long id = BPF_CORE_READ(ctx, args[1]); // Syscall ID is the second element
    if (id != 59)   // execve sycall ID
	return 0;

    struct pt_regs *regs = (struct pt_regs *)BPF_CORE_READ(ctx, args[0]);

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Raw tracepoint (CO-RE) triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve_non_core(struct pt_regs *ctx) {
    // On x86-64, the entry wrapper __x64_sys_execve is called with a pointer to struct pt_regs in %rdi -> pt_regs.di
    struct pt_regs *regs = (struct pt_regs *)ctx->di;

    // Read the filename "from the inner regs"
    unsigned long di = 0;
    bpf_probe_read_kernel(&di, sizeof(di), &regs->di);
    const char *filename = (const char *)di;

    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Kprobe triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    // Print the flags value
    bpf_printk("Kprobe triggered (CO-RE) for execve syscall with parameter filename: %s\n", buf);

    return 0;
}

SEC("fentry/__x64_sys_execve")
int fentry_execve(u64 *ctx) {
    // Direct kernel memory access
    struct pt_regs *regs = (struct pt_regs *)ctx[0];

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Fentry tracepoint triggered (CO-RE) for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("tp_btf/sys_enter")
int handle_execve_btf(u64 *ctx) {
    // There is no method to attach a tp_btf directly to a single syscall. Same reason as for the raw_tp
    // The tracepoint btf version allows you to access kernel memory directly from within the ebpf program.
    // There is no need to use a helper function like bpf_core_read or bpf_probe_read_kernel to access the kernel memory as in regular raw tracepoint
    long int syscall_id = (long int)ctx[1];
    if (syscall_id != 59)  // execve syscall ID
        return 0;

    // Direct kernel memory access here as well
    struct pt_regs *regs = (struct pt_regs *)ctx[0];
    // You don't need to use PT_REGS_PARM1_CORE helper
    char *filename = (char *)PT_REGS_PARM1(regs);
    char buf[ARGSIZE];
    // You don't need to use bpf_core_read_user_str helper
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("BTF-enabled tracepoint (CO-RE) triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}
