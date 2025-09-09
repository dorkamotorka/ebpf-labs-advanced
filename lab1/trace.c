//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define ARGSIZE 256 

struct trace_sys_enter_execve {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;

    s32 syscall_nr;        // offset=8,  size=4
    u32 pad;               // offset=12, size=4 (pad)
    const u8 *filename;    // offset=16, size=8
    const u8 *const *argv; // offset=24, size=8
    const u8 *const *envp; // offset=32, size=8
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_tp_non_core(struct trace_sys_enter_execve *ctx) {
    char *filename_ptr = (char *)BPF_PROBE_READ(ctx, filename);

    u8 buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename_ptr);

    bpf_printk("Tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp_non_core(struct bpf_raw_tracepoint_args *ctx) {
    // There is no method to attach a raw_tp or tp_btf directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    unsigned long id = BPF_PROBE_READ(ctx, args[1]);
    if (id != 59)   // execve sycall ID
	return 0;

    struct pt_regs *regs = (struct pt_regs *)BPF_PROBE_READ(ctx, args[0]);

    const char *filename;
    // Intentionally accessing the register (without using PT_REGS_PARM* macro) directly for illustration
    bpf_probe_read(&filename, sizeof(filename), &regs->di);

    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Raw tracepoint triggered for execve syscall with parameter filename: %s\n", buf);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve_non_core(struct pt_regs *ctx) {
    char *filename = (char *)PT_REGS_PARM1(ctx);

    // This is INTENTIONALLY not portable, so you might have to actually replace the first line with this
    //struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    //char *filename = (char *)PT_REGS_PARM1(ctx2);

    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    // Print the flags value
    bpf_printk("Kprobe triggered for execve syscall with parameter filename: %s\n", buf);

    return 0;
}

SEC("fentry/__x64_sys_execve")
int fentry_execve(u64 *ctx) {
    // Direct kernel memory access
    struct pt_regs *regs = (struct pt_regs *)ctx[0];

    char *filename = (char *)PT_REGS_PARM1(regs);
    char buf[ARGSIZE];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    bpf_printk("Fentry tracepoint triggered (CO-RE) for execve syscall with parameter filename: %s\n", buf);
    return 0;
}
