package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

import (
        "context"
        "log"
        "os"
        "os/signal"
        "syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs traceObjects
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	// Attach Tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveTp, nil)
	if err != nil {
		log.Fatalf("Attaching Tracepoint: %s", err)
	}
	defer tp.Close()
	log.Printf("Successfully attached eBPF Tracepoint...")

	// Attach Raw Tracepoint
	rawtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sys_enter", 
		Program: objs.HandleExecveRawTp,
	})
	if err != nil {
		log.Fatalf("Attaching raw Tracepoint: %s", err)
	}
	defer rawtp.Close()
	log.Printf("Successfully attached eBPF Raw Tracepoint...")

	// Attach kprobe 
	kprobe, err := link.Kprobe("__x64_sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("Attaching kprobe: %v", err)
	}
	defer kprobe.Close()
	log.Printf("Successfully attached eBPF kprobe...")

	// Attach fentry fprobe 
	fentry, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryExecve,
	})
	if err != nil {
		log.Fatalf("Attaching Fentry: %v", err)
	}
	defer fentry.Close()
	log.Printf("Successfully attached eBPF fprobe...")

	// Attach BTF-Enabled tracepoint
	tpbtf, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleExecveBtf,
	})
	if err != nil {
		log.Fatalf("Attaching BTF-Enabled Tracepoint: %v", err)
	}
	defer tpbtf.Close()
	log.Printf("Successfully attached BTF-Enabled Tracepoint...")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
        ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
        defer stop()

        <-ctx.Done()
        log.Println("Received signal, exiting...")
}
