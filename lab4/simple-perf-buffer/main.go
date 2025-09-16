package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Must match the C struct layout exactly!
type event struct {
	PID      uint32
	TGID     uint32
	Filename [256]byte
}

func cString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

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

	// Open a perf reader on the "events" PERF_EVENT_ARRAY map.
	// A per-CPU page-sized buffer is typical; bump if you see lost samples.
	reader, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("opening perf reader: %v", err)
	}
	defer reader.Close()

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reader loop in a goroutine so we can cancel via context.
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)

		for {
			rec, err := reader.Read()
			if err != nil {
				// When Close() is called, Read() returns an error; exit cleanly.
				errCh <- err
				return
			}

			// perf can report lost samples.
			if rec.LostSamples > 0 {
				log.Printf("perf buffer: lost %d samples", rec.LostSamples)
				continue
			}

			var ev event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				fmt.Printf("failed to decode event: %v\n", err)
				continue
			}

			fmt.Printf("execve pid=%d tgid=%d file=%q\n",
				ev.PID, ev.TGID, cString(ev.Filename[:]))
		}
	}()

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")

	// Stop the reader and drain any error.
	_ = reader.Close()
	<-errCh
}
