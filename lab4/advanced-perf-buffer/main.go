package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 perf perf.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Must match the C struct layout exactly!
type event struct {
	PID       uint32
	TGID      uint32
	Timestamp uint64
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
	var objs perfObjects
	if err := loadPerfObjects(&objs, nil); err != nil {
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
	reader, err := perf.NewReaderWithOptions(objs.Events, os.Getpagesize(), perf.ReaderOptions{
		// The number of events required in any per CPU buffer before
		// Read will process data. This is mutually exclusive with Watermark.
		// The default is zero, which means Watermark will take precedence.
		WakeupEvents: 3,

		// The number of written bytes required in any per CPU buffer before
		// Read will process data. Must be smaller than PerCPUBuffer.
		// The default is to start processing as soon as data is available.
		// Watermark: 0,
		//
		// This perf ring buffer is overwritable, once full the oldest event will be
		// overwritten by newest. The default is false.
		// Overwritable: true,
	})
	if err != nil {
		log.Fatalf("opening perf reader: %v", err)
	}
	// We do NOT defer reader.Close() here; we close it explicitly on shutdown.

	// Instantiate Queue for forwarding messages
	recordsQueue := make(chan *perf.Record, 8192)

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reader loop in a goroutine so we can cancel via context.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			rec, err := reader.Read()
			if err != nil {
				// When Close() is called, Read() returns an error; exit cleanly.
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				log.Fatalf("Failed to read perf event: %v", err)
				return
			} else {
				if len(rec.RawSample) > 0 {
					select {
					case recordsQueue <- &rec:
					default:
						log.Printf("recordsQueue channel is full, drop the event")
					}
				}

				// perf can report lost samples.
				if rec.LostSamples > 0 {
					log.Printf("perf buffer: lost %d samples", rec.LostSamples)
					continue
				}
			}
		}
	}()

	// Start processing records from records queue.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case record := <-recordsQueue:
				// Here we could further pass the data to other goroutines
				var ev event
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
					fmt.Printf("failed to decode record: %v\n", err)
					continue
				}

				fmt.Printf("execve pid=%d tgid=%d file=%q ts=%d\n",
					ev.PID, ev.TGID, cString(ev.Filename[:]), ev.Timestamp)
			case <-ctx.Done():
				log.Printf("Listening for events completed.")
				log.Printf("Unprocessed events in recordsQueue: %d", len(recordsQueue))
				// graceful shutdown; drain whatever’s already in the channel if you want
				return
			}
		}
	}()

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")

	// Unblock reader.Read()
	_ = reader.Close()

	// Wait for goroutines
	wg.Wait()
}
