package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go postgres postgres.c

import (
	"os"
	"log"
	"unsafe"
	"os/signal"
	"sync"
	"syscall"
	"context"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type L7Event struct {
	Fd                  uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            string // L7_PROTOCOL_HTTP
	Tls                 bool   // Whether request was encrypted
	Method              string
	Payload             [1024]uint8
	PayloadSize         uint32 // How much of the payload was copied
	PayloadReadComplete bool   // Whether the payload was copied completely
	Failed              bool   // Request failed
	WriteTimeNs         uint64 // start time of write syscall
	Tid                 uint32
	Seq                 uint32 // tcp seq num
	EventReadTime       int64
}

type bpfL7Event struct {
	Fd                  uint64
	WriteTimeNs         uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	Payload             [1024]uint8
	PayloadSize         uint32
	PayloadReadComplete uint8
	Failed              uint8
	IsTls               uint8
	_                   [1]byte
	Seq                 uint32
	Tid                 uint32
	_                   [4]byte
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Load pre-compiled programs and maps into the kernel.
	var pgObjs postgresObjects
	if err := loadPostgresObjects(&pgObjs, nil); err != nil {
		log.Fatal(err)
	}

	r, err := link.Tracepoint("syscalls", "sys_enter_read", pgObjs.HandleRead, nil)
	if err != nil {
		log.Fatal("link sys_enter_read tracepoint")
	}
	defer r.Close()

	rexit, err := link.Tracepoint("syscalls", "sys_exit_read", pgObjs.HandleReadExit, nil)
	if err != nil {
		log.Fatal("link sys_exit_read tracepoint")
	}
	defer rexit.Close()

	L7EventsReader, err := perf.NewReader(pgObjs.L7Events, int(4096)*os.Getpagesize())
	if err != nil {
		log.Fatal("error creating perf event array reader")
	}

	log.Println("eBPF programs loaded and attached...")
	// Reader loop in a goroutine so we can cancel via context.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var record perf.Record
			err := L7EventsReader.ReadInto(&record)
			if err != nil {
				log.Print("error reading from perf array")
				return
			}

			if record.LostSamples != 0 {
				log.Printf("lost samples l7-event %d", record.LostSamples)
			}

			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Print("read sample l7-event nil or empty")
				return
			}

			l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))

			// copy payload slice
			payload := [1024]uint8{}
			copy(payload[:], l7Event.Payload[:])
			log.Printf("%s", payload)
		}
	}()

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")

	// Unblock reader
	_ = L7EventsReader.Close()

	// Wait for goroutines
	wg.Wait()
}
