package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"netwatch/bpf"
	"os"
	"os/signal"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type FsEvent struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
	Op       uint8
}

func Watch(fsObjs *bpf.FsObjects) {
	    tp, err := link.Tracepoint("syscalls", "sys_enter_openat", fsObjs.TraceOpenat, nil)
    if err != nil {
        log.Fatalf("attach tracepoint: %v", err)
    }
    defer tp.Close()

    // Read from ringbuf
    rd, err := ringbuf.NewReader(fsObjs.FsEvents)
    if err != nil {
        log.Fatalf("ringbuf reader: %v", err)
    }
    defer rd.Close()

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt)

    fmt.Println("watching filesystem... Ctrl+C to stop")

    go func() {
        <-stop
        rd.Close()
    }()

    for {
        record, err := rd.Read()
        if err != nil {
            break
        }

        var event FsEvent
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
            continue
        }

        comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
        filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

        fmt.Printf("pid=%-6d comm=%-16s file=%s\n", event.Pid, comm, filename)
    }
} 