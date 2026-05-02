package filesystem

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
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
type FsRecord struct {
	Pid      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Filename string `json:"filename"`
	Op       string `json:"op"`
	Count    uint16   `json:"count"`
}

type FsKey struct {
    Pid      uint32
    Comm     string
    Filename string
    Op       string
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

	f, err := os.OpenFile("fs_events.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("open file: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

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

		fsRecord := FsRecord{
			Pid:      event.Pid,
			Comm:     string(bytes.TrimRight(event.Comm[:], "\x00")),
			Filename: string(bytes.TrimRight(event.Filename[:], "\x00")),
			Op:       opName(event.Op),
		}

		if err := enc.Encode(fsRecord); err != nil {
			log.Printf("encode: %v", err)
		}
	}
}

func opName(op uint8) string {
	switch op {
	case 0:
		return "OPEN"
	case 1:
		return "WRITE"
	case 2:
		return "DELETE"
	default:
		return "UNKNOWN"
	}
}
