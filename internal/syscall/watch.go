package syscall

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"netwatch/bpf"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Event describes a syscall observed by the eBPF tracepoint monitor.
type Event struct {
	Time     time.Time `json:"time"`
	PID      uint32    `json:"pid"`
	TID      uint32    `json:"tid"`
	UID      uint32    `json:"uid"`
	Comm     string    `json:"comm"`
	Name     string    `json:"name"`
	Category string    `json:"category"`
	Path     string    `json:"path,omitempty"`
	Arg0     int64     `json:"arg0"`
	Arg1     int64     `json:"arg1"`
	Arg2     int64     `json:"arg2"`
}

type rawEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	UID       uint32
	Comm      [16]byte
	Name      [24]byte
	Category  [24]byte
	Path      [256]byte
	Arg0      int64
	Arg1      int64
	Arg2      int64
}

type tracepointProgram struct {
	name    string
	program *ebpf.Program
}

// Watch attaches supported syscall tracepoints and streams ring-buffer events until ctx is cancelled.
func Watch(ctx context.Context, objs *bpf.SyscallObjects, out chan<- Event, report func(string)) error {
	links, err := attachTracepoints(objs, report)
	if err != nil {
		return err
	}
	defer func() {
		for _, attached := range links {
			if closeErr := attached.Close(); closeErr != nil && report != nil {
				report(fmt.Sprintf("close tracepoint: %v", closeErr))
			}
		}
	}()

	reader, err := ringbuf.NewReader(objs.SyscallEvents)
	if err != nil {
		return fmt.Errorf("open syscall ringbuf: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read syscall ringbuf: %w", err)
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			if report != nil {
				report(err.Error())
			}
			continue
		}

		select {
		case out <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

func attachTracepoints(objs *bpf.SyscallObjects, report func(string)) ([]link.Link, error) {
	programs := []tracepointProgram{
		{"accept4", objs.TraceAccept4},
		{"bind", objs.TraceBind},
		{"bpf", objs.TraceBpf},
		{"capset", objs.TraceCapset},
		{"chmod", objs.TraceChmod},
		{"chown", objs.TraceChown},
		{"clone", objs.TraceClone},
		{"clone3", objs.TraceClone3},
		{"connect", objs.TraceConnect},
		{"creat", objs.TraceCreat},
		{"delete_module", objs.TraceDeleteModule},
		{"execve", objs.TraceExecve},
		{"execveat", objs.TraceExecveat},
		{"fchmodat", objs.TraceFchmodat},
		{"fchownat", objs.TraceFchownat},
		{"finit_module", objs.TraceFinitModule},
		{"init_module", objs.TraceInitModule},
		{"listen", objs.TraceListen},
		{"mkdir", objs.TraceMkdir},
		{"mkdirat", objs.TraceMkdirat},
		{"mount", objs.TraceMount},
		{"openat", objs.TraceOpenat},
		{"openat2", objs.TraceOpenat2},
		{"rename", objs.TraceRename},
		{"renameat", objs.TraceRenameat},
		{"renameat2", objs.TraceRenameat2},
		{"setgid", objs.TraceSetgid},
		{"setns", objs.TraceSetns},
		{"setresgid", objs.TraceSetresgid},
		{"setresuid", objs.TraceSetresuid},
		{"setuid", objs.TraceSetuid},
		{"socket", objs.TraceSocket},
		{"umount2", objs.TraceUmount2},
		{"unlink", objs.TraceUnlink},
		{"unlinkat", objs.TraceUnlinkat},
		{"unshare", objs.TraceUnshare},
	}

	var links []link.Link
	for _, item := range programs {
		attached, err := link.Tracepoint("syscalls", "sys_enter_"+item.name, item.program, nil)
		if err != nil {
			if report != nil {
				report(fmt.Sprintf("tracepoint sys_enter_%s unavailable: %v", item.name, err))
			}
			continue
		}
		links = append(links, attached)
	}

	if len(links) == 0 {
		return nil, fmt.Errorf("no syscall tracepoints attached")
	}
	return links, nil
}

func decodeEvent(sample []byte) (Event, error) {
	var raw rawEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("decode syscall event: %w", err)
	}

	return Event{
		Time:     time.Now(),
		PID:      raw.PID,
		TID:      raw.TID,
		UID:      raw.UID,
		Comm:     cString(raw.Comm[:]),
		Name:     cString(raw.Name[:]),
		Category: cString(raw.Category[:]),
		Path:     cString(raw.Path[:]),
		Arg0:     raw.Arg0,
		Arg1:     raw.Arg1,
		Arg2:     raw.Arg2,
	}, nil
}

func cString(value []byte) string {
	return strings.TrimRight(string(value), "\x00")
}
