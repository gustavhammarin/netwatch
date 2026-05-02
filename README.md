# netwatch-ebpf

A simple eBPF/XDP-based network monitor written in Go.

## Features
- Live packet counting
- Flow tracking (src/dst IP, protocol, port)
- eBPF kernel program (XDP)
- Go userspace CLI

## Run

```bash
go generate
sudo go run . <interface>