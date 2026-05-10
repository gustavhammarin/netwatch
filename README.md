# netwatch-ebpf

A simple eBPF/XDP-based network monitor written in Go.

## Features
- Live packet counting
- Flow tracking (src/dst IP, protocol, port)
- eBPF kernel program (XDP)
- Go userspace CLI

## Run

```bash
make deps
go generate
make run <interface>
```

## API + Web UI

The API server runs Docker image analysis, container observation, XDP network flow
tracking, and syscall eBPF monitoring inside the VM. It serves a small web UI on
the same port.

```bash
make iface
export NETWATCH_TOKEN=dev-secret
make run-api IFACE=enp0s1
```

Open `http://<vm-ip>:8080`, enter the bearer token, choose an image, and start a
scan. The server permits one active scan at a time and observes the container for
up to 60 seconds by default.

API shape:

```text
GET  /api/images
POST /api/scans
GET  /api/scans/current
POST /api/scans/current/stop
POST /api/scans/current/clear
GET  /api/scans/events
```

Example:

```bash
curl -H "Authorization: Bearer $NETWATCH_TOKEN" \
  -d '{"image":"nginx:latest"}' \
  -H 'Content-Type: application/json' \
  http://<vm-ip>:8080/api/scans
```
