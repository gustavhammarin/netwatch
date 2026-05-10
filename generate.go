package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu" -output-dir ./bpf -go-package bpf Net ./c/net_watch.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu" -output-dir ./bpf -go-package bpf Fs ./c/fs_watch.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu" -output-dir ./bpf -go-package bpf Syscall ./c/syscall_watch.c
