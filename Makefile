IFACE ?= enp0s1
ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
	INCLUDE_DIR := /usr/include/aarch64-linux-gnu
else
	INCLUDE_DIR := /usr/include/x86_64-linux-gnu
endif

.PHONY: deps generate build run clean iface

deps:
	sudo apt update
	sudo apt install -y golang-go clang llvm gcc make git libbpf-dev linux-libc-dev linux-headers-$$(uname -r) linux-tools-common
	go mod tidy
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

build: generate
	go build -o netwatch .

run: build
	sudo ./netwatch $(IFACE)

iface:
	ip link

clean:
	rm -f netwatch bpf_bpfel.go bpf_bpfel.o bpf_bpfeb.go bpf_bpfeb.o