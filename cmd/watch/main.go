package main

import (
	"fmt"
	"log"
	"netwatch/bpf"
	"netwatch/internal/filesystem"
	"netwatch/internal/network"
	"os"
	"os/signal"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: sudo go run . <interface>")
	}

	ifaceName := os.Args[1]

	fmt.Println("interface:", ifaceName)

	var netObjs bpf.NetObjects
	var fsObjs bpf.FsObjects

	if err := bpf.LoadNetObjects(&netObjs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer netObjs.Close()
	if err := bpf.LoadFsObjects(&fsObjs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer fsObjs.Close()

	go func ()  {
		filesystem.Watch(&fsObjs)
	}()

	go func ()  {
		network.Watch(netObjs, ifaceName)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	fmt.Println("stopping")

}