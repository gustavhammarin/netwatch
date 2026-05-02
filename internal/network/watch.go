package network

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"netwatch/bpf"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	Protocol uint8
	_        uint8
	DstPort  uint16
}
type FlowRecord struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol string `json:"protocol"`
	DstPort  uint16 `json:"dst_port"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Service  string `json:"service"`
}

type FlowValue struct {
	Packets uint64
	Bytes   uint64
}

func Watch(netObjs bpf.NetObjects, ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %s not found: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   netObjs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer l.Close()

	fmt.Println("netwatch running... Ctrl+C to stop")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-ticker.C:
			writeCountsToJSON(&netObjs, "flows.json")
		case <-stop:
			fmt.Println("stopping")
			return
		}

	}
}

func writeCountsToJSON(netObjs *bpf.NetObjects, filename string) {
	var records []FlowRecord

	var key FlowKey
	var value FlowValue

	iter := netObjs.FlowCounts.Iterate()

	for iter.Next(&key, &value) {
		records = append(records, FlowRecord{
			SrcIP:    Uint32ToIp(key.SrcIP),
			DstIP:    Uint32ToIp(key.DstIP),
			Protocol: ProtoName(key.Protocol),
			DstPort:  key.DstPort,
			Packets:  value.Packets,
			Bytes:    value.Bytes,
			Service:  ServiceName(key.Protocol, key.DstPort),
		})
	}

	if err := iter.Err(); err != nil {
		log.Printf("iterate map: %v", err)
		return
	}

	data, err := json.MarshalIndent(records, "", " ")
	if err != nil {
		log.Printf("marchal json: %v", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Printf("write json: %v", err)
	}
}
