package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
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
	Count uint64 `json:"count"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: sudo go run . <interface>")
	}

	ifaceName := os.Args[1]

	fmt.Println("interface:", ifaceName)

	var objs bpfObjects

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %s not found: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
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
			writeCountsToJSON(&objs, "flows.json")
		case <-stop:
			fmt.Println("stopping")
			return
		}

	}

}

func writeCountsToJSON(objs *bpfObjects, filename string) {
	var records []FlowRecord

	var key FlowKey
	var value uint64

	iter := objs.FlowCounts.Iterate()

	for iter.Next(&key, &value) {
		records = append(records, FlowRecord{
			SrcIP: uint32ToIp(key.SrcIP),
			DstIP: uint32ToIp(key.DstIP),
			Protocol: protoName(key.Protocol),
			DstPort: key.DstPort,
			Count: value,
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

func uint32ToIp(n uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)

	addr := netip.AddrFrom4(b)
	return addr.String()
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UPD"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", p)
	}
}
