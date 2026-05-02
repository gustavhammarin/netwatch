package network

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

func Uint32ToIp(n uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)

	addr := netip.AddrFrom4(b)
	return addr.String()
}

func ProtoName(p uint8) string {
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

func ServiceName(proto uint8, port uint16) string {
	if proto == 17 && port == 53 {
		return "DNS"
	}
	if proto == 6 && port == 53 {
		return "DNS"
	}
	if proto == 6 && port == 80 {
		return "HTTP"
	}
	if proto == 6 && port == 443 {
		return "HTTPS"
	}
	if proto == 6 && port == 22 {
		return "SSH"
	}
	return "UNKNOWN"
}