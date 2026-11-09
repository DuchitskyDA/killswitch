// Package capture разбирает кадры с WAN-интерфейса: кто, кому, по какому протоколу и порту.
package capture

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"

	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
)

// Flow — сводка одного пакета.
type Flow struct {
	Src   netip.Addr `json:"src"`
	Dst   netip.Addr `json:"dst"`
	Proto string     `json:"proto"`
	SPort uint16     `json:"sport,omitempty"`
	DPort uint16     `json:"dport,omitempty"`
	Mark  string     `json:"mark,omitempty"`
	Out   bool       `json:"out,omitempty"`
}

func protoName(p byte) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	}
	return "p" + strconv.Itoa(int(p))
}

// ParseEthernet разбирает кадр Ethernet с IPv4 или IPv6; прочее (ARP и т. п.) — false.
func ParseEthernet(b []byte) (Flow, bool) {
	if len(b) < 14 {
		return Flow{}, false
	}
	var f Flow
	var proto byte
	var l4 []byte
	switch binary.BigEndian.Uint16(b[12:14]) {
	case 0x0800:
		ip := b[14:]
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return Flow{}, false
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return Flow{}, false
		}
		proto = ip[9]
		f.Src = netip.AddrFrom4([4]byte(ip[12:16]))
		f.Dst = netip.AddrFrom4([4]byte(ip[16:20]))
		if binary.BigEndian.Uint16(ip[6:8])&0x1fff == 0 { // только первый фрагмент несёт порты
			l4 = ip[ihl:]
		}
	case 0x86dd:
		ip := b[14:]
		if len(ip) < 40 || ip[0]>>4 != 6 {
			return Flow{}, false
		}
		proto = ip[6]
		f.Src = netip.AddrFrom16([16]byte(ip[8:24]))
		f.Dst = netip.AddrFrom16([16]byte(ip[24:40]))
		l4 = ip[40:]
	default:
		return Flow{}, false
	}
	f.Proto = protoName(proto)
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		f.SPort = binary.BigEndian.Uint16(l4[0:2])
		f.DPort = binary.BigEndian.Uint16(l4[2:4])
	}
	if proto == 17 && len(l4) > 8 {
		if p := string(l4[8:]); strings.HasPrefix(p, topo.MarkPrefix) {
			f.Mark = strings.TrimSpace(strings.TrimPrefix(p, topo.MarkPrefix))
		}
	}
	return f, true
}
