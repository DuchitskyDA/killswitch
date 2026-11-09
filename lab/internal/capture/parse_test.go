package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func eth(etype uint16, ip []byte) []byte {
	b := make([]byte, 14, 14+len(ip))
	binary.BigEndian.PutUint16(b[12:], etype)
	return append(b, ip...)
}

func ipv4(proto byte, src, dst string, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(h, l4...)
}

func ipv6(proto byte, src, dst string, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = proto
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(h, l4...)
}

func ports(sp, dp uint16, payload string) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	return append(b, payload...)
}

func TestParseEthernet(t *testing.T) {
	f, ok := ParseEthernet(eth(0x0800, ipv4(6, "198.51.100.2", "203.0.113.130", ports(40000, 80, ""))))
	if !ok || f.Proto != "tcp" || f.DPort != 80 || f.Src.String() != "198.51.100.2" || f.Dst.String() != "203.0.113.130" {
		t.Fatalf("tcp4: %+v %t", f, ok)
	}
	f, ok = ParseEthernet(eth(0x86dd, ipv6(17, "2001:db8:c::2", "2001:db8:b::2", ports(5000, 443, "x"))))
	if !ok || f.Proto != "udp" || f.DPort != 443 || f.Src.String() != "2001:db8:c::2" {
		t.Fatalf("udp6: %+v %t", f, ok)
	}
	f, ok = ParseEthernet(eth(0x0800, ipv4(17, "198.51.100.1", "198.51.100.2", ports(1, 9, "KSLMARK:42\n"))))
	if !ok || f.Mark != "42" {
		t.Fatalf("mark: %+v %t", f, ok)
	}
	if _, ok := ParseEthernet(eth(0x0806, make([]byte, 28))); ok {
		t.Fatal("ARP не должен разбираться как IP")
	}
	if _, ok := ParseEthernet([]byte{1, 2, 3}); ok {
		t.Fatal("короткий кадр")
	}
	frag := ipv4(17, "198.51.100.2", "203.0.113.130", ports(1, 2, ""))
	binary.BigEndian.PutUint16(frag[6:], 0x0010)
	if f, ok := ParseEthernet(eth(0x0800, frag)); !ok || f.DPort != 0 {
		t.Fatalf("фрагмент не несёт портов: %+v", f)
	}
}
