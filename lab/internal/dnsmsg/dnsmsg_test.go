package dnsmsg

import (
	"net/netip"
	"testing"
)

var (
	a    = netip.MustParseAddr("203.0.113.99")
	aaaa = netip.MustParseAddr("2001:db8:b::99")
)

func TestRoundTrip(t *testing.T) {
	for _, c := range []struct {
		qtype uint16
		want  netip.Addr
	}{{TypeA, a}, {TypeAAAA, aaaa}} {
		q, err := Query(0x1234, "probe.ksl.test", c.qtype)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Answer(q, a, aaaa)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Addrs(r, 0x1234)
		if err != nil || len(got) != 1 || got[0] != c.want {
			t.Fatalf("qtype %d: %v %v", c.qtype, got, err)
		}
	}
}

func TestRejects(t *testing.T) {
	q, _ := Query(7, "probe.ksl.test", TypeA)
	r, _ := Answer(q, a, aaaa)
	if _, err := Addrs(r, 8); err == nil {
		t.Fatal("чужой id принят")
	}
	if _, err := Addrs(q, 7); err == nil {
		t.Fatal("запрос принят как ответ")
	}
	if _, err := Answer(q[:10], a, aaaa); err == nil {
		t.Fatal("обрезанный запрос принят")
	}
	if _, err := Answer(r, a, aaaa); err == nil {
		t.Fatal("ответ принят как запрос")
	}
	if _, err := Query(1, "a..b", TypeA); err == nil {
		t.Fatal("пустая метка принята")
	}
	other, _ := Query(9, "probe.ksl.test", 16)
	r, err := Answer(other, a, aaaa)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Addrs(r, 9); err != nil || len(got) != 0 {
		t.Fatalf("TXT: %v %v", got, err)
	}
}
