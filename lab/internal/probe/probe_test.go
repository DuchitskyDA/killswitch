package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/services"
	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
)

// Пробы и сервисы на loopback: содержимое ответа, запись получателя, отсутствие сервера.
func TestProbesAgainstServices(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan services.Entry, 16)
	go services.Serve(ctx, services.Config{
		Addrs: []netip.Addr{lo}, AnswerA: topo.DNSAnswerA, AnswerAAAA: topo.DNSAnswerAAAA,
		HTTPPort: port, UDPPort: port, DNSPort: port + 1,
	}, func(e services.Entry) { got <- e })
	time.Sleep(200 * time.Millisecond)

	for _, s := range []Spec{
		{Kind: HTTP, Port: port}, {Kind: UDP, Port: port}, {Kind: DNSUDP, Port: port + 1}, {Kind: DNSTCP, Port: port + 1},
	} {
		s.Dst, s.Timeout = lo, time.Second
		r := Run(s)
		if !r.OK {
			t.Fatalf("%s: %+v", s.Kind, r)
		}
		if (s.Kind == HTTP || s.Kind == UDP) && r.Echo != "127.0.0.1" {
			t.Fatalf("%s: эхо %q", s.Kind, r.Echo)
		}
		select {
		case e := <-got:
			if e.Src != lo {
				t.Fatalf("%s: получатель записал %v", s.Kind, e)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s: получатель ничего не записал", s.Kind)
		}
	}
	if r := Run(Spec{Kind: HTTP, Dst: lo, Port: freePort(t), Timeout: 500 * time.Millisecond}); r.OK {
		t.Fatalf("порт без сервера дал успех: %+v", r)
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := uint16(l.Addr().(*net.TCPAddr).Port)
	u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p+1))
	if err != nil {
		return freePort(t)
	}
	u.Close()
	return p
}
