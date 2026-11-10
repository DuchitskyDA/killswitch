package probe

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
)

func TestDirectSendsFromPlannedSourcePort(t *testing.T) {
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	noErr(t, err)
	defer srv.Close()
	from := make(chan netip.AddrPort, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := srv.ReadFrom(buf)
		if err != nil {
			return
		}
		from <- addr.(*net.UDPAddr).AddrPort()
		_, _ = srv.WriteTo(buf[:n], addr)
	}()
	port := srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	src := netip.MustParseAddrPort("127.0.0.1:30005")
	id := ProbeID{Proto: "udp", Src: src, Dst: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	noBind := health.Binder(func(env.Iface) health.ControlFunc {
		return func(string, string, syscall.RawConn) error { return nil }
	})
	n := NetProber{Bind: noBind, Timeout: 2 * time.Second}
	ok, err := n.Direct(context.Background(), Service{Name: "udp-echo", Proto: "udp", Port: port}, id, env.Iface{Name: "lo"})
	noErr(t, err)
	eq(t, ok, true)
	eq(t, <-from, src)
}

// udpEcho — UDP-эхо на 127.0.0.1.
func udpEcho(t *testing.T) uint16 {
	t.Helper()
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	noErr(t, err)
	t.Cleanup(func() { srv.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = srv.WriteTo(buf[:n], addr)
		}
	}()
	return srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

func TestRouteRejectsSourceOutsideTunnel(t *testing.T) {
	port := udpEcho(t)
	noBind := health.Binder(func(env.Iface) health.ControlFunc {
		return func(string, string, syscall.RawConn) error { return nil }
	})
	other := env.Iface{Name: "wg0", Addrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}
	n := NetProber{Bind: noBind, Timeout: 2 * time.Second}
	err := n.Route(context.Background(), Service{Name: "udp-echo", Proto: "udp", Port: port}, netip.MustParseAddr("127.0.0.1"), other)
	hasErr(t, err)
}

func TestRouteFromTunnelSourceAnswers(t *testing.T) {
	port := udpEcho(t)
	lo := env.Iface{Name: "lo", Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}
	n := NetProber{Bind: func(env.Iface) health.ControlFunc { return nil }, Timeout: 2 * time.Second}
	noErr(t, n.Route(context.Background(), Service{Name: "udp-echo", Proto: "udp", Port: port}, netip.MustParseAddr("127.0.0.1"), lo))
}
