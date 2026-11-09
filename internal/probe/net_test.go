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
	src := netip.MustParseAddrPort("127.0.0.1:61005")
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
