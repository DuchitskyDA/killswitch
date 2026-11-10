package health

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

func serve(reply string) net.Conn {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte(reply))
		_ = server.Close()
	}()
	return client
}

func TestExchangeHTTPStatusIsHealthy(t *testing.T) {
	noErr(t, Exchange(serve("HTTP/1.1 204 No Content\r\n\r\n"), "198.18.0.1", "/"))
}

func TestExchangeNonHTTPReplyIsNotHealthy(t *testing.T) {
	hasErr(t, Exchange(serve("SSH-2.0-x\r\n"), "198.18.0.1", "/"))
}

func TestExchangeClosedWithoutReplyIsNotHealthy(t *testing.T) {
	hasErr(t, Exchange(serve(""), "198.18.0.1", "/"))
}

var healthAddr = netip.MustParseAddrPort("198.18.0.1:80")

func gatePolicy() policy.Policy {
	return policy.Policy{Tunnel: policy.Tunnel{Interfaces: []string{"wg0"}},
		Health: &policy.HealthURL{Addr: healthAddr, Path: "/"}}
}

func TestGateRouteViaTunnel(t *testing.T) {
	e := env.Env{Ifaces: []env.Iface{{Name: "wg0", Index: 7, Up: true}},
		Routes: map[netip.Addr]env.Route{healthAddr.Addr(): {IfaceIndex: 7, ViaTunnel: true}}}
	tun, err := Gate(e, gatePolicy())
	noErr(t, err)
	eq(t, tun.Name, "wg0")
}

func TestGateRouteViaPhysicalFails(t *testing.T) {
	e := env.Env{Ifaces: []env.Iface{{Name: "wg0", Index: 7, Up: true}},
		Routes: map[netip.Addr]env.Route{healthAddr.Addr(): {IfaceIndex: 2}}}
	_, err := Gate(e, gatePolicy())
	hasErr(t, err)
}

func TestGateRouteNotMarkedTunnelFails(t *testing.T) {
	e := env.Env{Ifaces: []env.Iface{{Name: "wg0", Index: 7, Up: true}},
		Routes: map[netip.Addr]env.Route{healthAddr.Addr(): {IfaceIndex: 7}}}
	_, err := Gate(e, gatePolicy())
	hasErr(t, err)
}

func TestGateTunnelDownFails(t *testing.T) {
	e := env.Env{Ifaces: []env.Iface{{Name: "wg0", Index: 7}},
		Routes: map[netip.Addr]env.Route{healthAddr.Addr(): {IfaceIndex: 7, ViaTunnel: true}}}
	_, err := Gate(e, gatePolicy())
	hasErr(t, err)
}

// httpOnLoopback — HTTP-сервер на 127.0.0.1, отвечает статусом.
func httpOnLoopback(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	noErr(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 512)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.0 204 No Content\r\n\r\n"))
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

var loTun = env.Iface{Name: "lo", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}

func TestCheckByRouteFromTunnelSourceIsHealthy(t *testing.T) {
	addr := httpOnLoopback(t)
	noErr(t, Check(context.Background(), policy.HealthURL{Addr: addr, Path: "/"}, loTun))
}

func TestRouteDialerRejectsSourceOutsideTunnel(t *testing.T) {
	addr := httpOnLoopback(t)
	other := env.Iface{Name: "wg0", Addrs: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}
	_, err := RouteDialer{Tun: other}.DialContext(context.Background(), "tcp", addr.String())
	hasErr(t, err)
}
