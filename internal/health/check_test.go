package health

import (
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
