package darwin

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Цели check входят в маршруты снимка: без них baseline не узнает, что маршрут идёт через туннель.
func TestRouteTargetsIncludeCheckTargets(t *testing.T) {
	h := policy.HealthURL{Addr: netip.MustParseAddrPort("198.18.0.1:80"), Path: "/"}
	p := policy.Policy{Health: &h, Check: policy.Check{Targets: []netip.Addr{netip.MustParseAddr("203.0.113.130")}},
		Tunnel: policy.Tunnel{Endpoints: []policy.Endpoint{{Host: "198.51.100.10", Port: 443, Proto: policy.ProtoTCP}}}}
	got := routeTargets(p, env.Env{})
	want := []netip.Addr{netip.MustParseAddr("203.0.113.130"), netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.18.0.1")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("цели маршрутов %v, ждали %v", got, want)
	}
}
