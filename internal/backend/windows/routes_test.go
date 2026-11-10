package windows

import (
	"errors"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

func defaults(ifaces []env.Iface) map[string][2]bool {
	out := map[string][2]bool{}
	for _, i := range ifaces {
		out[i.Name] = [2]bool{i.DefaultRoute4, i.DefaultRoute6}
	}
	return out
}

func adaptersFixture() []env.Iface {
	return []env.Iface{{Name: "Ethernet", LUID: 1}, {Name: "vEthernet (nat)", LUID: 2}, {Name: "vEthernet (External)", LUID: 3}}
}

func TestDefaultRoutesByLUIDAndFamily(t *testing.T) {
	ifs := adaptersFixture()
	markDefaultRoutes(ifs, []routeRow{{LUID: 1, V4: true}, {LUID: 3, V4: true}, {LUID: 3, V4: false}}, nil)
	got := defaults(ifs)
	if got["Ethernet"] != [2]bool{true, false} || got["vEthernet (nat)"] != [2]bool{false, false} ||
		got["vEthernet (External)"] != [2]bool{true, true} {
		t.Fatalf("маршруты по умолчанию: %v", got)
	}
}

func TestDefaultRoutesUnreadableAssumesRoute(t *testing.T) {
	ifs := adaptersFixture()
	markDefaultRoutes(ifs, nil, errors.New("GetIpForwardTable2"))
	if got := defaults(ifs); got["vEthernet (nat)"] != [2]bool{true, true} {
		t.Fatalf("без таблицы: %v", got)
	}
}
