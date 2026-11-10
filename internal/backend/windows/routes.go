package windows

import (
	"net/netip"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// routeTargets — адреса, к которым Snapshot ищет эффективный маршрут: цели check (baseline по маршруту через
// туннель), Endpoints и dns.health.
func routeTargets(p policy.Policy, e env.Env) []netip.Addr {
	targets := append([]netip.Addr(nil), p.Check.Targets...)
	for _, ep := range p.Tunnel.Endpoints {
		if a, ok := ep.Addr(); ok {
			targets = append(targets, a)
		}
		targets = append(targets, e.Resolved[ep.Host]...)
	}
	if p.Health != nil {
		targets = append(targets, p.Health.Addr.Addr())
	}
	return targets
}

// routeRow — маршрут по умолчанию из таблицы маршрутов (GetIpForwardTable2, префикс длины 0): интерфейс и семейство.
type routeRow struct {
	LUID uint64
	V4   bool
}

// markDefaultRoutes отмечает интерфейсы с маршрутом по умолчанию по семействам. vEthernet (nat) Hyper-V/WSL и подобные
// адаптеры без него в интернет не ведут: check их семейство пропускает. По имени ничего не исключается: vEthernet
// (External) с маршрутом проверяется. Таблицу не прочитать (err) — маршрут считается у каждого: пробы идут, как раньше.
func markDefaultRoutes(ifaces []env.Iface, rows []routeRow, err error) {
	for k := range ifaces {
		i := &ifaces[k]
		i.DefaultRoute4, i.DefaultRoute6 = err != nil, err != nil
		for _, r := range rows {
			if err == nil && r.LUID == i.LUID {
				i.DefaultRoute4 = i.DefaultRoute4 || r.V4
				i.DefaultRoute6 = i.DefaultRoute6 || !r.V4
			}
		}
	}
}
