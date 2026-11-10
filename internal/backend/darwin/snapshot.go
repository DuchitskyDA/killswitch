package darwin

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

const resolveTimeout = 3 * time.Second

// Snapshot собирает всё с побочными эффектами: интерфейсы, пользователей, пути, имена, маршруты, DNS от DHCP, boot id.
// Glob путей раскрываются независимо от p.Mode (enforce снимает снимок до выбора режима).
func (b *Backend) Snapshot(p policy.Policy) (env.Env, error) {
	id, err := bootID()
	if err != nil {
		return env.Env{}, err
	}
	e := env.Env{OS: "darwin", BootID: id, Users: map[string]int{}, Programs: map[string][]string{},
		Resolved: map[string][]netip.Addr{}, ResolveErr: map[string]string{}, Routes: map[netip.Addr]env.Route{},
		Health: env.HealthUnknown}
	if e.Ifaces, err = b.interfaces(); err != nil {
		return env.Env{}, err
	}
	b.markDefaultRoutes(e.Ifaces)
	for _, t := range p.Trust {
		b.snapshotTrust(&e, t)
	}
	for _, g := range p.Repair.Programs {
		e.Programs[g], _ = filepath.Glob(g)
	}
	resolveEndpoints(&e, p.Tunnel.Endpoints)
	b.snapshotRoutes(&e, p)
	if res, err := b.run.Run("", "/usr/sbin/scutil", "--dns"); err == nil {
		e.DHCPDNS = scopedResolvers(res.Out, physicalNames(e.Ifaces))
	}
	return e, nil
}

func (b *Backend) interfaces() ([]env.Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ports map[string]string
	if res, err := b.run.Run("", "/usr/sbin/networksetup", "-listallhardwareports"); err == nil {
		ports = hardwarePorts(res.Out)
	}
	out := make([]env.Iface, 0, len(ifs))
	for _, i := range ifs {
		it := env.Iface{Name: i.Name, Index: i.Index, Up: i.Flags&net.FlagUp != 0, Description: ports[i.Name],
			Physical: isPhysical(i.Name, ports)}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ones, _ := n.Mask.Size()
					it.Addrs = append(it.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
				}
			}
		}
		out = append(out, it)
	}
	return out, nil
}

// isPhysical — устройство аппаратного порта (networksetup); без списка — по имени en*.
func isPhysical(name string, ports map[string]string) bool {
	if ports == nil {
		return strings.HasPrefix(name, "en")
	}
	_, ok := ports[name]
	return ok
}

func (b *Backend) snapshotTrust(e *env.Env, t policy.Trust) {
	switch t.Kind {
	case policy.KindUser:
		if uid, err := strconv.Atoi(t.Value); err == nil {
			e.Users[t.Value] = uid
			return
		}
		// os/user без cgo не видит пользователей из каталога (dscl): спрашиваем id.
		if res, err := b.run.Run("", "/usr/bin/id", "-u", t.Value); err == nil {
			if uid, err := strconv.Atoi(strings.TrimSpace(res.Out)); err == nil {
				e.Users[t.Value] = uid
			}
		}
	case policy.KindProgram:
		e.Programs[t.Value], _ = filepath.Glob(t.Value)
	}
}

func resolveEndpoints(e *env.Env, eps []policy.Endpoint) {
	for _, ep := range eps {
		if _, ok := ep.Addr(); ok {
			continue
		}
		if _, done := e.Resolved[ep.Host]; done {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", ep.Host)
		cancel()
		if err != nil {
			e.ResolveErr[ep.Host] = err.Error()
			continue
		}
		e.Resolved[ep.Host] = sortedAddrs(addrs)
	}
}

// snapshotRoutes — эффективные маршруты к целям check, адресам endpoints и dns.health (`route -n get`).
func (b *Backend) snapshotRoutes(e *env.Env, p policy.Policy) {
	targets := routeTargets(p, *e)
	tunnel := map[string]bool{}
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		tunnel[i.Name] = true
	}
	index := map[string]int{}
	for _, i := range e.Ifaces {
		index[i.Name] = i.Index
	}
	for _, a := range targets {
		args := []string{"-n", "get", a.String()}
		if a.Is6() {
			args = []string{"-n", "get", "-inet6", a.String()}
		}
		res, err := b.run.Run("", "/sbin/route", args...)
		if err != nil {
			continue
		}
		if name := routeInterface(res.Out); name != "" {
			e.Routes[a] = env.Route{IfaceIndex: index[name], ViaTunnel: tunnel[name]}
		}
	}
}

// routeTargets — адреса, к которым Snapshot ищет эффективный маршрут: цели check (baseline по маршруту через
// туннель), адреса endpoints и dns.health.
func routeTargets(p policy.Policy, e env.Env) []netip.Addr {
	targets := append([]netip.Addr(nil), p.Check.Targets...)
	for _, ep := range p.Tunnel.Endpoints {
		targets = append(targets, endpointAddrs(ep, e)...)
	}
	if p.Health != nil {
		targets = append(targets, p.Health.Addr.Addr())
	}
	return targets
}

func physicalNames(ifs []env.Iface) map[string]bool {
	m := map[string]bool{}
	for _, i := range ifs {
		if i.Physical {
			m[i.Name] = true
		}
	}
	return m
}

// hardwarePorts: `networksetup -listallhardwareports` → устройство → имя порта ("en0" → "Wi-Fi").
func hardwarePorts(out string) map[string]string {
	ports := map[string]string{}
	port := ""
	for _, l := range lines(out) {
		if v, ok := strings.CutPrefix(l, "Hardware Port:"); ok {
			port = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "Device:"); ok && port != "" {
			ports[strings.TrimSpace(v)] = port
			port = ""
		}
	}
	return ports
}

// routeInterface: `route -n get` → значение "interface:".
func routeInterface(out string) string {
	for _, l := range lines(out) {
		if v, ok := strings.CutPrefix(l, "interface:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// scopedResolvers: `scutil --dns`, раздел scoped — резолверы физических интерфейсов (выданные DHCP/RA или заданные).
func scopedResolvers(out string, physical map[string]bool) []netip.Addr {
	_, scoped, ok := strings.Cut(out, "DNS configuration (for scoped queries)")
	if !ok {
		return nil
	}
	var found []netip.Addr
	flush := func(servers []netip.Addr, iface string) {
		if physical[iface] {
			found = append(found, servers...)
		}
	}
	var servers []netip.Addr
	iface := ""
	for _, l := range lines(scoped) {
		switch {
		case strings.HasPrefix(l, "resolver #"):
			flush(servers, iface)
			servers, iface = nil, ""
		case strings.HasPrefix(l, "nameserver["):
			if _, v, ok := strings.Cut(l, ":"); ok {
				if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
					servers = append(servers, a.WithZone(""))
				}
			}
		case strings.HasPrefix(l, "if_index"):
			if i, j := strings.Index(l, "("), strings.Index(l, ")"); i >= 0 && j > i {
				iface = l[i+1 : j]
			}
		}
	}
	flush(servers, iface)
	return sortedAddrs(found)
}

// markDefaultRoutes — есть ли у интерфейса маршрут по умолчанию v4/v6 (строки default `netstat -rn -f inet|inet6`,
// включая scoped; reject R и blackhole B — нет). Таблицу не прочитать — маршрут считается у каждого: пробы check
// идут, как раньше.
func (b *Backend) markDefaultRoutes(ifaces []env.Iface) {
	for _, v4 := range []bool{true, false} {
		fam := "inet6"
		if v4 {
			fam = "inet"
		}
		res, err := b.run.Run("", "/usr/sbin/netstat", "-rn", "-f", fam)
		devs := defaultRouteIfaces(res.Out)
		for k := range ifaces {
			has := err != nil || devs[ifaces[k].Name]
			if v4 {
				ifaces[k].DefaultRoute4 = has
			} else {
				ifaces[k].DefaultRoute6 = has
			}
		}
	}
}

// defaultRouteIfaces: `netstat -rn` → интерфейсы строк default (Destination Gateway Flags Netif …).
func defaultRouteIfaces(out string) map[string]bool {
	devs := map[string]bool{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != "default" || strings.ContainsAny(f[2], "RB") {
			continue
		}
		devs[f[3]] = true
	}
	return devs
}
