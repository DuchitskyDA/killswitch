package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

const (
	bootIDFile = "/proc/sys/kernel/random/boot_id"
	cgroupRoot = "/sys/fs/cgroup"
)

// resolvConfs — откуда берутся резолверы физики: upstream systemd-resolved, иначе /etc/resolv.conf.
var resolvConfs = []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}

// Snapshot собирает всё, что читает систему и сеть (рев. 4 B4). Glob раскрываются независимо от режима.
func (b *Backend) Snapshot(p policy.Policy) (env.Env, error) {
	ifaces, err := b.ifaces()
	if err != nil {
		return env.Env{}, fmt.Errorf("интерфейсы: %w", err)
	}
	e := env.Env{OS: "linux", Ifaces: ifaces, Programs: map[string][]string{}, Users: map[string]int{},
		Resolved: map[string][]netip.Addr{}, ResolveErr: map[string]string{}, Routes: map[netip.Addr]env.Route{}}
	tunnels := map[string]bool{}
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		tunnels[i.Name] = true
	}
	for k := range e.Ifaces {
		i := &e.Ifaces[k]
		i.Physical = i.Name != "lo" && !tunnels[i.Name]
	}
	b.markDefaultRoutes(e.Ifaces)
	boot, err := os.ReadFile(b.path(bootIDFile))
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return env.Env{}, fmt.Errorf("boot id: %v", err)
	}
	e.BootID = strings.TrimSpace(string(boot))
	b.expandTrust(p, &e)
	for _, g := range p.Repair.Programs {
		e.Programs[g] = b.glob(g, "")
	}
	b.resolveEndpoints(p, &e)
	for _, a := range routeTargets(p, e) {
		if r, ok := b.route(a, e, tunnels); ok {
			e.Routes[a] = r
		}
	}
	e.DHCPDNS = b.physicalResolvers(e, tunnels)
	return e, nil
}

func (b *Backend) expandTrust(p policy.Policy, e *env.Env) {
	for _, t := range p.Trust {
		switch t.Kind {
		case policy.KindUser:
			if _, err := strconv.ParseUint(t.Value, 10, 32); err == nil {
				continue
			}
			if uid, err := b.lookupUser(t.Value); err == nil {
				e.Users[t.Value] = uid
			}
		case policy.KindCgroup:
			e.Programs[t.Value] = b.glob(strings.TrimPrefix(t.Value, "/"), cgroupRoot)
		}
	}
}

// glob раскрывает шаблон под base (от корня ФС) и возвращает пути относительно base, со «/».
func (b *Backend) glob(pattern, base string) []string {
	dir := b.path(base)
	matches, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	var out []string
	for _, m := range matches {
		if base == cgroupRoot {
			if fi, err := os.Stat(m); err != nil || !fi.IsDir() {
				continue
			}
		}
		rel, err := filepath.Rel(dir, m)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if base == "" {
			rel = "/" + rel
		}
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

func (b *Backend) resolveEndpoints(p policy.Policy, e *env.Env) {
	for _, ep := range p.Tunnel.Endpoints {
		if _, ok := ep.Addr(); ok {
			continue
		}
		if _, done := e.Resolved[ep.Host]; done {
			continue
		}
		addrs, err := b.resolve(ep.Host)
		if err != nil {
			e.ResolveErr[ep.Host] = err.Error()
			continue
		}
		e.Resolved[ep.Host] = addrs
	}
}

// markDefaultRoutes — есть ли у интерфейса маршрут по умолчанию v4/v6 в любой таблице (`ip -j route show default
// table all`; multipath — по nexthops; unreachable, blackhole, prohibit — нет). Таблицу не прочитать — маршрут
// считается у каждого: пробы check идут, как раньше.
func (b *Backend) markDefaultRoutes(ifaces []env.Iface) {
	for _, v4 := range []bool{true, false} {
		fam := "-6"
		if v4 {
			fam = "-4"
		}
		devs, err := b.defaultDevs(fam)
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

func (b *Backend) defaultDevs(fam string) (map[string]bool, error) {
	out, err := b.run("", "ip", fam, "-j", "route", "show", "default", "table", "all")
	if err != nil {
		return nil, err
	}
	var routes []struct {
		Type     string `json:"type"`
		Dev      string `json:"dev"`
		Nexthops []struct {
			Dev string `json:"dev"`
		} `json:"nexthops"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		return nil, err
	}
	devs := map[string]bool{}
	for _, r := range routes {
		if r.Type != "" && r.Type != "unicast" {
			continue
		}
		devs[r.Dev] = true
		for _, h := range r.Nexthops {
			devs[h.Dev] = true
		}
	}
	delete(devs, "")
	return devs, nil
}

func routeTargets(p policy.Policy, e env.Env) []netip.Addr {
	out := append([]netip.Addr(nil), p.Check.Targets...)
	if p.Health != nil {
		out = append(out, p.Health.Addr.Addr())
	}
	for _, ep := range p.Tunnel.Endpoints {
		if a, ok := ep.Addr(); ok {
			out = append(out, a)
			continue
		}
		out = append(out, e.Resolved[ep.Host]...)
	}
	return out
}

// route — эффективный маршрут `ip -j route get`.
func (b *Backend) route(a netip.Addr, e env.Env, tunnels map[string]bool) (env.Route, bool) {
	out, err := b.run("", "ip", "-j", "route", "get", a.String())
	if err != nil {
		return env.Route{}, false
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal([]byte(out), &routes) != nil || len(routes) == 0 {
		return env.Route{}, false
	}
	for _, i := range e.Ifaces {
		if i.Name == routes[0].Dev {
			return env.Route{IfaceIndex: i.Index, ViaTunnel: tunnels[i.Name]}, true
		}
	}
	return env.Route{}, false
}

// physicalResolvers — nameserver машины без loopback и без тех, чей маршрут идёт через туннель: резолвер, выданный
// туннелем, не должен открываться через физику.
func (b *Backend) physicalResolvers(e env.Env, tunnels map[string]bool) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, a := range b.nameservers() {
		if a.IsLoopback() || seen[a] {
			continue
		}
		seen[a] = true
		if r, ok := b.route(a, e, tunnels); ok && r.ViaTunnel {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func (b *Backend) nameservers() []netip.Addr {
	for _, p := range resolvConfs {
		f, err := os.Open(b.path(p))
		if err != nil {
			continue
		}
		var out []netip.Addr
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, a.WithZone("").Unmap())
			}
		}
		f.Close()
		return out
	}
	return nil
}

// systemIfaces — интерфейсы текущего network namespace; Alias — ifalias из sysfs.
func systemIfaces() ([]env.Iface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]env.Iface, 0, len(list))
	for _, ni := range list {
		i := env.Iface{Name: ni.Name, Index: ni.Index, Up: ni.Flags&net.FlagUp != 0}
		if alias, err := os.ReadFile("/sys/class/net/" + ni.Name + "/ifalias"); err == nil {
			i.Alias = strings.TrimSpace(string(alias))
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ones, _ := n.Mask.Size()
					i.Addrs = append(i.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
				}
			}
		}
		out = append(out, i)
	}
	return out, nil
}

func systemLookupUser(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

func systemResolve(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, err
}
