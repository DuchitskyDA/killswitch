package linux

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// snapSys — `ip -j route get` и файлы машины для Snapshot.
func snapBackend(t *testing.T, routes map[string]string) *Backend {
	t.Helper()
	root := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/proc/sys/kernel/random/boot_id", "6f1c-boot\n")
	write("/run/systemd/resolve/resolv.conf", "# upstream\nnameserver 192.168.1.1\nnameserver 127.0.0.53\nnameserver 10.8.0.1\nnameserver fe80::1%eth0\n")
	write("/sys/fs/cgroup/system.slice/sing-box.service/cgroup.procs", "")
	write("/sys/fs/cgroup/system.slice/sing-box-extra.service/cgroup.procs", "")
	run := func(_, name string, args ...string) (string, error) {
		if name == "ip" && len(args) == 4 && args[0] == "-j" && args[2] == "get" {
			if dev, ok := routes[args[3]]; ok {
				return `[{"dst":"` + args[3] + `","dev":"` + dev + `","flags":[]}]`, nil
			}
			return "", errors.New("RTNETLINK answers: Network is unreachable")
		}
		return "", errors.New("неожиданная команда " + name + " " + strings.Join(args, " "))
	}
	b := newBackend(root, run, os.Executable, func() bool { return false })
	b.ifaces = func() ([]env.Iface, error) {
		return []env.Iface{{Name: "lo", Index: 1, Up: true}, {Name: "eth0", Index: 2, Up: true}, {Name: "wg0", Index: 3, Up: true}}, nil
	}
	b.lookupUser = func(name string) (int, error) {
		if name == "sing-box" {
			return 990, nil
		}
		return 0, errors.New("unknown user")
	}
	return b
}

func snapPolicy() policy.Policy {
	p := basePolicy()
	h := policy.HealthURL{Addr: netip.MustParseAddrPort("10.8.0.1:80"), Path: "/"}
	p.Health = &h
	p.Trust = []policy.Trust{
		{Kind: policy.KindUser, Value: "sing-box", Destinations: policy.DestAny},
		{Kind: policy.KindCgroup, Value: "/system.slice/sing-box*.service", Destinations: policy.DestAny},
	}
	return p
}

func TestSnapshotPhysicalExcludesLoopbackAndTunnel(t *testing.T) {
	e, err := snapBackend(t, nil).Snapshot(snapPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var phys []string
	for _, i := range e.Ifaces {
		if i.Physical {
			phys = append(phys, i.Name)
		}
	}
	if !reflect.DeepEqual(phys, []string{"eth0"}) || e.BootID != "6f1c-boot" {
		t.Fatalf("физические %v, boot id %q", phys, e.BootID)
	}
}

func TestSnapshotDHCPDNSSkipsLoopbackAndTunnelRouted(t *testing.T) {
	routes := map[string]string{"192.168.1.1": "eth0", "10.8.0.1": "wg0", "fe80::1": "eth0"}
	e, err := snapBackend(t, routes).Snapshot(snapPolicy())
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1")}
	if !reflect.DeepEqual(e.DHCPDNS, want) {
		t.Fatalf("DHCPDNS = %v, ждали %v", e.DHCPDNS, want)
	}
}

func TestSnapshotRouteToHealthViaTunnel(t *testing.T) {
	e, err := snapBackend(t, map[string]string{"10.8.0.1": "wg0"}).Snapshot(snapPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Routes[netip.MustParseAddr("10.8.0.1")]; r != (env.Route{IfaceIndex: 3, ViaTunnel: true}) {
		t.Fatalf("маршрут к dns.health = %+v", r)
	}
}

func TestSnapshotExpandsCgroupGlobAndUsers(t *testing.T) {
	e, err := snapBackend(t, nil).Snapshot(snapPolicy())
	if err != nil {
		t.Fatal(err)
	}
	got := e.Programs["/system.slice/sing-box*.service"]
	want := []string{"system.slice/sing-box-extra.service", "system.slice/sing-box.service"}
	if !reflect.DeepEqual(got, want) || e.Users["sing-box"] != 990 {
		t.Fatalf("cgroup %v, users %v", got, e.Users)
	}
}

func TestSnapshotRequiresBootID(t *testing.T) {
	b := snapBackend(t, nil)
	os.Remove(b.path(bootIDFile))
	if _, err := b.Snapshot(snapPolicy()); err == nil {
		t.Fatal("снимок без boot id")
	}
}

// withDefaults — ответы `ip -4|-6 -j route show default table all`.
func withDefaults(b *Backend, v4, v6 string) *Backend {
	inner := b.run
	b.run = func(stdin, name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "ip -4 -j route show default table all":
			return v4, nil
		case "ip -6 -j route show default table all":
			return v6, nil
		}
		return inner(stdin, name, args...)
	}
	b.ifaces = func() ([]env.Iface, error) {
		return []env.Iface{{Name: "lo", Index: 1, Up: true}, {Name: "eth0", Index: 2, Up: true},
			{Name: "wg0", Index: 3, Up: true}, {Name: "docker0", Index: 4, Up: true}}, nil
	}
	return b
}

func defaultsOf(e env.Env) map[string][2]bool {
	out := map[string][2]bool{}
	for _, i := range e.Ifaces {
		out[i.Name] = [2]bool{i.DefaultRoute4, i.DefaultRoute6}
	}
	return out
}

// (в) Маршрут по умолчанию — по интерфейсу и семейству, из всех таблиц; multipath — по nexthops; unreachable — нет.
func TestSnapshotDefaultRoutesPerFamily(t *testing.T) {
	v4 := `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","flags":[]},{"dst":"default","dev":"wg0","table":"51820","flags":[]}]`
	v6 := `[{"type":"unreachable","dst":"default","dev":"lo","table":"main","flags":[]},` +
		`{"dst":"default","table":"main","nexthops":[{"gateway":"fe80::1","dev":"eth0","weight":1,"flags":[]}],"flags":[]}]`
	e, err := withDefaults(snapBackend(t, nil), v4, v6).Snapshot(snapPolicy())
	if err != nil {
		t.Fatal(err)
	}
	got := defaultsOf(e)
	if got["eth0"] != [2]bool{true, true} || got["docker0"] != [2]bool{false, false} || got["lo"] != [2]bool{false, false} {
		t.Fatalf("маршруты по умолчанию: %v", got)
	}
}

// Таблицу маршрутов не прочитать — физические интерфейсы считаются с маршрутом (пробы идут, как без этого признака).
func TestSnapshotDefaultRoutesUnreadableAssumesRoute(t *testing.T) {
	e, err := snapBackend(t, nil).Snapshot(snapPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultsOf(e); got["eth0"] != [2]bool{true, true} {
		t.Fatalf("маршруты по умолчанию без ip: %v", got)
	}
}

func TestSnapshotRoutesIncludeCheckTargets(t *testing.T) {
	p := snapPolicy()
	p.Check.Targets = []netip.Addr{netip.MustParseAddr("203.0.113.130")}
	e, err := snapBackend(t, map[string]string{"203.0.113.130": "wg0"}).Snapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Routes[netip.MustParseAddr("203.0.113.130")]; r != (env.Route{IfaceIndex: 3, ViaTunnel: true}) {
		t.Fatalf("маршрут к цели check = %+v", r)
	}
}
