package linux

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

var update = flag.Bool("update", false, "переписать эталоны testdata/*.nft")

func basePolicy() policy.Policy {
	return policy.Policy{Mode: policy.ModeOn, LAN: true, DNS: policy.DNSOpen, TrustMode: policy.TrustCompat,
		Tunnel: policy.Tunnel{Interfaces: []string{"wg*"}}}
}

func baseEnv() env.Env {
	return env.Env{OS: "linux", BootID: "b1",
		Ifaces: []env.Iface{
			{Name: "lo", Index: 1, Up: true},
			{Name: "eth0", Index: 2, Up: true, Physical: true},
			{Name: "wg0", Index: 3, Up: true},
		},
		DHCPDNS: []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("203.0.113.53")},
		Users:   map[string]int{"sing-box": 990},
		Programs: map[string][]string{
			"system.slice/sing-box*.service": {"system.slice/sing-box.service"},
		},
		Resolved: map[string][]netip.Addr{"tunnel.example": {netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}},
	}
}

func strictEndpoints(p policy.Policy) policy.Policy {
	p.TrustMode = policy.TrustStrict
	p.Tunnel.Endpoints = []policy.Endpoint{
		{Host: "198.51.100.10", Port: 51820, Proto: policy.ProtoUDP},
		{Host: "tunnel.example", Port: 443, Proto: policy.ProtoTCP},
	}
	return p
}

// Эталоны по строкам матрицы: имя файла testdata/<имя>.nft.
func TestRenderMatrix(t *testing.T) {
	rows := []struct {
		name string
		p    func(policy.Policy) policy.Policy
		e    func(env.Env) env.Env
	}{
		{"on-minimal", nil, nil},
		{"on-lan-false", func(p policy.Policy) policy.Policy { p.LAN = false; return p }, nil},
		{"on-dns-tunnel-up-down", func(p policy.Policy) policy.Policy { p.DNS = policy.DNSTunnelUp; return p },
			func(e env.Env) env.Env { e.Health = env.HealthDown; return e }},
		{"on-dns-tunnel-up-up", func(p policy.Policy) policy.Policy { p.DNS = policy.DNSTunnelUp; return p },
			func(e env.Env) env.Env { e.Health = env.HealthUp; return e }},
		{"on-dns-resolvers", func(p policy.Policy) policy.Policy {
			p.DNS = policy.DNSResolvers
			p.Resolvers = []netip.Prefix{netip.MustParsePrefix("9.9.9.9/32"), netip.MustParsePrefix("2620:fe::/48")}
			return p
		}, nil},
		{"on-trust-compat", func(p policy.Policy) policy.Policy {
			p.Trust = []policy.Trust{
				{Kind: policy.KindUser, Value: "sing-box", Destinations: policy.DestAny},
				{Kind: policy.KindCgroup, Value: "system.slice/sing-box*.service", Destinations: policy.DestAny},
				{Kind: policy.KindMark, Value: "0xca6c", Destinations: policy.DestAny},
			}
			return p
		}, nil},
		{"on-trust-strict", func(p policy.Policy) policy.Policy {
			p = strictEndpoints(p)
			p.Trust = []policy.Trust{
				{Kind: policy.KindUser, Value: "0", Destinations: policy.DestEndpoints},
				{Kind: policy.KindMark, Value: "0x1/0xff", Destinations: policy.DestEndpoints},
			}
			return p
		}, nil},
		{"on-no-tunnel", nil, func(e env.Env) env.Env { e.Ifaces = e.Ifaces[:2]; return e }},
		{"off", func(p policy.Policy) policy.Policy { p.Mode = policy.ModeOff; return p }, nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			p, e := basePolicy(), baseEnv()
			if row.p != nil {
				p = row.p(p)
			}
			if row.e != nil {
				e = row.e(e)
			}
			r, err := Plan(p, e)
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			golden(t, filepath.Join("testdata", row.name+".nft"), r.Render())
		})
	}
}

func golden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("эталон: %v (запусти с -update)", err)
	}
	if got != string(want) {
		t.Errorf("Render не совпал с %s:\n%s", path, got)
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	p := strictEndpoints(basePolicy())
	p.Trust = []policy.Trust{{Kind: policy.KindUser, Value: "sing-box", Destinations: policy.DestEndpoints}}
	a, _ := Plan(p, baseEnv())
	b, _ := Plan(p, baseEnv())
	if backend.HashOf(a) != backend.HashOf(b) {
		t.Fatal("два плана одной политики разошлись")
	}
}

// on.nft не содержит cgroup: при загрузке пути ещё нет, а несуществующий путь роняет всю транзакцию.
func TestPersistOmitsCgroup(t *testing.T) {
	p := basePolicy()
	p.Trust = []policy.Trust{{Kind: policy.KindCgroup, Value: "system.slice/sing-box*.service", Destinations: policy.DestAny}}
	r, err := Plan(p, baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Load, "socket cgroupv2 level 2 \"system.slice/sing-box.service\"") {
		t.Error("в текущем наборе нет правила cgroup")
	}
	if strings.Contains(r.Persist, "cgroupv2") {
		t.Error("on.nft содержит cgroup")
	}
}

func TestOffPersistsOnSet(t *testing.T) {
	p := basePolicy()
	on, _ := Plan(p, baseEnv())
	off, err := Plan(p.WithMode(policy.ModeOff), baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	if off.Persist != on.Persist {
		t.Error("off должен держать в on.nft полный on-набор")
	}
	if strings.Contains(off.Load, "chain") {
		t.Errorf("off грузит не пустую таблицу:\n%s", off.Load)
	}
}

func TestPlanConfigErrors(t *testing.T) {
	cases := []struct {
		name  string
		trust policy.Trust
		mode  policy.Mode
	}{
		{"неизвестный пользователь", policy.Trust{Kind: policy.KindUser, Value: "nobody-here", Destinations: policy.DestAny}, policy.ModeOn},
		{"плохая метка", policy.Trust{Kind: policy.KindMark, Value: "0xzz", Destinations: policy.DestAny}, policy.ModeOn},
		{"программа", policy.Trust{Kind: policy.KindProgram, Value: "/usr/bin/x", Destinations: policy.DestAny}, policy.ModeOn},
		{"repair", policy.Trust{Kind: policy.KindUser, Value: "0", Destinations: policy.DestAny}, policy.ModeRepair},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := basePolicy().WithMode(c.mode)
			p.Trust = []policy.Trust{c.trust}
			if _, err := Plan(p, baseEnv()); !errors.Is(err, backend.ErrConfig) {
				t.Fatalf("ждали ErrConfig, получили %v", err)
			}
		})
	}
}

// Имя интерфейса или путь cgroup с кавычкой не попадает в nft-текст (fail-closed: правило не ставится).
func TestUnsafeNamesSkipped(t *testing.T) {
	p := basePolicy()
	p.Trust = []policy.Trust{{Kind: policy.KindCgroup, Value: "x*", Destinations: policy.DestAny}}
	e := baseEnv()
	e.Ifaces = append(e.Ifaces, env.Iface{Name: `wg"x`, Index: 9, Up: true})
	e.Programs = map[string][]string{"x*": {`x"y`}}
	r, err := Plan(p, e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Load, `x"`) {
		t.Errorf("небезопасное имя попало в набор:\n%s", r.Load)
	}
}

// Ужесточение доверия (A8): метку соединения ставит только cgroup (его ядро в postrouting не видит); user и mark
// проверяются в postrouting напрямую, поэтому снятое доверие к ним не переживает смену набора.
func TestOnlyCgroupCarriesLabel(t *testing.T) {
	p := basePolicy()
	p.Trust = []policy.Trust{
		{Kind: policy.KindUser, Value: "0", Destinations: policy.DestAny},
		{Kind: policy.KindMark, Value: "0xca6c", Destinations: policy.DestAny},
	}
	r, _ := Plan(p, baseEnv())
	if strings.Contains(r.Load, "ct label") {
		t.Fatalf("user/mark ставят или принимают метку:\n%s", r.Load)
	}
}

// Метка cgroup — два бита от селектора и назначений; приём требует оба и ограничен назначениями.
func TestCgroupLabelPerSelector(t *testing.T) {
	cg := func(dest policy.Destinations) policy.Policy {
		p := strictEndpoints(basePolicy())
		if dest == policy.DestAny {
			p = basePolicy()
		}
		p.Trust = []policy.Trust{{Kind: policy.KindCgroup, Value: "system.slice/sing-box*.service", Destinations: dest}}
		return p
	}
	a, _ := Plan(cg(policy.DestAny), baseEnv())
	b, _ := Plan(cg(policy.DestEndpoints), baseEnv())
	la, lb := labelAccepts(a.Load), labelAccepts(b.Load)
	if len(la) != 1 || len(lb) == 0 || labelOf(la[0]) == labelOf(lb[0]) {
		t.Fatalf("метки не различаются: any %v, endpoints %v", la, lb)
	}
	for _, l := range lb {
		if !strings.Contains(l, " daddr ") {
			t.Errorf("приём по метке без назначения: %q", l)
		}
	}
}

func labelOf(rule string) string {
	f := strings.Fields(rule)
	return f[2] + "," + f[5]
}

func labelAccepts(script string) []string {
	var out []string
	for _, line := range strings.Split(script, "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "ct label ") && strings.HasSuffix(l, " accept") {
			out = append(out, l)
		}
	}
	return out
}
