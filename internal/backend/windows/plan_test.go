package windows

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

var update = flag.Bool("update", false, "переписать эталоны testdata/*.golden")

const happApp = `\device\harddiskvolume3\program files\happ\happ.exe`

func basePolicy(mode policy.Mode) policy.Policy {
	return policy.Policy{
		Mode:      mode,
		LAN:       true,
		DNS:       policy.DNSOpen,
		TrustMode: policy.TrustCompat,
		Tunnel:    policy.Tunnel{Interfaces: []string{"happ-tun"}},
		Trust:     []policy.Trust{{Kind: policy.KindProgram, Value: `C:\Program Files\Happ\happ.exe`, Destinations: policy.DestAny}},
		Repair:    policy.Repair{Programs: []string{`C:\Program Files\Happ\happ.exe`}},
	}
}

func baseEnv() env.Env {
	return env.Env{
		OS: "windows",
		Ifaces: []env.Iface{
			{Name: "Ethernet", Index: 4, LUID: 1688849860263936, Up: true, Physical: true},
			{Name: "happ-tun", Index: 17, LUID: 1689399632478208, Up: true},
		},
		Programs: map[string][]string{`C:\Program Files\Happ\happ.exe`: {happApp}},
		DHCPDNS:  []netip.Addr{netip.MustParseAddr("168.63.129.16"), netip.MustParseAddr("fe80::1")},
		Health:   env.HealthUnknown,
		BootID:   "boot-1",
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("эталон %s: %v (запусти с -update)", path, err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("план расходится с эталоном %s:\n%s", path, got)
	}
}

func plan(t *testing.T, p policy.Policy, e env.Env) Ruleset {
	t.Helper()
	r, err := PlanRules(p, e)
	if err != nil {
		t.Fatalf("план: %v", err)
	}
	return r
}

func TestPlanOnGolden(t *testing.T) {
	golden(t, "on", plan(t, basePolicy(policy.ModeOn), baseEnv()).Render())
}

func TestPlanOffGolden(t *testing.T) {
	golden(t, "off", plan(t, basePolicy(policy.ModeOff), baseEnv()).Render())
}

func TestPlanRepairGolden(t *testing.T) {
	golden(t, "repair", plan(t, basePolicy(policy.ModeRepair), baseEnv()).Render())
}

func TestPlanStrictGolden(t *testing.T) {
	p := basePolicy(policy.ModeOn)
	p.TrustMode, p.LAN = policy.TrustStrict, false
	p.Trust[0].Destinations = policy.DestEndpoints
	p.Tunnel.Endpoints = []policy.Endpoint{{Host: "srv.example", Port: 443, Proto: policy.ProtoTCP},
		{Host: "198.51.100.7", Port: 51820, Proto: policy.ProtoUDP}}
	e := baseEnv()
	e.Resolved = map[string][]netip.Addr{"srv.example": {netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}}
	golden(t, "strict", plan(t, p, e).Render())
}

func TestPlanTunnelUpClosesLANDNS(t *testing.T) {
	p := basePolicy(policy.ModeOn)
	p.DNS = policy.DNSTunnelUp
	e := baseEnv()
	e.Health = env.HealthUp
	golden(t, "tunnel-up", plan(t, p, e).Render())
}

func TestPlanResolversOnlyListed(t *testing.T) {
	p := basePolicy(policy.ModeOn)
	p.DNS, p.LAN = policy.DNSResolvers, false
	p.Resolvers = []netip.Prefix{netip.MustParsePrefix("9.9.9.9/32")}
	golden(t, "resolvers", plan(t, p, baseEnv()).Render())
}

func TestPlanRejectsSvchostTrust(t *testing.T) {
	p := basePolicy(policy.ModeOn)
	p.Trust = []policy.Trust{{Kind: policy.KindProgram, Value: `C:\Windows\System32\SVCHOST.exe`, Destinations: policy.DestAny}}
	_, err := PlanRules(p, baseEnv())
	if !errors.Is(err, backend.ErrConfig) {
		t.Errorf("ожидалась ErrConfig, получено %v", err)
	}
}

func TestPlanTrustWithoutPathsPermitsNothing(t *testing.T) {
	e := baseEnv()
	e.Programs = nil
	r := plan(t, basePolicy(policy.ModeOn), e)
	if strings.Contains(r.Render(), "app-id") {
		t.Errorf("glob без путей не должен давать app-id:\n%s", r.Render())
	}
}

func TestRenderIgnoresOrderAndNames(t *testing.T) {
	r := plan(t, basePolicy(policy.ModeRepair), baseEnv())
	back := Ruleset{Filters: make([]Filter, len(r.Filters))}
	for i, f := range r.Filters {
		f.Name = ""
		for a, b := 0, len(f.Conds)-1; a < b; a, b = a+1, b-1 {
			f.Conds[a], f.Conds[b] = f.Conds[b], f.Conds[a]
		}
		back.Filters[len(r.Filters)-1-i] = f
	}
	if backend.HashOf(back) != backend.HashOf(r) {
		t.Error("набор, прочитанный в другом порядке и без имён, должен давать тот же хеш")
	}
}

func TestModeOfOverlay(t *testing.T) {
	got := [3]policy.Mode{
		ModeOf(plan(t, basePolicy(policy.ModeOn), baseEnv()).Filters),
		ModeOf(plan(t, basePolicy(policy.ModeOff), baseEnv()).Filters),
		ModeOf(plan(t, basePolicy(policy.ModeRepair), baseEnv()).Filters),
	}
	if got != [3]policy.Mode{policy.ModeOn, policy.ModeOff, policy.ModeRepair} {
		t.Errorf("ModeOf: %v", got)
	}
}

func TestKeyDiffersForBootTimeTwin(t *testing.T) {
	f := Filter{Layer: ConnectV4, Action: Block, Weight: WeightBlock, Hard: true, Persistent: true}
	b := f
	b.Persistent, b.BootTime = false, true
	if f.Key() == b.Key() {
		t.Error("persistent и boot-time фильтр с одними условиями должны иметь разные ключи")
	}
}
