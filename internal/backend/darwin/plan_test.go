package darwin

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

func basePolicy() policy.Policy {
	return policy.Policy{Mode: policy.ModeOn, LAN: true, DNS: policy.DNSOpen, TrustMode: policy.TrustCompat,
		Tunnel: policy.Tunnel{Interfaces: []string{"utun*"}},
		Trust:  []policy.Trust{{Kind: policy.KindUser, Value: "runner", Destinations: policy.DestAny}}}
}

func strictPolicy() policy.Policy {
	p := basePolicy()
	p.TrustMode = policy.TrustStrict
	p.Tunnel.Endpoints = []policy.Endpoint{{Host: "203.0.113.7", Port: 443, Proto: policy.ProtoTCP},
		{Host: "srv.example", Port: 51820, Proto: policy.ProtoUDP}}
	p.Trust = []policy.Trust{{Kind: policy.KindUser, Value: "runner", Destinations: policy.DestEndpoints}}
	return p
}

func baseEnv() env.Env {
	return env.Env{OS: "darwin", BootID: "1700000000.000001",
		Ifaces: []env.Iface{
			{Name: "lo0", Index: 1, Up: true},
			{Name: "en0", Index: 6, Up: true, Physical: true, Description: "Wi-Fi",
				Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")}},
			{Name: "utun4", Index: 21, Up: true},
		},
		Users:    map[string]int{"runner": 501},
		Resolved: map[string][]netip.Addr{"srv.example": {netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("198.51.100.7")}},
		DHCPDNS:  []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		Health:   env.HealthUnknown}
}

func render(t *testing.T, p policy.Policy, e env.Env) string {
	t.Helper()
	r, err := Plan(p, e)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return r.Render()
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
		t.Fatalf("эталон %s: %v (перепишите с -update)", path, err)
	}
	if got != string(want) {
		t.Errorf("Render расходится с %s:\n%s", path, got)
	}
}

func TestRenderOnCompatGolden(t *testing.T) {
	golden(t, "on-compat", render(t, basePolicy(), baseEnv()))
}

func TestRenderOnStrictGolden(t *testing.T) {
	golden(t, "on-strict", render(t, strictPolicy(), baseEnv()))
}

func TestRenderOffGolden(t *testing.T) {
	golden(t, "off", render(t, basePolicy().WithMode(policy.ModeOff), baseEnv()))
}

func TestRenderTunnelUpHealthyClosesDNSToLAN(t *testing.T) {
	p := basePolicy()
	p.DNS = policy.DNSTunnelUp
	e := baseEnv()
	e.Health = env.HealthUp
	got := render(t, p, e)
	if strings.Contains(got, "port 53 no state") {
		t.Errorf("при поднятом туннеле в tunnel-up DNS на физике не разрешается:\n%s", got)
	}
}

func TestRenderTunnelUpDownKeepsDNSToLAN(t *testing.T) {
	p := basePolicy()
	p.DNS = policy.DNSTunnelUp
	got := render(t, p, baseEnv())
	if !strings.Contains(got, "to 192.168.1.1 port 53 no state") {
		t.Errorf("в состоянии down DNS к DHCP-резолверу открыт:\n%s", got)
	}
}

func TestRenderResolversOnlyListed(t *testing.T) {
	p := basePolicy()
	p.DNS = policy.DNSResolvers
	p.Resolvers = []netip.Prefix{netip.MustParsePrefix("9.9.9.9/32")}
	got := render(t, p, baseEnv())
	dns := linesWith(got, "port 53 no state")
	if len(dns) != 1 || !strings.Contains(dns[0], "to 9.9.9.9/32 port 53") {
		t.Errorf("resolvers: 53 только к перечисленным, получено %q", dns)
	}
}

func TestRenderLANFalseKeepsDNSAndClosesLAN(t *testing.T) {
	p := basePolicy()
	p.LAN = false
	got := render(t, p, baseEnv())
	if strings.Contains(got, "fc00::/7, fe80::/10 } no state") {
		t.Errorf("LAN=false: разрешения LAN быть не должно:\n%s", got)
	}
	if !strings.Contains(got, "fe80::/10 } port 53 no state") {
		t.Errorf("LAN=false: DNS к LAN по матрице A11 остаётся:\n%s", got)
	}
}

// Рев. 6: pf знает владельца только у TCP и UDP — доверенному не разрешаются ICMP и фрагменты.
func TestRenderTrustedUserOnlyTCPAndUDP(t *testing.T) {
	for _, p := range []policy.Policy{basePolicy(), strictPolicy()} {
		for _, l := range linesWith(render(t, p, baseEnv()), " user ") {
			if !(strings.Contains(l, "proto { tcp udp }") || strings.Contains(l, "proto tcp ") || strings.Contains(l, "proto udp ")) ||
				strings.Contains(l, "icmp") || strings.Contains(l, "fragment") {
				t.Errorf("правило доверенного шире TCP/UDP: %q", l)
			}
		}
	}
}

func TestRenderUnknownUserAllowsNothing(t *testing.T) {
	p := basePolicy()
	p.Trust = []policy.Trust{{Kind: policy.KindUser, Value: "ghost", Destinations: policy.DestAny}}
	if got := linesWith(render(t, p, baseEnv()), "pass out quick proto { tcp udp } user"); len(got) != 0 {
		t.Errorf("неизвестный пользователь не должен получить исключение: %q", got)
	}
}

func TestRenderNumericUserWithoutLookup(t *testing.T) {
	p := basePolicy()
	p.Trust = []policy.Trust{{Kind: policy.KindUser, Value: "0", Destinations: policy.DestAny}}
	if got := linesWith(render(t, p, baseEnv()), "user 0 no state"); len(got) != 1 {
		t.Errorf("uid числом — без поиска пользователя, получено %q", got)
	}
}

func TestPlanRepairIsConfigError(t *testing.T) {
	_, err := Plan(basePolicy().WithMode(policy.ModeRepair), baseEnv())
	if !errors.Is(err, backend.ErrConfig) {
		t.Errorf("repair на macOS — ошибка конфига, получено %v", err)
	}
}

func linesWith(text, sub string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, sub) && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Пробы DNS (порт 53) отбрасывает DNS-блок раньше общих правил проб: перед ним нужны свои правила с тем же label.
func TestRenderDNSProbeCountedBeforeDNSBlock(t *testing.T) {
	got := render(t, basePolicy(), baseEnv())
	block := strings.Index(got, "block return out quick proto { tcp udp } from any to any port 53")
	probe := strings.Index(got, `from any port 30000 to any port 53 label "killswitch-probe-udp-30000"`)
	if probe < 0 || block < 0 || probe > block {
		t.Errorf("правило пробы udp 30000 → 53 должно стоять до DNS-блока: проба %d, блок %d", probe, block)
	}
}
