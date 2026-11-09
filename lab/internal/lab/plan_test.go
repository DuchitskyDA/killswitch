package lab

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestNaivePolicy(t *testing.T) {
	p1 := NaivePolicy("wg0", nil)
	want := "table inet ksl_probe\ndelete table inet ksl_probe\ntable inet ksl_probe {\n\tchain output {\n" +
		"\t\ttype filter hook output priority filter - 10; policy drop;\n\t\toifname \"lo\" accept\n" +
		"\t\toifname \"wg0\" accept\n\t}\n}\n"
	if p1 != want {
		t.Fatalf("P1:\n%s\nждали:\n%s", p1, want)
	}
	p2 := NaivePolicy("ksb0", []Endpoint{
		{netip.MustParseAddr("203.0.113.2"), 8388, "tcp"},
		{netip.MustParseAddr("2001:db8:a::2"), 8388, "udp"},
	})
	for _, s := range []string{"ip daddr 203.0.113.2 tcp dport 8388 accept", "ip6 daddr 2001:db8:a::2 udp dport 8388 accept"} {
		if !strings.Contains(p2, s) {
			t.Fatalf("P2 без %q:\n%s", s, p2)
		}
	}
}

func TestClientConfigsBindPhysical(t *testing.T) {
	for name, f := range map[string]func(string) ([]byte, []byte, error){"sing-box": SingBoxConfigs, "xray": XrayConfigs} {
		srv, cli, err := f("AAAAAAAAAAAAAAAAAAAAAA==")
		if err != nil {
			t.Fatal(err)
		}
		var a, b map[string]any
		if json.Unmarshal(srv, &a) != nil || json.Unmarshal(cli, &b) != nil {
			t.Fatalf("%s: неверный JSON", name)
		}
		if !strings.Contains(string(cli), `"c0"`) {
			t.Fatalf("%s: исходящий клиента не привязан к c0 — петля через TUN", name)
		}
		if name == "xray" && !strings.Contains(string(srv), InetSubnetV4) {
			t.Fatal("xray: freedom без allow для «интернета» — v4 через туннель недостижим")
		}
	}
}

func TestDirectProbesCoverMatrix(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range DirectProbes() {
		seen[p.Name] = true
		if p.Dst().Is4() != (p.Family == 4) {
			t.Fatalf("%s: семейство адреса", p.Name)
		}
	}
	for _, n := range []string{"tcp4/80 http", "tcp6/80 http", "udp4/443", "udp6/443", "dns-udp4/53", "dns-tcp4/53",
		"dns-udp6/53", "dns-tcp6/53", "tcp4/81 нет сервера", "udp4/444 нет сервера"} {
		if !seen[n] {
			t.Fatalf("нет пробы %s", n)
		}
	}
}
