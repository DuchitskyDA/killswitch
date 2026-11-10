// Package lab — сценарий спайка: топология, туннели, baseline, пробная политика nft и классификация.
package lab

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/DuchitskyDA/killswitch/lab/internal/probe"
	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
)

// Probe — одна проба матрицы.
type Probe struct {
	Name     string
	Kind     probe.Kind
	Family   int
	Port     uint16
	Proto    string
	NoServer bool // контроль: сервера нет, ждём INCONCLUSIVE
}

func (p Probe) Dst() netip.Addr { return topo.Inet(p.Family) }

// ServiceProbes — сервисы «интернета»: v4, v6, TCP, UDP/443, DNS TCP/UDP 53.
var ServiceProbes = []Probe{
	{"tcp4/80 http", probe.HTTP, 4, topo.HTTPPort, "tcp", false},
	{"tcp6/80 http", probe.HTTP, 6, topo.HTTPPort, "tcp", false},
	{"udp4/443", probe.UDP, 4, topo.UDPPort, "udp", false},
	{"udp6/443", probe.UDP, 6, topo.UDPPort, "udp", false},
	{"dns-udp4/53", probe.DNSUDP, 4, topo.DNSPort, "udp", false},
	{"dns-tcp4/53", probe.DNSTCP, 4, topo.DNSPort, "tcp", false},
	{"dns-udp6/53", probe.DNSUDP, 6, topo.DNSPort, "udp", false},
	{"dns-tcp6/53", probe.DNSTCP, 6, topo.DNSPort, "tcp", false},
}

// ControlProbes — порты без сервера.
var ControlProbes = []Probe{
	{"tcp4/81 нет сервера", probe.HTTP, 4, topo.NoServerTCP, "tcp", true},
	{"udp4/444 нет сервера", probe.UDP, 4, topo.NoServerUDP, "udp", true},
}

// DirectProbes — пробы мимо туннеля через физический интерфейс.
func DirectProbes() []Probe { return append(append([]Probe{}, ServiceProbes...), ControlProbes...) }

// Endpoint — сервер туннеля: адрес, порт, протокол.
type Endpoint struct {
	Addr  netip.Addr
	Port  uint16
	Proto string
}

// NaivePolicy — пробная политика nft для ns клиента: drop всего в output, кроме lo и интерфейса туннеля;
// endpoints (P2) дополнительно открывают транспорт туннеля к его серверу.
func NaivePolicy(tunIface string, endpoints []Endpoint) string {
	var b strings.Builder
	b.WriteString("table inet ksl_probe\ndelete table inet ksl_probe\n")
	b.WriteString("table inet ksl_probe {\n\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority filter - 10; policy drop;\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	fmt.Fprintf(&b, "\t\toifname %q accept\n", tunIface)
	for _, e := range endpoints {
		fam := "ip"
		if e.Addr.Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "\t\t%s daddr %s %s dport %d accept\n", fam, e.Addr, e.Proto, e.Port)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// SingBoxConfigs — сервер (ksl-peer) и клиент (ksl-client) sing-box: TUN → shadowsocks 2022 → direct.
func SingBoxConfigs(password string) (server, client []byte, err error) {
	srv := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "shadowsocks", "tag": "ss-in", "listen": "::", "listen_port": topo.SingBoxPort,
			"method": topo.ProxyMethod, "password": password,
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	cli := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": "ksb0",
			"address":    []string{"198.18.1.1/30", "2001:db8:ffff:1::1/126"},
			"mtu":        1500,
			"auto_route": false,
		}},
		"outbounds": []any{map[string]any{
			"type": "shadowsocks", "tag": "ss-out", "server": topo.PeerV4.String(), "server_port": topo.SingBoxPort,
			"method": topo.ProxyMethod, "password": password, "bind_interface": topo.PhysIf,
		}},
		"route": map[string]any{"final": "ss-out"},
	}
	if server, err = json.MarshalIndent(srv, "", "  "); err != nil {
		return nil, nil, err
	}
	client, err = json.MarshalIndent(cli, "", "  ")
	return server, client, err
}

// InetSubnetV4 — линия «интернет»-хоста за маршрутизатором.
const InetSubnetV4 = "203.0.113.128/25"

// XrayConfigs — сервер и клиент xray: собственный TUN-inbound → shadowsocks 2022 → freedom.
func XrayConfigs(password string) (server, client []byte, err error) {
	srv := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "::", "port": topo.XrayPort, "protocol": "shadowsocks", "tag": "ss-in",
			"settings": map[string]any{"method": topo.ProxyMethod, "password": password, "network": "tcp,udp"},
		}},
		// freedom в xray 26.x для shadowsocks-входа по умолчанию блокирует geoip:private, куда входит TEST-NET-3:
		// без явного allow v4-«интернет» лаборатории недостижим (v6 2001:db8::/32 в список не входит).
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{
			"finalRules": []any{map[string]any{"action": "allow", "ip": []string{InetSubnetV4}}},
		}}},
	}
	cli := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"port": 0, "protocol": "tun", "tag": "tun",
			"settings": map[string]any{"name": "kxr0", "mtu": 1500},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "shadowsocks", "tag": "ss-out",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": topo.PeerV4.String(), "port": topo.XrayPort, "method": topo.ProxyMethod, "password": password,
			}}},
			"streamSettings": map[string]any{"sockopt": map[string]any{"interface": topo.PhysIf}},
		}},
	}
	if server, err = json.MarshalIndent(srv, "", "  "); err != nil {
		return nil, nil, err
	}
	client, err = json.MarshalIndent(cli, "", "  ")
	return server, client, err
}
