package lab

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
)

// Status — итог проверки приёмки.
type Status string

const (
	Pass      Status = "PASS"
	Fail      Status = "FAIL"
	NotTested Status = "NOT_TESTED"
)

// Check — одна проверка приёмки: сценарий × клиент × семейство. Family "-" — проверка без семейства (код выхода,
// хеш правил); она входит в обе ячейки v4 и v6.
type Check struct {
	Scenario string `json:"scenario"`
	Client   string `json:"client"`
	Family   string `json:"family"`
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Log      string `json:"log,omitempty"`
}

// Scenarios — порядок строк таблицы: живые сценарии эпика, 10 (enforce восстанавливает), рев. 6 и открытые вопросы ks-linux.
var Scenarios = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "r6-маршрут", "r6-зомби", "(а)", "(б)", "(в)", "(г)", ScenarioNoDefault}

// Cell — итог ячейки таблицы.
type Cell struct {
	Scenario, Client, Family string
	Status                   Status
	Reasons                  []string // проверки, давшие FAIL или NOT_TESTED
	Log                      string
}

// Summarize сводит проверки в ячейки: хоть одна FAIL — FAIL; иначе хоть одна NOT_TESTED — NOT_TESTED (непроверенная
// проба не прячется за пройденными); иначе PASS.
func Summarize(checks []Check) []Cell {
	type key struct{ s, c, f string }
	cells := map[key]*Cell{}
	order := []key{}
	get := func(k key) *Cell {
		if c, ok := cells[k]; ok {
			return c
		}
		c := &Cell{Scenario: k.s, Client: k.c, Family: k.f}
		cells[k] = c
		order = append(order, k)
		return c
	}
	for _, ch := range checks {
		fams := []string{ch.Family}
		if ch.Family == "-" {
			fams = []string{"v4", "v6"}
		}
		for _, f := range fams {
			c := get(key{ch.Scenario, ch.Client, f})
			if c.Log == "" {
				c.Log = ch.Log
			}
			switch {
			case ch.Status == Fail:
				c.Status = Fail
			case ch.Status == NotTested && c.Status != Fail:
				c.Status = NotTested
			case ch.Status == Pass && c.Status == "":
				c.Status = Pass
			}
			if r := ch.Name + ": " + ch.Detail; ch.Status != Pass && !slices.Contains(c.Reasons, r) {
				c.Reasons = append(c.Reasons, r)
			}
		}
	}
	out := make([]Cell, 0, len(order))
	for _, k := range order {
		out = append(out, *cells[k])
	}
	return out
}

// RenderTable — markdown: строки — сценарии, столбцы — клиент × семейство; ниже — причины FAIL и NOT_TESTED.
func RenderTable(cells []Cell) string {
	var clients []string
	seen := map[string]bool{}
	idx := map[string]Cell{}
	for _, c := range cells {
		if !seen[c.Client] {
			seen[c.Client] = true
			clients = append(clients, c.Client)
		}
		idx[c.Scenario+"|"+c.Client+"|"+c.Family] = c
	}
	sort.Strings(clients)
	var b strings.Builder
	b.WriteString("| сценарий |")
	for _, cl := range clients {
		fmt.Fprintf(&b, " %s v4 | %s v6 |", cl, cl)
	}
	b.WriteString("\n|---|")
	b.WriteString(strings.Repeat("---|---|", len(clients)))
	b.WriteString("\n")
	var notes []string
	for _, s := range Scenarios {
		fmt.Fprintf(&b, "| %s |", s)
		for _, cl := range clients {
			for _, f := range []string{"v4", "v6"} {
				c, ok := idx[s+"|"+cl+"|"+f]
				if !ok {
					b.WriteString(" — |")
					continue
				}
				fmt.Fprintf(&b, " %s |", c.Status)
				if len(c.Reasons) > 0 {
					notes = append(notes, fmt.Sprintf("- %s %s %s (%s): %s", s, cl, f, c.Status, strings.Join(c.Reasons, "; ")))
				}
			}
		}
		b.WriteString("\n")
	}
	if len(notes) > 0 {
		b.WriteString("\nПричины:\n" + strings.Join(notes, "\n") + "\n")
	}
	logs := map[string]string{}
	for _, c := range cells {
		if c.Log != "" && logs[c.Client] == "" {
			logs[c.Client] = c.Log
		}
	}
	b.WriteString("\nЖурналы (относительно каталога прогона):\n")
	for _, cl := range clients {
		fmt.Fprintf(&b, "- %s: %s\n", cl, logs[cl])
	}
	return b.String()
}

// SummaryMain — `kslab summary файлы…`: читает results.json прогонов и печатает таблицу.
func SummaryMain(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("summary: нужны файлы results.json")
	}
	var all []Check
	for _, p := range fs.Args() {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var cs []Check
		if err := json.Unmarshal(data, &cs); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		all = append(all, cs...)
	}
	fmt.Fprint(out, RenderTable(Summarize(all)))
	return nil
}

// ClientDef — клиент туннеля в приёмке: как его доверяет killswitch и как его зовут интерфейсы.
type ClientDef struct {
	Name      string
	Profile   string    // встроенный профиль; "" — без профиля
	Ifaces    [2]string // интерфейс туннеля до и после переподключения (сценарий 4)
	Patterns  []string  // [tunnel] interfaces в конфиге; nil — из профиля
	Endpoints []string  // сервер туннеля "адрес:порт/протокол" (strict)
	Cgroup    bool      // доверие по cgroup (путь задаёт раннер)
	Redirect  bool      // sing-box auto_route + auto_redirect
	DirectUID int       // uid прямых проб «программы»; 0 — NobodyUID
}

// Clients — клиенты приёмки. Имена TUN подобраны под шаблоны профилей, чтобы проверялся профиль как есть.
var Clients = map[string]ClientDef{
	"wireguard": {Name: "wireguard", Profile: "wireguard", Ifaces: [2]string{"wg0", "wg1"},
		Endpoints: []string{fmt.Sprintf("%s:%d/udp", topo.PeerV4, topo.WGServerPort)}},
	"sing-box": {Name: "sing-box", Profile: "sing-box", Ifaces: [2]string{"tun0", "tun1"},
		Endpoints: proxyEndpoints(topo.SingBoxPort)},
	"sing-box-ar": {Name: "sing-box-ar", Profile: "sing-box", Ifaces: [2]string{"tun0", "tun1"},
		Endpoints: proxyEndpoints(topo.SingBoxPort), Redirect: true, DirectUID: topo.BypassUID},
	"xray": {Name: "xray", Ifaces: [2]string{"kxr0", "kxr1"}, Patterns: []string{"kxr*"},
		Endpoints: proxyEndpoints(topo.XrayPort), Cgroup: true},
}

func proxyEndpoints(port uint16) []string {
	return []string{fmt.Sprintf("%s:%d/tcp", topo.PeerV4, port), fmt.Sprintf("%s:%d/udp", topo.PeerV4, port)}
}

// ConfigOpts — вариант конфига killswitch для этапа приёмки.
type ConfigOpts struct {
	Strict         bool
	TunnelUpDNS    bool     // dns.mode = tunnel-up, dns.health через туннель к «интернету»
	CgroupPath     string   // путь доверенного cgroup относительно /sys/fs/cgroup (xray)
	ExtraEndpoints []string // дополнительные endpoints strict (проверка (а))
}

// HealthURL — dns.health приёмки: HTTP «интернет»-хоста, отвечает только через живой туннель.
var HealthURL = fmt.Sprintf("http://%s:%d/", topo.InetV4, topo.HTTPPort)

// Config — config.toml killswitch для клиента и варианта.
func (c ClientDef) Config(o ConfigOpts) string {
	var b strings.Builder
	if c.Profile != "" {
		fmt.Fprintf(&b, "profile = %q\n", c.Profile)
	}
	if o.Strict {
		b.WriteString("trust_mode = \"strict\"\n")
	}
	b.WriteString("\n[tunnel]\n")
	if c.Patterns != nil {
		fmt.Fprintf(&b, "interfaces = %s\n", tomlList(c.Patterns))
	}
	if o.Strict {
		fmt.Fprintf(&b, "endpoints = %s\n", tomlList(append(append([]string{}, c.Endpoints...), o.ExtraEndpoints...)))
	}
	if c.Cgroup && o.CgroupPath != "" {
		fmt.Fprintf(&b, "\n[[trust]]\nkind = \"cgroup\"\nvalue = %q\n", o.CgroupPath)
	}
	if o.TunnelUpDNS {
		fmt.Fprintf(&b, "\n[dns]\nmode = \"tunnel-up\"\nhealth = %q\n", HealthURL)
	}
	fmt.Fprintf(&b, "\n[check]\ntargets = %s\n", tomlList([]string{topo.InetV4.String(), topo.InetV6.String()}))
	return b.String()
}

func tomlList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// ExecStart достаёт команду ExecStart= из текста юнита и разбирает её как systemd: слова через пробел,
// одинарные и двойные кавычки группируют. Нет строки — ошибка.
func ExecStart(unit string) ([]string, error) {
	for _, line := range strings.Split(unit, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart=")
		if !ok {
			continue
		}
		var argv []string
		var cur strings.Builder
		var quote rune
		inWord := false
		for _, r := range v {
			switch {
			case quote != 0 && r == quote:
				quote = 0
			case quote != 0:
				cur.WriteRune(r)
			case r == '\'' || r == '"':
				quote, inWord = r, true
			case r == ' ' || r == '\t':
				if inWord {
					argv = append(argv, cur.String())
					cur.Reset()
					inWord = false
				}
			default:
				cur.WriteRune(r)
				inWord = true
			}
		}
		if quote != 0 {
			return nil, fmt.Errorf("ExecStart: незакрытая кавычка: %s", v)
		}
		if inWord {
			argv = append(argv, cur.String())
		}
		if len(argv) == 0 {
			return nil, errors.New("ExecStart пуст")
		}
		return argv, nil
	}
	return nil, errors.New("в юните нет ExecStart=")
}

// StripTable убирает из листинга `nft list ruleset` блок одной таблицы ("inet killswitch"): сценарий 6 сверяет
// всё остальное с состоянием до on.
func StripTable(listing, name string) string {
	var b strings.Builder
	skip := false
	for _, line := range strings.SplitAfter(listing, "\n") {
		switch {
		case !skip && strings.HasPrefix(line, "table "+name+" {"):
			skip = true
		case skip && strings.HasPrefix(line, "}"):
			skip = false
		case !skip:
			b.WriteString(line)
		}
	}
	return b.String()
}

// SingBoxClient — клиент sing-box для приёмки: TUN iface → shadowsocks 2022. redirect — auto_route + auto_redirect
// (маршруты и nft ставит сам sing-box); direct — правило «HTTP «интернета» v4 → direct» (рев. 6: прямой маршрут).
func SingBoxClient(password, iface string, redirect, direct bool) ([]byte, error) {
	tun := map[string]any{
		"type": "tun", "tag": "tun-in", "interface_name": iface,
		"address": []string{"198.18.1.1/30", "2001:db8:ffff:1::1/126"}, "mtu": 1500, "auto_route": redirect,
	}
	out := map[string]any{
		"type": "shadowsocks", "tag": "ss-out", "server": topo.PeerV4.String(), "server_port": topo.SingBoxPort,
		"method": topo.ProxyMethod, "password": password,
	}
	route := map[string]any{"final": "ss-out"}
	if redirect {
		tun["auto_redirect"], tun["strict_route"] = true, false
		tun["exclude_uid"] = []int{topo.BypassUID}
		route["auto_detect_interface"] = true
	} else {
		out["bind_interface"] = topo.PhysIf
	}
	outbounds := []any{out}
	if direct {
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct", "bind_interface": topo.PhysIf})
		route["rules"] = []any{map[string]any{"ip_cidr": []string{topo.InetV4.String() + "/32"}, "port": []int{topo.HTTPPort},
			"outbound": "direct"}}
	}
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true}, "inbounds": []any{tun}, "outbounds": outbounds, "route": route,
	}, "", "  ")
}

// XrayClient — клиент xray для приёмки: собственный TUN iface → shadowsocks 2022, исходящий привязан к c0.
func XrayClient(password, iface string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"port": 0, "protocol": "tun", "tag": "tun",
			"settings": map[string]any{"name": iface, "mtu": 1500}}},
		"outbounds": []any{map[string]any{
			"protocol": "shadowsocks", "tag": "ss-out",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": topo.PeerV4.String(), "port": topo.XrayPort, "method": topo.ProxyMethod, "password": password,
			}}},
			"streamSettings": map[string]any{"sockopt": map[string]any{"interface": topo.PhysIf}},
		}},
	}, "", "  ")
}

// ScenarioNoDefault — ks-probe (в): физический интерфейс без маршрута по умолчанию check пропускает с пометкой.
const ScenarioNoDefault = "без default"

// RedirectCheckOK — (б): при перенаправлении клиента (sing-box auto_redirect) check даёт 0 или 5 по правилам ks-probe
// (перехваченная проба — SKIPPED, baseline без маршрута через туннель — INCONCLUSIVE), но не ложный LEAK.
func RedirectCheckOK(out string, code int) bool {
	if code != 0 && code != 5 {
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "LEAK") {
			return false
		}
	}
	return true
}
