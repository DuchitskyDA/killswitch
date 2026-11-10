// Package linux — backend nftables: своя таблица `inet killswitch`, загрузка одной транзакцией `nft -f`.
//
// Решение фильтра принимает цепочка postrouting (живой тест в network namespace: sing-box auto_redirect перемаршрутизирует
// пакеты в output, и oifname там — интерфейс до перемаршрутизации). Цепочка output только помечает доверенные соединения
// cgroup битами ct label: `socket cgroupv2` ядро в postrouting не принимает.
package linux

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

const (
	table       = "killswitch"
	denyChain   = "deny"
	restChain   = "rest"
	egressChain = "egress" // пробы check, дошедшие до физического интерфейса: счётчик на порт — признак выхода
)

// Ruleset — план nftables. Render — то, что печатает `plan` и от чего считается хеш.
type Ruleset struct {
	Mode    policy.Mode
	Load    string // скрипт `nft -f` для текущего режима
	Persist string // on.nft: полный on-набор без cgroup, его грузит ранний юнит при загрузке
}

// Render — детерминированный текст плана.
func (r Ruleset) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# killswitch linux: режим %s\n", r.Mode)
	b.WriteString(r.Load)
	if r.Persist == r.Load {
		b.WriteString("# при загрузке (on.nft): тот же набор\n")
	} else {
		b.WriteString("# при загрузке (on.nft):\n")
		b.WriteString(r.Persist)
	}
	return b.String()
}

// Plan — чистая функция: политика и снимок → набор. Ошибки конфига обёрнуты в backend.ErrConfig.
func Plan(p policy.Policy, e env.Env) (Ruleset, error) {
	if p.Mode != policy.ModeOn && p.Mode != policy.ModeOff {
		return Ruleset{}, fmt.Errorf("%w: режим %s на linux не поддерживается", backend.ErrConfig, p.Mode)
	}
	on, err := build(p, e)
	if err != nil {
		return Ruleset{}, err
	}
	persist := on.script(false)
	if p.Mode == policy.ModeOff {
		return Ruleset{Mode: policy.ModeOff, Load: offScript, Persist: persist}, nil
	}
	return Ruleset{Mode: policy.ModeOn, Load: on.script(true), Persist: persist}, nil
}

// offScript — пустая таблица: до перезагрузки ничего не фильтруется, on.nft остаётся полным.
const offScript = "table inet " + table + "\ndelete table inet " + table + "\ntable inet " + table + " {\n}\n"

// fallbackScript — запасной набор раннего юнита, если on.nft не загрузился: только loopback.
const fallbackScript = "table inet " + table + "\ndelete table inet " + table + "\ntable inet " + table + ` {
	chain postrouting {
		type filter hook postrouting priority filter - 10; policy drop;
		oifname "lo" accept
		meta iiftype != loopback fib saddr type != local accept
	}
}
`

// selector — доверенный селектор: выражение nft и назначения (пустая строка — куда угодно).
type selector struct {
	match  string
	cgroup bool     // только в output: socket cgroupv2 ядро в postrouting не принимает
	dests  []string // "" — любое назначение
}

// onSet — on-набор в данных; script печатает его в nft.
type onSet struct {
	tunnels   []string
	selectors []selector
	dns       []string // назначения, к которым DNS 53 разрешён через физику
	lan       []string // назначения LAN (пусто при LAN=false)
}

func build(p policy.Policy, e env.Env) (onSet, error) {
	var s onSet
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		if safe(i.Name) {
			s.tunnels = append(s.tunnels, i.Name)
		}
	}
	sort.Strings(s.tunnels)
	s.tunnels = dedup(s.tunnels)
	endpoints := endpointDests(p.Tunnel.Endpoints, e.Resolved)
	for _, t := range p.Trust {
		sels, err := selectors(t, e)
		if err != nil {
			return onSet{}, err
		}
		dests := []string{""}
		if t.Destinations == policy.DestEndpoints {
			dests = endpoints
		}
		for i := range sels {
			sels[i].dests = dests
		}
		s.selectors = append(s.selectors, sels...)
	}
	permits := p.DNSPermits(e.Health == env.HealthUp)
	var dns []netip.Prefix
	if permits.LAN {
		dns = append(dns, policy.LANPrefixes...)
	}
	if permits.DHCP {
		addrs := append([]netip.Addr(nil), e.DHCPDNS...)
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
		for _, a := range addrs {
			dns = append(dns, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	dns = append(dns, permits.Listed...)
	s.dns = dedup(prefixDests(dns))
	if p.LAN {
		s.lan = prefixDests(append(append([]netip.Prefix(nil), policy.LANPrefixes...), policy.LANMulticast...))
	}
	return s, nil
}

func selectors(t policy.Trust, e env.Env) ([]selector, error) {
	switch t.Kind {
	case policy.KindUser:
		uid, err := userID(t.Value, e.Users)
		if err != nil {
			return nil, err
		}
		return []selector{{match: fmt.Sprintf("meta skuid %d", uid)}}, nil
	case policy.KindMark:
		m, err := markMatch(t.Value)
		if err != nil {
			return nil, err
		}
		return []selector{{match: m}}, nil
	case policy.KindCgroup:
		paths := append([]string(nil), e.Programs[t.Value]...)
		sort.Strings(paths)
		var out []selector
		for _, path := range dedup(paths) {
			path = strings.Trim(path, "/")
			if path == "" || !safe(path) {
				continue
			}
			level := strings.Count(path, "/") + 1
			out = append(out, selector{match: fmt.Sprintf("socket cgroupv2 level %d %q", level, path), cgroup: true})
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: trust %s на linux не поддерживается", backend.ErrConfig, t.Kind)
}

func userID(v string, users map[string]int) (int, error) {
	if uid, err := strconv.ParseUint(v, 10, 32); err == nil {
		return int(uid), nil
	}
	uid, ok := users[v]
	if !ok {
		return 0, fmt.Errorf("%w: trust user %q: пользователь не найден", backend.ErrConfig, v)
	}
	return uid, nil
}

// markMatch: "value" или "value/mask", десятичное или 0x….
func markMatch(v string) (string, error) {
	valStr, maskStr, masked := strings.Cut(v, "/")
	val, err := strconv.ParseUint(valStr, 0, 32)
	if err != nil {
		return "", fmt.Errorf("%w: trust mark %q: нужно число или число/маска", backend.ErrConfig, v)
	}
	if !masked {
		return fmt.Sprintf("meta mark 0x%08x", val), nil
	}
	mask, err := strconv.ParseUint(maskStr, 0, 32)
	if err != nil || mask == 0 {
		return "", fmt.Errorf("%w: trust mark %q: неверная маска", backend.ErrConfig, v)
	}
	return fmt.Sprintf("meta mark and 0x%08x == 0x%08x", mask, val&mask), nil
}

// endpointDests — адрес+порт+протокол серверов туннеля; имена — по снимку. Без адресов — ничего (fail-closed).
func endpointDests(eps []policy.Endpoint, resolved map[string][]netip.Addr) []string {
	var out []string
	for _, ep := range eps {
		addrs := resolved[ep.Host]
		if a, ok := ep.Addr(); ok {
			addrs = []netip.Addr{a}
		}
		for _, a := range addrs {
			out = append(out, fmt.Sprintf("%s daddr %s %s dport %d", family(a), a.Unmap(), ep.Proto, ep.Port))
		}
	}
	return dedup(out)
}

func prefixDests(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		a := p.Addr().Unmap()
		if p.IsSingleIP() {
			out = append(out, fmt.Sprintf("%s daddr %s", family(a), a))
			continue
		}
		out = append(out, fmt.Sprintf("%s daddr %s", family(a), p.Masked()))
	}
	return out
}

func family(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "ip"
	}
	return "ip6"
}

// safe — строку можно вставить в nft в кавычках: без кавычек, обратной косой, пробелов и управляющих.
func safe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == '"' || r == '\\' || r == 0x7f {
			return false
		}
	}
	return true
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// script печатает on-набор; withCgroup=false — для on.nft (раннего юнита).
func (s onSet) script(withCgroup bool) string {
	var sels []selector
	for _, sel := range s.selectors {
		if withCgroup || !sel.cgroup {
			sels = append(sels, sel)
		}
	}
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, "\t\t"+format+"\n", a...) }
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", table, table, table)
	var cgroups []selector
	for _, sel := range sels {
		if sel.cgroup {
			cgroups = append(cgroups, sel)
		}
	}
	checks := labelChecks(cgroups)
	if len(cgroups) > 0 {
		b.WriteString("\tchain output {\n")
		line("type filter hook output priority filter - 10; policy accept;")
		for _, c := range checks {
			// lo — без проверки: ответ локального сервиса доверенному идёт по той же записи conntrack от чужого сокета.
			line(`oifname != "lo" ct label %d ct label %d jump %s`, c.l1, c.l2, c.chain())
		}
		for _, sel := range cgroups {
			l1, l2 := cgroupLabel(sel)
			for _, d := range sel.dests {
				line("%s ct label set %d ct label set %d", join(sel.match, d), l1, l2)
			}
		}
		b.WriteString("\t}\n\n")
	}
	for _, c := range checks {
		fmt.Fprintf(&b, "\tchain %s {\n", c.chain())
		for _, m := range c.matches {
			line("%s return", m)
		}
		line("meta skuid >= 0 counter drop comment \"foreign socket\"")
		b.WriteString("\t}\n\n")
	}
	b.WriteString("\tchain postrouting {\n")
	line("type filter hook postrouting priority filter - 10; policy drop;")
	line(`oifname "lo" accept`)
	line("meta iiftype != loopback fib saddr type != local accept comment \"transit\"")
	for _, t := range s.tunnels {
		line("oifname %q accept", t)
	}
	line("udp sport 68 udp dport 67 accept")
	line("udp sport 546 udp dport 547 accept")
	line("icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, mld-listener-report, mld2-listener-report } accept")
	line("meta l4proto { tcp, udp } th sport %d-%d goto %s comment \"check probes\"", probe.SrcPortFirst, probe.SrcPortLast, egressChain)
	for _, sel := range sels {
		match := sel.match
		if sel.cgroup {
			l1, l2 := cgroupLabel(sel)
			match = fmt.Sprintf("ct label %d ct label %d", l1, l2)
		}
		for _, d := range sel.dests {
			line("%s accept", join(match, d))
		}
	}
	line("goto %s", restChain)
	b.WriteString("\t}\n\n")
	fmt.Fprintf(&b, "\tchain %s {\n", egressChain)
	for port := probe.SrcPortFirst; port <= probe.SrcPortLast; port++ {
		line("meta l4proto { tcp, udp } th sport %d counter comment \"%s\"", port, egressComment(port))
	}
	line("goto %s", restChain)
	b.WriteString("\t}\n\n")
	fmt.Fprintf(&b, "\tchain %s {\n", restChain)
	for _, d := range s.dns {
		line("%s meta l4proto { tcp, udp } th dport 53 accept", d)
	}
	line("meta l4proto { tcp, udp } th dport 53 goto %s", denyChain)
	for _, d := range s.lan {
		line("%s accept", d)
	}
	line("goto %s", denyChain)
	b.WriteString("\t}\n\n")
	fmt.Fprintf(&b, "\tchain %s {\n", denyChain)
	for port := probe.SrcPortFirst; port <= probe.SrcPortLast; port++ {
		line("meta l4proto { tcp, udp } th sport %d counter drop comment \"%s\"", port, probeComment(port))
	}
	line("counter drop comment \"final\"")
	b.WriteString("\t}\n}\n")
	return b.String()
}

// cgroupLabel — два бита ct label доверенного cgroup (64–95 и 96–127) от его пути и назначений. cgroup ядро видит только
// в output, поэтому соединение помечается там и принимается в postrouting по обоим битам и тем же назначениям. Биты
// зависят от селектора: соединение снятого из доверия cgroup по метке оставшихся не проходит, кроме совпадения
// пары битов (≈1/1024 на пару селекторов). user и mark метку не ставят: они проверяются в postrouting напрямую.
func cgroupLabel(sel selector) (int, int) {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%s", sel.match, strings.Join(sel.dests, ","))
	sum := h.Sum64()
	return 64 + int(sum%32), 96 + int((sum>>32)%32)
}

// labelCheck — цепочка проверки одной пары битов ct label. Метка живёт на записи conntrack, а не на сокете: без
// проверки чужой процесс, занявший тот же 5-кортеж, прошёл бы по ней. Пакет соединения с этой меткой должен идти от
// сокета одного из доверенных cgroup пары (`return`), иначе полный сокет отброшен (`meta skuid` есть только у полного
// сокета; пакет без него — TIME_WAIT, RST/ACK ядра — проходит по метке, как раньше). Цепочка — на пару, а не на
// селектор: селекторы с совпавшей парой иначе отбросили бы доверенных друг друга. `socket cgroupv2 … !=` не годится:
// для сокета мельче уровня N выражение не вычисляется и правило не срабатывает.
type labelCheck struct {
	l1, l2  int
	matches []string
}

func (c labelCheck) chain() string { return fmt.Sprintf("cgroup_%d_%d", c.l1, c.l2) }

func labelChecks(cgroups []selector) []labelCheck {
	var out []labelCheck
	index := map[[2]int]int{}
	for _, sel := range cgroups {
		l1, l2 := cgroupLabel(sel)
		i, ok := index[[2]int{l1, l2}]
		if !ok {
			i = len(out)
			index[[2]int{l1, l2}] = i
			out = append(out, labelCheck{l1: l1, l2: l2})
		}
		out[i].matches = dedup(append(out[i].matches, sel.match))
	}
	return out
}

func probeComment(port uint16) string { return fmt.Sprintf("probe %d", port) }

func egressComment(port uint16) string { return fmt.Sprintf("egress %d", port) }

func join(match, dest string) string {
	if dest == "" {
		return match
	}
	return match + " " + dest
}
