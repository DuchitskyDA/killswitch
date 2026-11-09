// Package darwin — backend macOS: pf-якорь com.apple/000.killswitch (рев. 3), LaunchDaemon-наблюдатель.
package darwin

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// Anchor — наш якорь: дочерний com.apple/*, сортируется раньше системных соседей.
const Anchor = "com.apple/000.killswitch"

const (
	canaryLabel = "killswitch-canary"
	canaryAddr  = "127.0.0.1"
	canaryPort  = 9
	headerMode  = "# killswitch mode="
)

// Rules — план якоря: текст для `pfctl -a Anchor -f`. Комментарии pf отбрасывает при загрузке.
type Rules struct {
	Mode policy.Mode
	Text string
}

// Render — детерминированный текст якоря.
func (r Rules) Render() string { return r.Text }

// probeLabel — label block-правила пробы: его счётчик — свидетельство отброса (рев. 5).
func probeLabel(proto string, port uint16) string {
	return fmt.Sprintf("killswitch-probe-%s-%d", proto, port)
}

// Plan — чистая функция: политика и снимок → текст якоря.
func Plan(p policy.Policy, e env.Env) (backend.Ruleset, error) {
	switch p.Mode {
	case policy.ModeOn:
		return Rules{Mode: p.Mode, Text: renderOn(p, e)}, nil
	case policy.ModeOff:
		return Rules{Mode: p.Mode, Text: headerMode + "off\n# якорь пуст: защита снята до перезагрузки\n"}, nil
	}
	return nil, fmt.Errorf("%w: режим %q не поддерживается на macOS", backend.ErrConfig, p.Mode)
}

type writer struct{ b strings.Builder }

func (w *writer) line(format string, args ...any) { fmt.Fprintf(&w.b, format+"\n", args...) }

func renderOn(p policy.Policy, e env.Env) string {
	var w writer
	w.line("%son", headerMode)
	w.line("# pf-якорь %s: блок всего исходящего, кроме перечисленного; все pass без состояния", Anchor)
	w.line("pass out quick on lo0 proto udp from any to %s port %d no state label %q", canaryAddr, canaryPort, canaryLabel)
	w.line("pass out quick on lo0 all no state")
	renderTunnel(&w, p, e)
	w.line("# служебное: DHCPv4, DHCPv6, NDP, ICMPv6 PMTU")
	w.line("pass out quick inet proto udp from any port 68 to any port 67 no state")
	w.line("pass out quick inet6 proto udp from any port 546 to any port 547 no state")
	w.line("pass out quick inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, toobig } no state")
	w.line("# пробы check: выше доверенных, DNS и LAN — отброс считается правилом своего порта-источника;")
	w.line("# порты проб ниже эфемерных, обычный и доверенный трафик в них не попадает")
	renderProbes(&w)
	renderTrust(&w, p, e)
	renderDNS(&w, p, e)
	if p.LAN {
		w.line("# LAN: разрешённые назначения, а не доказанная локальная сеть")
		w.line("pass out quick from any to %s no state", list(prefixStrings(policy.LANPrefixes)))
		w.line("pass out quick from any to %s no state", list(prefixStrings(policy.LANMulticast)))
	}
	w.line("# всё остальное")
	w.line("block return out quick all")
	return w.b.String()
}

// ifaceName — имена, которые безопасно подставить в правило pf.
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

func renderTunnel(w *writer, p policy.Policy, e env.Env) {
	var names []string
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		if ifaceName.MatchString(i.Name) {
			names = append(names, i.Name)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	w.line("# туннель (точные имена по шаблонам %s)", strings.Join(p.Tunnel.Interfaces, ", "))
	if len(names) == 0 {
		w.line("# совпавших интерфейсов нет: туннель закрыт до перепланирования")
	}
	for _, n := range names {
		w.line("pass out quick on %s all no state", n)
	}
}

// renderTrust — доверенные пользователи: pf знает владельца только у TCP и UDP (рев. 6),
// поэтому ICMP и фрагменты доверенного блокируются.
func renderTrust(w *writer, p policy.Policy, e env.Env) {
	if len(p.Trust) == 0 {
		return
	}
	w.line("# доверенные пользователи: только TCP и UDP")
	for _, t := range p.Trust {
		uid, ok := lookupUID(t.Value, e.Users)
		if !ok {
			w.line("# пользователь %q не найден: исключение не действует", t.Value)
			continue
		}
		if t.Destinations == policy.DestAny {
			w.line("pass out quick proto { tcp udp } user %d no state", uid)
			continue
		}
		for _, ep := range p.Tunnel.Endpoints {
			addrs := endpointAddrs(ep, e)
			if len(addrs) == 0 {
				w.line("# endpoint %s: адресов нет, к нему ничего не разрешено", ep)
			}
			for _, a := range addrs {
				w.line("pass out quick %s proto %s from any to %s port %d user %d no state", family(a), ep.Proto, a, ep.Port, uid)
			}
		}
	}
}

func lookupUID(value string, users map[string]int) (int, bool) {
	if uid, err := strconv.Atoi(value); err == nil && uid >= 0 {
		return uid, true
	}
	uid, ok := users[value]
	return uid, ok
}

func endpointAddrs(ep policy.Endpoint, e env.Env) []netip.Addr {
	if a, ok := ep.Addr(); ok {
		return []netip.Addr{a.Unmap()}
	}
	return sortedAddrs(e.Resolved[ep.Host])
}

// renderDNS — TCP/UDP 53 на физике по матрице A11 стоят выше LAN: LAN сам по себе 53 не открывает.
func renderDNS(w *writer, p policy.Policy, e env.Env) {
	d := p.DNSPermits(e.Health == env.HealthUp)
	w.line("# DNS (TCP и UDP 53): режим %s, туннель %s", p.DNS, healthWord(e.Health))
	if d.LAN {
		w.line("pass out quick proto { tcp udp } from any to %s port 53 no state", list(prefixStrings(policy.LANPrefixes)))
	}
	if dhcp := sortedAddrs(e.DHCPDNS); d.DHCP && len(dhcp) > 0 {
		w.line("pass out quick proto { tcp udp } from any to %s port 53 no state", list(addrStrings(dhcp)))
	}
	if len(d.Listed) > 0 {
		w.line("pass out quick proto { tcp udp } from any to %s port 53 no state", list(prefixStrings(d.Listed)))
	}
	w.line("block return out quick proto { tcp udp } from any to any port 53")
}

// renderProbes — block-правила портов-источников проб с label (рев. 5): счётчик label — свидетельство отброса.
func renderProbes(w *writer) {
	for port := probe.SrcPortFirst; port <= probe.SrcPortLast; port++ {
		for _, proto := range []string{"tcp", "udp"} {
			w.line("block return out quick proto %s from any port %d to any label %q", proto, port, probeLabel(proto, port))
		}
	}
}

func healthWord(h env.HealthState) string {
	if h == env.HealthUp {
		return "up"
	}
	return "down"
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "inet"
	}
	return "inet6"
}

func sortedAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		out = append(out, a.Unmap().WithZone(""))
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

func addrStrings(in []netip.Addr) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = a.String()
	}
	return out
}

func prefixStrings(in []netip.Prefix) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = p.String()
	}
	return out
}

// list — список pf: одно значение без скобок, несколько — `{ a, b }`.
func list(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "{ " + strings.Join(items, ", ") + " }"
}
