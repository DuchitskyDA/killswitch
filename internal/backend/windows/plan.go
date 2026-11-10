package windows

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Порты DHCP: клиент → сервер.
var dhcpPorts = map[bool][2]uint16{true: {68, 67}, false: {546, 547}}

// PlanRules — чистый план (Backend.Plan). Env.Programs: glob → app-id (NT-путь, как вернул FwpmGetAppIdFromFileName0).
func PlanRules(p policy.Policy, e env.Env) (Ruleset, error) {
	if err := noSvchost(p, e); err != nil {
		return Ruleset{}, err
	}
	var fs []Filter
	for _, l := range Layers {
		fs = append(fs, onFilters(p, e, l)...)
		fs = append(fs, bootFilters(l)...)
		fs = append(fs, overlay(p, e, l)...)
	}
	return Ruleset{Mode: p.Mode, Filters: unique(fs)}, nil
}

// unique убирает фильтры с одинаковой канонической строкой (одинаковые endpoint): у них один ключ WFP,
// и Status прочитает один фильтр — план должен совпасть с прочитанным.
func unique(fs []Filter) []Filter {
	seen := map[string]bool{}
	out := fs[:0:0]
	for _, f := range fs {
		if line := f.Line(); !seen[line] {
			seen[line] = true
			out = append(out, f)
		}
	}
	return out
}

// noSvchost: svchost по app-id не разрешается никогда — ошибка конфига.
func noSvchost(p policy.Policy, e env.Env) error {
	for _, t := range p.Trust {
		if t.Kind != policy.KindProgram {
			continue
		}
		for _, id := range append([]string{t.Value}, e.Programs[t.Value]...) {
			if strings.EqualFold(path.Base(strings.ReplaceAll(id, `\`, "/")), "svchost.exe") {
				return fmt.Errorf("%w: доверие к svchost.exe по app-id запрещено (%s)", backend.ErrConfig, t.Value)
			}
		}
	}
	return nil
}

// onFilters — persistent-набор on: block 1 и permit 10.
func onFilters(p policy.Policy, e env.Env, l Layer) []Filter {
	pers := func(name string, a Action, w uint64, hard bool, conds ...Cond) Filter {
		return Filter{Name: name, Layer: l, Action: a, Weight: w, Hard: hard, Persistent: true, Conds: conds}
	}
	out := []Filter{
		pers("block", Block, WeightBlock, true),
		pers("loopback", Permit, WeightPermit, false, Cond{Field: FieldLoopback}),
		pers("dhcp", Permit, WeightPermit, false, dhcpConds(l)...),
	}
	if c := tunnelConds(p, e); len(c) > 0 {
		out = append(out, pers("tunnel", Permit, WeightPermit, false, c...))
	}
	for _, t := range trustFilters(p, e, l) {
		out = append(out, pers("trust", Permit, WeightPermit, false, t...))
	}
	if p.LAN {
		if c := lanConds(l); len(c) > 0 {
			out = append(out, pers("lan", Permit, WeightPermit, false, c...))
		}
	}
	if c := dnsConds(p, e, l); len(c) > 0 {
		out = append(out, pers("dns", Permit, WeightPermit, false, c...))
	}
	return out
}

// bootFilters — boot-time-набор: block + loopback + DHCP (до старта BFE).
func bootFilters(l Layer) []Filter {
	boot := func(name string, a Action, w uint64, hard bool, conds ...Cond) Filter {
		return Filter{Name: "boot " + name, Layer: l, Action: a, Weight: w, Hard: hard, BootTime: true, Conds: conds}
	}
	return []Filter{
		boot("block", Block, WeightBlock, true),
		boot("loopback", Permit, WeightPermit, false, Cond{Field: FieldLoopback}),
		boot("dhcp", Permit, WeightPermit, false, dhcpConds(l)...),
	}
}

// overlay — НЕ-persistent надстройка off/repair: исчезает при перезагрузке.
func overlay(p policy.Policy, e env.Env, l Layer) []Filter {
	if p.Mode == policy.ModeOn {
		return nil
	}
	out := []Filter{{Name: "permit-all", Layer: l, Action: Permit, Weight: WeightPermitAll}}
	if p.Mode == policy.ModeRepair {
		if c := appConds(p.Repair.Programs, e); len(c) > 0 {
			out = append(out, Filter{Name: "repair block", Layer: l, Action: Block, Weight: WeightBlockRepair, Hard: true, Conds: c})
		}
	}
	return out
}

func dhcpConds(l Layer) []Cond {
	ports := dhcpPorts[l.V4()]
	return []Cond{
		{Field: FieldProto, Proto: ProtoUDP},
		{Field: FieldLocalPort, Port: ports[0]},
		{Field: FieldRemotePort, Port: ports[1]},
	}
}

// tunnelConds — все совпавшие туннельные интерфейсы по LUID (поднятые и нет: LUID не меняется при down/up).
func tunnelConds(p policy.Policy, e env.Env) []Cond {
	seen := map[uint64]bool{}
	var out []Cond
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		if i.LUID == 0 || seen[i.LUID] {
			continue
		}
		seen[i.LUID] = true
		out = append(out, Cond{Field: FieldLocalIface, LUID: i.LUID})
	}
	return out
}

// appConds — app-id программ по glob; glob без найденных путей ничего не разрешает (fail-closed).
func appConds(globs []string, e env.Env) []Cond {
	seen := map[string]bool{}
	var ids []string
	for _, g := range globs {
		for _, id := range e.Programs[g] {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	out := make([]Cond, len(ids))
	for i, id := range ids {
		out[i] = Cond{Field: FieldAppID, AppID: id}
	}
	return out
}

// trustFilters — условия permit доверенных программ: compat — куда угодно (все слои);
// strict — только к своим Endpoints (исходящие слои), по фильтру на endpoint.
func trustFilters(p policy.Policy, e env.Env, l Layer) [][]Cond {
	var anyGlobs, epGlobs []string
	for _, t := range p.Trust {
		if t.Kind != policy.KindProgram {
			continue
		}
		if t.Destinations == policy.DestEndpoints {
			epGlobs = append(epGlobs, t.Value)
		} else {
			anyGlobs = append(anyGlobs, t.Value)
		}
	}
	var out [][]Cond
	if c := appConds(anyGlobs, e); len(c) > 0 {
		out = append(out, c)
	}
	apps := appConds(epGlobs, e)
	if len(apps) == 0 || !l.Connect() {
		return out
	}
	for _, ep := range p.Tunnel.Endpoints {
		addrs := endpointAddrs(ep, e, l.V4())
		if len(addrs) == 0 {
			continue
		}
		c := append([]Cond{}, apps...)
		c = append(c, Cond{Field: FieldProto, Proto: protoNum(ep.Proto)}, Cond{Field: FieldRemotePort, Port: ep.Port})
		for _, a := range addrs {
			c = append(c, Cond{Field: FieldRemoteAddr, Prefix: netip.PrefixFrom(a, a.BitLen())})
		}
		out = append(out, c)
	}
	return out
}

func endpointAddrs(ep policy.Endpoint, e env.Env, v4 bool) []netip.Addr {
	addrs := e.Resolved[ep.Host]
	if a, ok := ep.Addr(); ok {
		addrs = []netip.Addr{a}
	}
	return familyAddrs(addrs, v4)
}

func familyAddrs(addrs []netip.Addr, v4 bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() == v4 {
			out = append(out, a)
		}
	}
	return out
}

func protoNum(p policy.Proto) uint8 {
	if p == policy.ProtoTCP {
		return ProtoTCP
	}
	return ProtoUDP
}

// lanConds — LAN-диапазоны и mDNS/LLMNR семейства слоя, кроме порта 53: LAN сам по себе DNS не открывает.
func lanConds(l Layer) []Cond {
	var out []Cond
	for _, pfx := range append(append([]netip.Prefix{}, policy.LANPrefixes...), policy.LANMulticast...) {
		if pfx.Addr().Is4() == l.V4() {
			out = append(out, Cond{Field: FieldRemoteAddr, Prefix: pfx})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return append(out, Cond{Field: FieldRemotePort, Op: OpNeq, Port: 53})
}

// dnsConds — TCP/UDP 53 на исходящем слое по матрице DNSPermits.
func dnsConds(p policy.Policy, e env.Env, l Layer) []Cond {
	if !l.Connect() {
		return nil
	}
	perm := p.DNSPermits(e.Health == env.HealthUp)
	var dst []netip.Prefix
	if perm.LAN {
		dst = append(dst, policy.LANPrefixes...)
	}
	if perm.DHCP {
		for _, a := range e.DHCPDNS {
			a = a.Unmap()
			dst = append(dst, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	dst = append(dst, perm.Listed...)
	seen := map[netip.Prefix]bool{}
	var addr []Cond
	for _, pfx := range dst {
		pfx = pfx.Masked()
		if pfx.Addr().Is4() != l.V4() || seen[pfx] {
			continue
		}
		seen[pfx] = true
		addr = append(addr, Cond{Field: FieldRemoteAddr, Prefix: pfx})
	}
	if len(addr) == 0 {
		return nil
	}
	return append([]Cond{
		{Field: FieldProto, Proto: ProtoTCP},
		{Field: FieldProto, Proto: ProtoUDP},
		{Field: FieldRemotePort, Port: 53},
	}, addr...)
}
