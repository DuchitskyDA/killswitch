// Package env — снимок машины: вход чистого планирования (Backend.Plan).
// Всё, что читает сеть или имеет побочные эффекты, собирает Backend.Snapshot.
package env

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"
)

// Iface — сетевой интерфейс.
type Iface struct {
	Name, Alias, Description string
	Index                    int
	LUID                     uint64 // Windows
	Up                       bool
	Physical                 bool
	Addrs                    []netip.Prefix
	// DefaultRoute4/6 — у интерфейса есть маршрут по умолчанию семейства (в любой таблице маршрутов). Физический
	// интерфейс без него (vEthernet (nat) Hyper-V/WSL, docker0) в интернет не ведёт: check его семейство пропускает.
	DefaultRoute4, DefaultRoute6 bool
}

// DefaultRoute — есть ли маршрут по умолчанию семейства v4 (true) или v6 (false).
func (i Iface) DefaultRoute(v4 bool) bool {
	if v4 {
		return i.DefaultRoute4
	}
	return i.DefaultRoute6
}

// SourceAddr — адрес интерфейса семейства v4 (true) или v6 (false), кроме link-local v6.
func (i Iface) SourceAddr(v4 bool) (netip.Addr, bool) {
	for _, p := range i.Addrs {
		a := p.Addr()
		if a.Is4() == v4 && !(a.Is6() && a.IsLinkLocalUnicast()) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// Route — эффективный маршрут к адресу.
type Route struct {
	IfaceIndex int
	ViaTunnel  bool
}

// HealthState — состояние здоровья туннеля; unknown действует как down.
type HealthState string

const (
	HealthUnknown HealthState = "unknown"
	HealthDown    HealthState = "down"
	HealthUp      HealthState = "up"
)

// Env — снимок машины.
type Env struct {
	OS         string
	Ifaces     []Iface
	Programs   map[string][]string // glob → найденные пути
	Users      map[string]int      // имя → uid
	Resolved   map[string][]netip.Addr
	ResolveErr map[string]string
	Routes     map[netip.Addr]Route
	DHCPDNS    []netip.Addr
	Health     HealthState
	BootID     string
}

// MatchIfaces раскрывает шаблоны туннеля: glob по имени, alias и описанию; на Windows — без учёта регистра.
func (e Env) MatchIfaces(patterns []string) []Iface {
	var out []Iface
	for _, i := range e.Ifaces {
		if e.matchesAny(patterns, i) {
			out = append(out, i)
		}
	}
	return out
}

func (e Env) matchesAny(patterns []string, i Iface) bool {
	fold := func(s string) string { return s }
	if e.OS == "windows" {
		fold = strings.ToLower
	}
	for _, p := range patterns {
		for _, s := range []string{i.Name, i.Alias, i.Description} {
			if ok, _ := path.Match(fold(p), fold(s)); ok && s != "" {
				return true
			}
		}
	}
	return false
}

// WithLastKnown подставляет последние известные адреса для имён, которые сейчас не разрешились.
// Имя без известных адресов остаётся без адресов (Trust к нему ничего не разрешает) и даёт строку WARN.
func WithLastKnown(e Env, last map[string][]netip.Addr) (Env, []string) {
	resolved := make(map[string][]netip.Addr, len(e.Resolved)+len(e.ResolveErr))
	for name, addrs := range e.Resolved {
		resolved[name] = addrs
	}
	var warns []string
	for _, name := range sortedKeys(e.ResolveErr) {
		if addrs := last[name]; len(addrs) > 0 {
			resolved[name] = addrs
			warns = append(warns, fmt.Sprintf("WARN %s не разрешилось (%s): взяты последние известные %v", name, e.ResolveErr[name], addrs))
			continue
		}
		warns = append(warns, fmt.Sprintf("WARN %s не разрешилось (%s): адресов нет, к нему ничего не разрешено", name, e.ResolveErr[name]))
	}
	e.Resolved = resolved
	return e, warns
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
