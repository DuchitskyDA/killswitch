package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/BurntSushi/toml"
)

// Layer — вклад профиля клиента в политику (секция текущей ОС).
type Layer struct {
	Interfaces     []string
	RepairPrograms []string
	Trust          []Trust // Destinations может быть пустым: выбирается по trust_mode
}

// Config — конфиг пользователя. nil-поле — ключа нет, значение берётся из профиля или умолчания.
type Config struct {
	Profile   string       `toml:"profile"`
	LAN       *bool        `toml:"lan"`
	TrustMode *string      `toml:"trust_mode"`
	Tunnel    configTunnel `toml:"tunnel"`
	Trust     *[]trustTOML `toml:"trust"`
	DNS       configDNS    `toml:"dns"`
	Repair    configRepair `toml:"repair"`
	Check     configCheck  `toml:"check"`
}

type configTunnel struct {
	Interfaces *[]string `toml:"interfaces"`
	Endpoints  *[]string `toml:"endpoints"`
}

type trustTOML struct {
	Kind         string `toml:"kind"`
	Value        string `toml:"value"`
	Destinations string `toml:"destinations"`
}

type configDNS struct {
	Mode      *string   `toml:"mode"`
	Resolvers *[]string `toml:"resolvers"`
	Health    *string   `toml:"health"`
}

type configRepair struct {
	Programs *[]string `toml:"programs"`
}

type configCheck struct {
	Targets *[]string `toml:"targets"`
}

// ParseConfig разбирает TOML конфига; неизвестный ключ — ошибка.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return Config{}, fmt.Errorf("конфиг: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return Config{}, fmt.Errorf("конфиг: неизвестные ключи %v", und)
	}
	return c, nil
}

// Build сливает встроенные умолчания → профиль → конфиг. Ключ конфига заменяет значение целиком.
// Mode не задаётся: его ставит команда (WithMode).
func Build(l Layer, c Config) (Policy, error) {
	p := Policy{
		LAN:       true,
		DNS:       DNSOpen,
		TrustMode: TrustCompat,
		Tunnel:    Tunnel{Interfaces: l.Interfaces},
		Trust:     l.Trust,
		Repair:    Repair{Programs: l.RepairPrograms},
	}
	err := errors.Join(c.applyScalars(&p), c.applyLists(&p))
	if err != nil {
		return Policy{}, err
	}
	p.Trust = withDefaultDestinations(p.Trust, p.TrustMode)
	return p, nil
}

func (c Config) applyScalars(p *Policy) error {
	if c.LAN != nil {
		p.LAN = *c.LAN
	}
	if c.TrustMode != nil {
		p.TrustMode = TrustMode(*c.TrustMode)
	}
	if c.DNS.Mode != nil {
		p.DNS = DNSMode(*c.DNS.Mode)
	}
	if c.DNS.Health == nil {
		return nil
	}
	h, err := ParseHealthURL(*c.DNS.Health)
	if err != nil {
		return err
	}
	p.Health = &h
	return nil
}

func (c Config) applyLists(p *Policy) error {
	var errs []error
	if c.Tunnel.Interfaces != nil {
		p.Tunnel.Interfaces = *c.Tunnel.Interfaces
	}
	if c.Repair.Programs != nil {
		p.Repair.Programs = *c.Repair.Programs
	}
	if c.Trust != nil {
		p.Trust = toTrust(*c.Trust)
	}
	if c.Tunnel.Endpoints != nil {
		eps, err := parseAll(*c.Tunnel.Endpoints, ParseEndpoint)
		p.Tunnel.Endpoints, errs = eps, append(errs, err)
	}
	if c.DNS.Resolvers != nil {
		rs, err := parseAll(*c.DNS.Resolvers, parsePrefixOrAddr)
		p.Resolvers, errs = rs, append(errs, err)
	}
	if c.Check.Targets != nil {
		ts, err := parseAll(*c.Check.Targets, parseAddr)
		p.Check.Targets, errs = ts, append(errs, err)
	}
	return errors.Join(errs...)
}

func toTrust(in []trustTOML) []Trust {
	out := make([]Trust, 0, len(in))
	for _, t := range in {
		out = append(out, Trust{Kind: TrustKind(t.Kind), Value: t.Value, Destinations: Destinations(t.Destinations)})
	}
	return out
}

// withDefaultDestinations: пустые Destinations — any в compat, endpoints в strict.
func withDefaultDestinations(in []Trust, m TrustMode) []Trust {
	def := DestAny
	if m == TrustStrict {
		def = DestEndpoints
	}
	out := make([]Trust, 0, len(in))
	for _, t := range in {
		if t.Destinations == "" {
			t.Destinations = def
		}
		out = append(out, t)
	}
	return out
}

func parseAll[T any](in []string, parse func(string) (T, error)) ([]T, error) {
	out := make([]T, 0, len(in))
	var errs []error
	for _, s := range in {
		v, err := parse(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, v)
	}
	return out, errors.Join(errs...)
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("dns.resolvers: %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := parseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("dns.resolvers: %w", err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("адрес %q: %w", s, err)
	}
	return a, nil
}
