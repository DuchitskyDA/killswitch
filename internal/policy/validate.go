package policy

import (
	"errors"
	"fmt"
	"path"
)

// Capabilities — что backend ОС умеет исполнить. Неподдержанное в политике — ошибка, без замены.
type Capabilities struct {
	OS        string
	Trust     map[TrustKind]bool
	Endpoints bool
	Repair    bool
}

// CapabilitiesFor — возможности по ОС (рев. 2): одно место решения для всех backend.
func CapabilitiesFor(goos string) Capabilities {
	switch goos {
	case "windows":
		return Capabilities{OS: goos, Trust: map[TrustKind]bool{KindProgram: true}, Endpoints: true, Repair: true}
	case "darwin":
		return Capabilities{OS: goos, Trust: map[TrustKind]bool{KindUser: true}, Endpoints: true}
	case "linux":
		return Capabilities{OS: goos, Trust: map[TrustKind]bool{KindUser: true, KindCgroup: true, KindMark: true}, Endpoints: true}
	}
	return Capabilities{OS: goos, Trust: map[TrustKind]bool{}}
}

// Validate проверяет политику против возможностей ОС; любая ошибка — код 2.
func (p Policy) Validate(c Capabilities) error {
	return errors.Join(
		p.validateMode(c),
		p.validateTunnel(c),
		p.validateTrust(c),
		p.validateDNS(),
	)
}

func (p Policy) validateMode(c Capabilities) error {
	if _, err := ParseMode(string(p.Mode)); err != nil {
		return err
	}
	if p.Mode != ModeRepair {
		return nil
	}
	if !c.Repair {
		return fmt.Errorf("режим repair не поддерживается на %s", c.OS)
	}
	if len(p.Repair.Programs) == 0 {
		return errors.New("repair: не задано ни одной программы (repair.programs)")
	}
	return nil
}

func (p Policy) validateTunnel(c Capabilities) error {
	if len(p.Tunnel.Interfaces) == 0 {
		return errors.New("tunnel.interfaces: не задан ни один интерфейс туннеля")
	}
	for _, pat := range p.Tunnel.Interfaces {
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("tunnel.interfaces: неверный шаблон %q", pat)
		}
	}
	if len(p.Tunnel.Endpoints) > 0 && !c.Endpoints {
		return fmt.Errorf("tunnel.endpoints не поддерживаются на %s", c.OS)
	}
	return nil
}

func (p Policy) validateTrust(c Capabilities) error {
	switch p.TrustMode {
	case TrustCompat, TrustStrict:
	default:
		return fmt.Errorf("trust_mode %q: нужен compat или strict", p.TrustMode)
	}
	if p.TrustMode == TrustStrict && len(p.Tunnel.Endpoints) == 0 {
		return errors.New("trust_mode = strict: нужен хотя бы один tunnel.endpoints")
	}
	var errs []error
	for _, t := range p.Trust {
		errs = append(errs, p.validateOneTrust(c, t))
	}
	return errors.Join(errs...)
}

func (p Policy) validateOneTrust(c Capabilities, t Trust) error {
	if !c.Trust[t.Kind] {
		return fmt.Errorf("trust %s=%q: вид %q не поддерживается на %s", t.Kind, t.Value, t.Kind, c.OS)
	}
	if t.Value == "" {
		return fmt.Errorf("trust %s: пустое значение", t.Kind)
	}
	switch t.Destinations {
	case DestAny:
		if p.TrustMode == TrustStrict {
			return fmt.Errorf("trust %s=%q: destinations = any запрещено в strict", t.Kind, t.Value)
		}
	case DestEndpoints:
		if len(p.Tunnel.Endpoints) == 0 {
			return fmt.Errorf("trust %s=%q: destinations = endpoints без tunnel.endpoints", t.Kind, t.Value)
		}
	default:
		return fmt.Errorf("trust %s=%q: destinations %q: нужен any или endpoints", t.Kind, t.Value, t.Destinations)
	}
	return nil
}

func (p Policy) validateDNS() error {
	switch p.DNS {
	case DNSOpen, DNSTunnelUp, DNSResolvers:
	default:
		return fmt.Errorf("dns.mode %q: нужен open, tunnel-up или resolvers", p.DNS)
	}
	if p.DNS == DNSTunnelUp && p.Health == nil {
		return errors.New("dns.mode = tunnel-up: нужен dns.health")
	}
	if p.DNS == DNSResolvers && len(p.Resolvers) == 0 {
		return errors.New("dns.mode = resolvers: нужен dns.resolvers")
	}
	if p.DNS != DNSResolvers && len(p.Resolvers) > 0 {
		return fmt.Errorf("dns.resolvers задан, но dns.mode = %s", p.DNS)
	}
	return nil
}
