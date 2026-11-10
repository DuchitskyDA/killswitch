// Package policy описывает политику киллсвитча, одинаковую для всех ОС:
// режим, исключения (Trust), туннель, DNS и проверку.
package policy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Mode — режим защиты.
type Mode string

const (
	ModeOn     Mode = "on"
	ModeOff    Mode = "off"
	ModeRepair Mode = "repair"
)

// ParseMode разбирает режим из командной строки или state.json.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeOn, ModeOff, ModeRepair:
		return m, nil
	}
	return "", fmt.Errorf("неизвестный режим %q (on, off, repair)", s)
}

// DNSMode — режим DNS (TCP/UDP 53) на физических интерфейсах.
type DNSMode string

const (
	DNSOpen      DNSMode = "open"
	DNSTunnelUp  DNSMode = "tunnel-up"
	DNSResolvers DNSMode = "resolvers"
)

// TrustMode — куда ходят доверенные: compat — куда угодно, strict — только к Endpoints.
type TrustMode string

const (
	TrustCompat TrustMode = "compat"
	TrustStrict TrustMode = "strict"
)

// TrustKind — вид селектора исключения.
type TrustKind string

const (
	KindProgram TrustKind = "program"
	KindUser    TrustKind = "user"
	KindCgroup  TrustKind = "cgroup"
	KindMark    TrustKind = "mark"
)

// Destinations — куда доверенному можно. Пустое значение бывает только до Build.
type Destinations string

const (
	DestAny       Destinations = "any"
	DestEndpoints Destinations = "endpoints"
)

// Proto — транспорт endpoint.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Endpoint — сервер туннеля: адрес или имя, порт и протокол.
type Endpoint struct {
	Host  string
	Port  uint16
	Proto Proto
}

// String возвращает каноническую запись "host:port/proto".
func (e Endpoint) String() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) + "/" + string(e.Proto)
}

// ParseEndpoint разбирает "host:port/proto"; IPv6 — в скобках.
func ParseEndpoint(s string) (Endpoint, error) {
	hostPort, proto, ok := strings.Cut(s, "/")
	if !ok || (Proto(proto) != ProtoTCP && Proto(proto) != ProtoUDP) {
		return Endpoint{}, fmt.Errorf("endpoint %q: нужен вид host:port/tcp|udp", s)
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q: нужен вид host:port/tcp|udp", s)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Endpoint{}, fmt.Errorf("endpoint %q: неверный порт", s)
	}
	return Endpoint{Host: host, Port: uint16(port), Proto: Proto(proto)}, nil
}

// Addr возвращает адрес, если Host — IP-литерал.
func (e Endpoint) Addr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(e.Host)
	return a, err == nil
}

// Trust — исключение: селектор И ограничение назначений. Между Trust — ИЛИ.
type Trust struct {
	Kind         TrustKind
	Value        string
	Destinations Destinations
}

// Tunnel — интерфейсы туннеля (glob по имени, alias и описанию) и его серверы.
type Tunnel struct {
	Interfaces []string
	Endpoints  []Endpoint
}

// HealthURL — цель проверки здоровья туннеля: только http://<ip>:<port>/<path>.
type HealthURL struct {
	Addr netip.AddrPort
	Path string
}

// String возвращает URL.
func (h HealthURL) String() string { return "http://" + h.Addr.String() + h.Path }

// ParseHealthURL разбирает dns.health.
func ParseHealthURL(s string) (HealthURL, error) {
	rest, ok := strings.CutPrefix(s, "http://")
	if !ok {
		return HealthURL{}, fmt.Errorf("dns.health %q: нужен http://<ip>:<port>/<path>", s)
	}
	hostPort, path, _ := strings.Cut(rest, "/")
	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil || ap.Port() == 0 {
		return HealthURL{}, fmt.Errorf("dns.health %q: нужен IP-адрес и порт", s)
	}
	return HealthURL{Addr: ap, Path: "/" + path}, nil
}

// Repair — режим repair: открыто всё, кроме этих программ. Programs — шаблоны путей; Names — имена программ без
// пути и расширения: их файлы backend находит сам (запущенные и обычные места установки).
type Repair struct{ Programs, Names []string }

// Check — цели проб check (слушают HTTP 80, UDP-эхо 443, DNS 53).
type Check struct{ Targets []netip.Addr }

// Policy — полная политика после слияния умолчания → профиль → конфиг.
type Policy struct {
	Mode      Mode
	LAN       bool
	DNS       DNSMode
	Resolvers []netip.Prefix
	Health    *HealthURL
	TrustMode TrustMode
	Tunnel    Tunnel
	Trust     []Trust
	Repair    Repair
	Check     Check
}

// WithMode возвращает копию политики в режиме m.
func (p Policy) WithMode(m Mode) Policy {
	p.Mode = m
	return p
}
