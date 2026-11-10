package probe

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

// Service — слушающий сервис цели check: HTTP 80, UDP-эхо 443, DNS 53.
type Service struct {
	Name  string
	Proto string
	Port  uint16
	Host  string // имя сайта в запросе HTTP; пусто — адрес цели
}

// Services — пробы к каждой цели.
var Services = []Service{
	{Name: "http", Proto: "tcp", Port: 80},
	{Name: "udp-echo", Proto: "udp", Port: 443},
	{Name: "dns-udp", Proto: "udp", Port: 53},
	{Name: "dns-tcp", Proto: "tcp", Port: 53},
}

// Prober шлёт пробы. Реализация — NetProber; в тестах — фейк.
type Prober interface {
	// Tunnel: цель отвечает через сокет, привязанный к туннелю (baseline при включённой защите).
	Tunnel(ctx context.Context, s Service, dst netip.Addr, tun env.Iface) error
	// Route: цель отвечает через сокет без привязки, по эффективному маршруту через туннель tun; соединение с
	// адресом-источником не из tun — провал. Нужен, когда клиент туннеля перенаправляет трафик (sing-box
	// auto_redirect) и привязка к TUN ломает обмен.
	Route(ctx context.Context, s Service, dst netip.Addr, tun env.Iface) error
	// Direct: проба через физический интерфейс с портом-источником id.Src; answered — пришёл ответ сервера.
	// err — только сбой подготовки (привязка, порт занят), не отсутствие ответа.
	Direct(ctx context.Context, s Service, id ProbeID, iface env.Iface) (answered bool, err error)
	// Resolve — адреса имени host системным резолвером (простая проверка).
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
	// Plain: цель отвечает обычным путём — сокетом без привязки, как у любой программы (простая проверка).
	Plain(ctx context.Context, s Service, dst netip.Addr) error
}

// EvidenceSource — свидетельство, что пробу отбросило наше правило (Backend.Evidence).
type EvidenceSource interface {
	Evidence(id ProbeID, since time.Time) (dropped bool, err error)
}

// Preparer — необязательно у EvidenceSource: подготовка свидетельства до пробы (снять счётчик, включить сбор событий).
// Ошибка — проба INCONCLUSIVE.
type Preparer interface {
	BeforeProbe(id ProbeID) error
}

// Finisher — необязательно у EvidenceSource: уборка после пробы (вернуть сбор событий в исходное состояние).
// Run вызывает его ровно один раз на каждую отправляемую пробу, на любом исходе: BLOCKED, LEAK, сбой привязки
// или подготовки.
type Finisher interface {
	AfterProbe(id ProbeID)
}

// Egress — необязательно у EvidenceSource: ушёл ли пакет пробы через физический интерфейс.
// sent=false без ошибки — доказано, что не ушёл (клиент туннеля перехватил пробу); ошибка — признака нет.
type Egress interface {
	Egressed(id ProbeID) (sent bool, err error)
}

// Input — что проверять.
type Input struct {
	Targets    []netip.Addr
	Tunnels    []env.Iface              // совпавшие и поднятые туннельные интерфейсы
	Physical   []env.Iface              // поднятые физические интерфейсы
	Routes     map[netip.Addr]env.Route // эффективные маршруты к целям (Env.Routes)
	Structural []StructuralFinding
}

// Run выполняет пробы. Защита для baseline не снимается: baseline идёт через туннель.
func Run(ctx context.Context, in Input, p Prober, ev EvidenceSource, now func() time.Time) CheckResult {
	r := runner{ctx: ctx, p: p, ev: ev, now: now, port: SrcPortFirst}
	var probes []ProbeResult
	if !anyDefaultRoute(in.Physical) {
		probes = append(probes, ProbeResult{Target: "-", Class: Inconclusive,
			Detail: "ни у одного поднятого физического интерфейса нет маршрута по умолчанию: путь в интернет мимо туннеля не найден, проверять нечего"})
	}
	simple := len(in.Targets) == 0
	if simple {
		probes = append(probes, r.simple(in)...)
	}
	for _, dst := range in.Targets {
		for _, s := range Services {
			probes = append(probes, r.target(in, s, dst)...)
		}
	}
	return CheckResult{Probes: probes, Structural: in.Structural, Overall: Overall(probes, in.Structural), Simple: simple}
}

type runner struct {
	ctx  context.Context
	p    Prober
	ev   EvidenceSource
	now  func() time.Time
	port uint16
}

func (r *runner) target(in Input, s Service, dst netip.Addr) []ProbeResult {
	return r.physical(in, s, dst, r.baseline(in, s, dst), r.dropped)
}

// physical — проба s к dst через каждый физический интерфейс.
func (r *runner) physical(in Input, s Service, dst netip.Addr, baseline string, silent func(ProbeID) (Class, string)) []ProbeResult {
	var out []ProbeResult
	for _, phys := range in.Physical {
		res := ProbeResult{Target: netip.AddrPortFrom(dst, s.Port).String(), Family: family(dst), Proto: s.Name, Iface: phys.Name}
		res.Class, res.Detail = r.direct(s, dst, phys, baseline, silent)
		out = append(out, res)
	}
	return out
}

// direct — одна проба через физический интерфейс; silent — что значит молчание сервера.
func (r *runner) direct(s Service, dst netip.Addr, phys env.Iface, baseline string, silent func(ProbeID) (Class, string)) (Class, string) {
	src, ok := phys.SourceAddr(dst.Is4())
	if !ok {
		return Skipped, "нет адреса " + family(dst) + " на интерфейсе"
	}
	if !phys.DefaultRoute(dst.Is4()) {
		return Skipped, "нет маршрута по умолчанию " + family(dst) + " через интерфейс"
	}
	if baseline != "" {
		return Inconclusive, baseline
	}
	id := ProbeID{Proto: s.Proto, Src: netip.AddrPortFrom(src, r.nextPort()), Dst: netip.AddrPortFrom(dst, s.Port),
		Iface: phys.Name, At: r.now()}
	if fin, ok := r.ev.(Finisher); ok {
		defer fin.AfterProbe(id)
	}
	if prep, ok := r.ev.(Preparer); ok {
		if err := prep.BeforeProbe(id); err != nil {
			return Inconclusive, "свидетельство не подготовлено: " + err.Error()
		}
	}
	answered, err := r.p.Direct(r.ctx, s, id, phys)
	if err != nil {
		return Inconclusive, "проба не отправлена: " + err.Error()
	}
	if answered {
		return r.answered(id)
	}
	return silent(id)
}

// dropped — молчание сервера в полной проверке: BLOCKED только со свидетельством отброса нашим правилом.
func (r *runner) dropped(id ProbeID) (Class, string) {
	dropped, err := r.ev.Evidence(id, id.At)
	if err != nil {
		return Inconclusive, "нет свидетельства: " + err.Error()
	}
	if !dropped {
		return Inconclusive, "ответа нет, но и отброса нашим правилом не видно"
	}
	return Blocked, fmt.Sprintf("отброшено нашим правилом (порт-источник %d)", id.Src.Port())
}

// baseline — цель жива через туннель: по маршруту, если эффективный маршрут к ней идёт через поднятый туннель
// (перенаправление клиента ломает привязку к TUN), иначе сокетом, привязанным к туннелю. Пустая строка — жива.
func (r *runner) baseline(in Input, s Service, dst netip.Addr) string {
	if len(in.Tunnels) == 0 {
		return "туннель не поднят"
	}
	var err error
	if tun, ok := routedTunnel(in, dst); ok {
		err = r.p.Route(r.ctx, s, dst, tun)
	} else {
		err = r.p.Tunnel(r.ctx, s, dst, in.Tunnels[0])
	}
	if err != nil {
		return "цель не ответила через туннель: " + err.Error()
	}
	return ""
}

func routedTunnel(in Input, dst netip.Addr) (env.Iface, bool) {
	route, ok := in.Routes[dst]
	if !ok || !route.ViaTunnel {
		return env.Iface{}, false
	}
	for _, t := range in.Tunnels {
		if t.Index == route.IfaceIndex {
			return t, true
		}
	}
	return env.Iface{}, false
}

// answered — сервер ответил на прямую пробу. Утечка, кроме случая, когда backend доказал, что пакет пробы через
// физический интерфейс не уходил: клиент туннеля перехватил пробу и ответ пришёл через туннель — тогда пропуск с
// пометкой, итог — по остальным пробам. Признака нет или он не прочитан — утечка, как раньше.
func (r *runner) answered(id ProbeID) (Class, string) {
	if eg, ok := r.ev.(Egress); ok {
		if sent, err := eg.Egressed(id); err == nil && !sent {
			return Skipped, "перехвачено клиентом туннеля, через физический адаптер не ушло"
		}
	}
	return Leak, "сервер ответил мимо туннеля"
}

func anyDefaultRoute(ifaces []env.Iface) bool {
	for _, i := range ifaces {
		if i.DefaultRoute4 || i.DefaultRoute6 {
			return true
		}
	}
	return false
}

func (r *runner) nextPort() uint16 {
	p := r.port
	r.port++
	if r.port > SrcPortLast {
		r.port = SrcPortFirst
	}
	return p
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "v4"
	}
	return "v6"
}
