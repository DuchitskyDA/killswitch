package probe

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

// Service — слушающий сервис цели check (рев. 3: HTTP 80, UDP-эхо 443, DNS 53).
type Service struct {
	Name  string
	Proto string
	Port  uint16
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
	// Tunnel: цель отвечает через туннельный сокет (baseline при включённой защите).
	Tunnel(ctx context.Context, s Service, dst netip.Addr, tun env.Iface) error
	// Direct: проба через физический интерфейс с портом-источником id.Src; answered — пришёл ответ сервера.
	// err — только сбой подготовки (привязка, порт занят), не отсутствие ответа.
	Direct(ctx context.Context, s Service, id ProbeID, iface env.Iface) (answered bool, err error)
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

// Input — что проверять.
type Input struct {
	Targets    []netip.Addr
	Tunnels    []env.Iface // совпавшие и поднятые туннельные интерфейсы
	Physical   []env.Iface // поднятые физические интерфейсы
	Structural []StructuralFinding
}

// Run выполняет пробы. Защита для baseline не снимается: baseline идёт через туннель.
func Run(ctx context.Context, in Input, p Prober, ev EvidenceSource, now func() time.Time) CheckResult {
	r := runner{ctx: ctx, p: p, ev: ev, now: now, port: SrcPortFirst}
	var probes []ProbeResult
	if len(in.Targets) == 0 {
		probes = append(probes, ProbeResult{Target: "-", Class: Inconclusive,
			Detail: "check.targets пуст: задайте цели со слушающими HTTP 80, UDP-эхо 443 и DNS 53"})
	}
	for _, dst := range in.Targets {
		for _, s := range Services {
			probes = append(probes, r.target(in, s, dst)...)
		}
	}
	return CheckResult{Probes: probes, Structural: in.Structural, Overall: Overall(probes, in.Structural)}
}

type runner struct {
	ctx  context.Context
	p    Prober
	ev   EvidenceSource
	now  func() time.Time
	port uint16
}

func (r *runner) target(in Input, s Service, dst netip.Addr) []ProbeResult {
	fam := family(dst)
	baseline := "туннель не поднят"
	if len(in.Tunnels) > 0 {
		baseline = ""
		if err := r.p.Tunnel(r.ctx, s, dst, in.Tunnels[0]); err != nil {
			baseline = "цель не ответила через туннель: " + err.Error()
		}
	}
	var out []ProbeResult
	for _, phys := range in.Physical {
		res := ProbeResult{Target: netip.AddrPortFrom(dst, s.Port).String(), Family: fam, Proto: s.Name, Iface: phys.Name}
		res.Class, res.Detail = r.direct(s, dst, phys, baseline)
		out = append(out, res)
	}
	return out
}

func (r *runner) direct(s Service, dst netip.Addr, phys env.Iface, baseline string) (Class, string) {
	src, ok := phys.SourceAddr(dst.Is4())
	if !ok {
		return Skipped, "нет адреса " + family(dst) + " на интерфейсе"
	}
	if baseline != "" {
		return Inconclusive, baseline
	}
	id := ProbeID{Proto: s.Proto, Src: netip.AddrPortFrom(src, r.nextPort()), Dst: netip.AddrPortFrom(dst, s.Port),
		Iface: phys.Name, At: r.now()}
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
		return Leak, "сервер ответил мимо туннеля"
	}
	dropped, err := r.ev.Evidence(id, id.At)
	if err != nil {
		return Inconclusive, "нет свидетельства: " + err.Error()
	}
	if !dropped {
		return Inconclusive, "ответа нет, но и отброса нашим правилом не видно"
	}
	return Blocked, fmt.Sprintf("отброшено нашим правилом (порт-источник %d)", id.Src.Port())
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
