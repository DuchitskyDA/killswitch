package probe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

type fakeProber struct {
	tunnelErr     error
	answered      bool
	answeredProto string // отвечает только на пробы этого протокола ("tcp"|"udp")
	sent          []ProbeID
	baselines     []string // "tunnel <iface>" | "route <iface>"
}

func (f *fakeProber) Tunnel(_ context.Context, _ Service, _ netip.Addr, tun env.Iface) error {
	f.baselines = append(f.baselines, "tunnel "+tun.Name)
	return f.tunnelErr
}

func (f *fakeProber) Route(_ context.Context, _ Service, _ netip.Addr, tun env.Iface) error {
	f.baselines = append(f.baselines, "route "+tun.Name)
	return f.tunnelErr
}

func (f *fakeProber) Direct(_ context.Context, _ Service, id ProbeID, _ env.Iface) (bool, error) {
	f.sent = append(f.sent, id)
	return f.answered || (f.answeredProto != "" && id.Proto == f.answeredProto), nil
}

type fakeEvidence struct{ dropped bool }

func (f fakeEvidence) Evidence(ProbeID, time.Time) (bool, error) { return f.dropped, nil }

// preparingEvidence запоминает, сколько проб было отправлено к моменту подготовки.
type preparingEvidence struct {
	fakeEvidence
	p          *fakeProber
	err        error
	sentBefore []int
}

func (e *preparingEvidence) BeforeProbe(ProbeID) error {
	e.sentBefore = append(e.sentBefore, len(e.p.sent))
	return e.err
}

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func now() time.Time { return t0 }

var tun = env.Iface{Name: "wg0", Index: 7, Up: true}
var eth = env.Iface{Name: "eth0", Index: 2, Up: true, Physical: true, DefaultRoute4: true, DefaultRoute6: true,
	Addrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24")}}

// vnat — физический интерфейс с адресом, но без маршрута по умолчанию (vEthernet (nat) Hyper-V/WSL).
var vnat = env.Iface{Name: "vEthernet (nat)", Index: 9, Up: true, Physical: true,
	Addrs: []netip.Prefix{netip.MustParsePrefix("172.20.0.1/20")}}
var target4 = netip.MustParseAddr("203.0.113.130")
var target6 = netip.MustParseAddr("2001:db8:b::2")

func run(in Input, p *fakeProber, ev fakeEvidence) CheckResult {
	return Run(context.Background(), in, p, ev, now)
}

func TestOverallStructuralIsLeak(t *testing.T) {
	probes := []ProbeResult{{Class: Blocked}}
	eq(t, Overall(probes, []StructuralFinding{{Kind: "wfp-tie"}}), Leak)
}

func TestOverallLeakBeatsInconclusive(t *testing.T) {
	eq(t, Overall([]ProbeResult{{Class: Inconclusive}, {Class: Leak}}, nil), Leak)
}

func TestOverallInconclusive(t *testing.T) {
	eq(t, Overall([]ProbeResult{{Class: Blocked}, {Class: Inconclusive}}, nil), Inconclusive)
}

func TestOverallAllBlocked(t *testing.T) {
	eq(t, Overall([]ProbeResult{{Class: Blocked}, {Class: Skipped}}, nil), Blocked)
}

func TestOverallOnlySkippedIsInconclusive(t *testing.T) {
	eq(t, Overall([]ProbeResult{{Class: Skipped}}, nil), Inconclusive)
}

func TestExitCodes(t *testing.T) {
	eq(t, ExitCode(Blocked), 0)
	eq(t, ExitCode(Leak), 4)
	eq(t, ExitCode(Inconclusive), 5)
}

func TestRunNoAnswerWithEvidenceIsBlocked(t *testing.T) {
	p := &fakeProber{}
	r := run(Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}, p, fakeEvidence{dropped: true})
	eq(t, r.Overall, Blocked)
	eq(t, len(r.Probes), len(Services))
	eq(t, p.sent[0].Src, netip.MustParseAddrPort("198.51.100.2:30000"))
	eq(t, p.sent[1].Src.Port(), SrcPortFirst+1)
}

func TestRunNoAnswerWithoutEvidenceIsInconclusive(t *testing.T) {
	r := run(Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}, &fakeProber{}, fakeEvidence{})
	eq(t, r.Overall, Inconclusive)
	eq(t, r.Probes[0].Class, Inconclusive)
}

func TestRunAnswerIsLeak(t *testing.T) {
	r := run(Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}},
		&fakeProber{answered: true}, fakeEvidence{dropped: true})
	eq(t, r.Overall, Leak)
	eq(t, r.Probes[0].Class, Leak)
}

func TestRunTunnelDownIsInconclusiveWithoutSending(t *testing.T) {
	p := &fakeProber{}
	r := run(Input{Targets: []netip.Addr{target4}, Physical: []env.Iface{eth}}, p, fakeEvidence{dropped: true})
	eq(t, r.Overall, Inconclusive)
	eq(t, len(p.sent), 0)
}

func TestRunBaselineFailedIsInconclusive(t *testing.T) {
	p := &fakeProber{tunnelErr: errors.New("timeout")}
	r := run(Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}, p, fakeEvidence{dropped: true})
	eq(t, r.Overall, Inconclusive)
	eq(t, len(p.sent), 0)
}

func TestRunFamilyWithoutAddressIsSkipped(t *testing.T) {
	r := run(Input{Targets: []netip.Addr{target4, target6}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}},
		&fakeProber{}, fakeEvidence{dropped: true})
	eq(t, r.Overall, Blocked)
	eq(t, r.Probes[len(Services)].Class, Skipped)
}

func TestRunNoTargetsIsInconclusive(t *testing.T) {
	r := run(Input{Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}, &fakeProber{}, fakeEvidence{dropped: true})
	eq(t, r.Overall, Inconclusive)
}

func TestRunStructuralWithBlockedProbesIsLeak(t *testing.T) {
	in := Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth},
		Structural: []StructuralFinding{{Kind: "pf-anchor-unreachable"}}}
	r := run(in, &fakeProber{}, fakeEvidence{dropped: true})
	eq(t, r.Overall, Leak)
	eq(t, len(r.Structural), 1)
}

func TestRunPreparesEvidenceBeforeEachProbe(t *testing.T) {
	p := &fakeProber{}
	ev := &preparingEvidence{fakeEvidence: fakeEvidence{dropped: true}, p: p}
	r := Run(context.Background(), Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}, p, ev, now)
	eq(t, r.Overall, Blocked)
	eq(t, ev.sentBefore, []int{0, 1, 2, 3})
}

func TestRunPreparationFailureIsInconclusiveWithoutSending(t *testing.T) {
	p := &fakeProber{}
	ev := &preparingEvidence{fakeEvidence: fakeEvidence{dropped: true}, p: p, err: errors.New("events off")}
	r := Run(context.Background(), Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}, p, ev, now)
	eq(t, r.Overall, Inconclusive)
	eq(t, len(p.sent), 0)
}

func TestSourcePortsWrapWithinRange(t *testing.T) {
	r := runner{port: SrcPortLast - 1}
	eq(t, r.nextPort(), SrcPortLast-1)
	eq(t, r.nextPort(), SrcPortLast)
	eq(t, r.nextPort(), SrcPortFirst)
}

func TestRunBaselineByRouteWhenRouteViaTunnel(t *testing.T) {
	p := &fakeProber{}
	in := Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth},
		Routes: map[netip.Addr]env.Route{target4: {IfaceIndex: tun.Index, ViaTunnel: true}}}
	r := run(in, p, fakeEvidence{dropped: true})
	eq(t, r.Overall, Blocked)
	eq(t, p.baselines[0], "route wg0")
}

func TestRunBaselineBoundWhenRouteNotViaTunnel(t *testing.T) {
	p := &fakeProber{}
	in := Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth},
		Routes: map[netip.Addr]env.Route{target4: {IfaceIndex: eth.Index}}}
	run(in, p, fakeEvidence{dropped: true})
	eq(t, p.baselines[0], "tunnel wg0")
}

func TestRunPhysicalWithoutDefaultRouteIsSkipped(t *testing.T) {
	p := &fakeProber{}
	in := Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{vnat, eth}}
	r := run(in, p, fakeEvidence{dropped: true})
	eq(t, r.Overall, Blocked)
	eq(t, r.Probes[0].Class, Skipped)
	eq(t, len(p.sent), len(Services))
}

func TestRunNoPhysicalDefaultRouteIsInconclusiveWithHint(t *testing.T) {
	in := Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{vnat}}
	r := run(in, &fakeProber{}, fakeEvidence{dropped: true})
	eq(t, r.Overall, Inconclusive)
	eq(t, strings.Contains(r.Probes[0].Detail, "маршрута по умолчанию"), true)
}

// egressEvidence — признак выхода пробы через физический интерфейс.
type egressEvidence struct {
	fakeEvidence
	sent bool
	err  error
}

func (e egressEvidence) Egressed(ProbeID) (bool, error) { return e.sent, e.err }

func answeredWith(ev EvidenceSource) CheckResult {
	return Run(context.Background(), oneTarget, &fakeProber{answered: true}, ev, now)
}

// Решение владельца: проба, перехваченная клиентом (ответ есть, через физику не ушла), — пропуск с пометкой.
func TestRunAnswerNotSentPhysicallyIsSkipped(t *testing.T) {
	r := answeredWith(egressEvidence{sent: false})
	eq(t, r.Probes[0].Class, Skipped)
	eq(t, r.Probes[0].Detail, "перехвачено клиентом туннеля, через физический адаптер не ушло")
}

// Все пробы перехвачены — проверять нечего: нет уверенности, как при одних пропусках.
func TestRunAllInterceptedIsInconclusive(t *testing.T) {
	eq(t, answeredWith(egressEvidence{sent: false}).Overall, Inconclusive)
}

// Итог — по остальным пробам: перехвачен TCP, UDP отброшен нашим правилом → BLOCKED.
func TestRunInterceptedTCPWithBlockedUDPIsBlocked(t *testing.T) {
	p := &fakeProber{answeredProto: "tcp"}
	r := Run(context.Background(), oneTarget, p, egressEvidence{fakeEvidence: fakeEvidence{dropped: true}}, now)
	eq(t, r.Overall, Blocked)
}

func TestRunAnswerSentPhysicallyIsLeak(t *testing.T) {
	eq(t, answeredWith(egressEvidence{sent: true}).Overall, Leak)
}

func TestRunAnswerEgressUnknownIsLeak(t *testing.T) {
	eq(t, answeredWith(egressEvidence{err: errors.New("нет счётчика")}).Overall, Leak)
}
