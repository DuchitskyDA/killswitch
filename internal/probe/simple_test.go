package probe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

// noTargets — check без своих адресов: простая проверка.
var noTargets = Input{Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}

// eth6 — физический интерфейс с адресами обоих семейств.
var eth6 = env.Iface{Name: "eth0", Index: 2, Up: true, Physical: true, DefaultRoute4: true, DefaultRoute6: true,
	Addrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24"), netip.MustParsePrefix("2001:db8:a::2/64")}}

var errTimeout = errors.New("timeout")

// С физического адаптера ответа нет, обычным путём сайт отвечает — утечек не найдено; свидетельство отброса
// не требуется.
func TestRunSimpleNoAnswerPlainOKIsBlocked(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4}}
	r := run(noTargets, p, fakeEvidence{})
	eq(t, r.Simple, true)
	eq(t, r.Overall, Blocked)
	eq(t, len(r.Probes), 1)
	eq(t, r.Probes[0].Target, "203.0.113.130:80")
	eq(t, strings.Contains(r.Probes[0].Detail, "ответа нет"), true)
	eq(t, p.sent[0].Src, netip.MustParseAddrPort("198.51.100.2:30000"))
	eq(t, p.sent[0].Dst, netip.MustParseAddrPort("203.0.113.130:80"))
	eq(t, p.plain, []netip.Addr{target4})
}

func TestRunSimpleSendsHTTPWithHostName(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4}}
	run(noTargets, p, fakeEvidence{})
	eq(t, p.services, []Service{{Name: "http", Proto: "tcp", Port: 80, Host: "example.com"}})
}

// Ответ с физического адаптера — утечка, даже если обычным путём сайт не ответил.
func TestRunSimpleAnswerIsLeak(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4}, answered: true, plainErr: map[netip.Addr]error{target4: errTimeout}}
	r := run(noTargets, p, fakeEvidence{})
	eq(t, r.Overall, Leak)
	eq(t, r.Probes[0].Class, Leak)
}

func TestRunSimpleNoAnswerAnywhereIsInconclusive(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4}, plainErr: map[netip.Addr]error{target4: errTimeout}}
	r := run(noTargets, p, fakeEvidence{dropped: true})
	eq(t, r.Overall, Inconclusive)
	eq(t, strings.Contains(r.Probes[0].Detail, "обычным путём example.com не ответил: timeout"), true)
}

func TestRunSimpleResolveErrorIsInconclusiveWithoutSending(t *testing.T) {
	p := &fakeProber{resolveErr: errors.New("no such host")}
	r := run(noTargets, p, fakeEvidence{})
	eq(t, r.Overall, Inconclusive)
	eq(t, len(r.Probes), 1)
	eq(t, strings.Contains(r.Probes[0].Detail, "no such host"), true)
	eq(t, len(p.sent)+len(p.plain), 0)
}

func TestRunSimpleNoAddressIsInconclusive(t *testing.T) {
	r := run(noTargets, &fakeProber{}, fakeEvidence{})
	eq(t, r.Overall, Inconclusive)
	eq(t, len(r.Probes), 1)
}

// Клиент туннеля с подменой имён отдаёт служебный адрес: проба к нему с адаптера не ответит при любой защите.
func TestRunSimpleNonPublicAddressIsInconclusiveWithoutSending(t *testing.T) {
	for _, a := range []string{"198.18.0.5", "10.0.0.1", "100.64.0.9", "127.0.0.1", "fd00::5", "::ffff:198.18.0.5"} {
		p := &fakeProber{resolved: []netip.Addr{netip.MustParseAddr(a)}}
		r := run(noTargets, p, fakeEvidence{})
		eq(t, r.Overall, Inconclusive)
		eq(t, strings.Contains(r.Probes[0].Detail, "[check] targets"), true)
		eq(t, len(p.sent)+len(p.plain), 0)
	}
}

func TestRunSimpleTakesFirstPublicAddressOfEachFamily(t *testing.T) {
	other4, other6 := netip.MustParseAddr("203.0.113.140"), netip.MustParseAddr("2001:db8:b::3")
	p := &fakeProber{resolved: []netip.Addr{netip.MustParseAddr("198.18.0.5"), target4, other4, target6, other6}}
	in := Input{Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth6}}
	r := run(in, p, fakeEvidence{})
	eq(t, p.plain, []netip.Addr{target4, target6})
	eq(t, len(r.Probes), 2)
	eq(t, r.Overall, Blocked)
}

// Обычным путём ответ засчитывается по любому семейству: у туннеля часто нет IPv6.
func TestRunSimplePlainByAnyFamilyCounts(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4, target6}, plainErr: map[netip.Addr]error{target6: errTimeout}}
	in := Input{Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth6}}
	r := run(in, p, fakeEvidence{})
	eq(t, r.Overall, Blocked)
	eq(t, []Class{r.Probes[0].Class, r.Probes[1].Class}, []Class{Blocked, Blocked})
}

func TestRunSimpleFamilyWithoutAddressIsSkipped(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4, target6}}
	r := run(noTargets, p, fakeEvidence{})
	eq(t, r.Overall, Blocked)
	eq(t, r.Probes[1].Class, Skipped)
	eq(t, len(p.sent), 1)
}

func TestRunSimpleInterceptedIsSkipped(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4}, answered: true}
	r := Run(context.Background(), noTargets, p, egressEvidence{sent: false}, now)
	eq(t, r.Probes[0].Class, Skipped)
	eq(t, r.Overall, Inconclusive)
}

func TestRunSimpleStructuralIsLeak(t *testing.T) {
	in := noTargets
	in.Structural = []StructuralFinding{{Kind: "wfp-tie"}}
	r := run(in, &fakeProber{resolved: []netip.Addr{target4}}, fakeEvidence{})
	eq(t, r.Overall, Leak)
}

func TestRunSimplePreparationFailureIsInconclusiveWithoutSending(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{target4}}
	ev := &preparingEvidence{p: p, err: errors.New("events off")}
	r := Run(context.Background(), noTargets, p, ev, now)
	eq(t, r.Overall, Inconclusive)
	eq(t, len(p.sent), 0)
}

func TestRunSimpleNoPhysicalDefaultRouteIsInconclusive(t *testing.T) {
	in := Input{Tunnels: []env.Iface{tun}, Physical: []env.Iface{vnat}}
	r := run(in, &fakeProber{resolved: []netip.Addr{target4}}, fakeEvidence{})
	eq(t, r.Overall, Inconclusive)
	eq(t, strings.Contains(r.Probes[0].Detail, "маршрута по умолчанию"), true)
}
