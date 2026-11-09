package probe

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

// finishingEvidence считает подготовки и завершения проб.
type finishingEvidence struct {
	dropped   bool
	beforeErr error
	finished  []ProbeID
}

func (f *finishingEvidence) Evidence(ProbeID, time.Time) (bool, error) { return f.dropped, nil }
func (f *finishingEvidence) BeforeProbe(ProbeID) error                 { return f.beforeErr }
func (f *finishingEvidence) AfterProbe(id ProbeID)                     { f.finished = append(f.finished, id) }

// bindFailProber — привязка сокета не удалась (Direct с ошибкой).
type bindFailProber struct{ fakeProber }

func (*bindFailProber) Direct(context.Context, Service, ProbeID, env.Iface) (bool, error) {
	return false, errors.New("bind")
}

var oneTarget = Input{Targets: []netip.Addr{target4}, Tunnels: []env.Iface{tun}, Physical: []env.Iface{eth}}

func finishRun(p Prober, ev *finishingEvidence) CheckResult {
	return Run(context.Background(), oneTarget, p, ev, now)
}

func TestAfterProbeOncePerBlockedProbe(t *testing.T) {
	ev := &finishingEvidence{dropped: true}
	res := finishRun(&fakeProber{}, ev)
	eq(t, res.Overall, Blocked)
	eq(t, len(ev.finished), len(Services))
}

func TestAfterProbeOncePerLeakProbe(t *testing.T) {
	ev := &finishingEvidence{}
	res := finishRun(&fakeProber{answered: true}, ev)
	eq(t, res.Overall, Leak)
	eq(t, len(ev.finished), len(Services))
}

func TestAfterProbeOncePerBindFailure(t *testing.T) {
	ev := &finishingEvidence{dropped: true}
	res := finishRun(&bindFailProber{}, ev)
	eq(t, res.Overall, Inconclusive)
	eq(t, len(ev.finished), len(Services))
}

func TestAfterProbeOncePerPreparerFailure(t *testing.T) {
	ev := &finishingEvidence{beforeErr: errors.New("events")}
	res := finishRun(&fakeProber{}, ev)
	eq(t, res.Overall, Inconclusive)
	eq(t, len(ev.finished), len(Services))
}
