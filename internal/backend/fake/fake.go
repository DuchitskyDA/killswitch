// Package fake — фейковый backend для тестов ядра: держит «установленный» набор в памяти.
package fake

import (
	"fmt"
	"strings"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// Ruleset — план фейка.
type Ruleset struct {
	Mode policy.Mode
	Text string
}

// Render — текст плана.
func (r Ruleset) Render() string { return r.Text }

// Backend — фейк. Поля *Err задают сбои, Installed — набор «в системе».
type Backend struct {
	Caps        policy.Capabilities
	Env         env.Env
	SnapshotErr error
	PlanErr     error
	ApplyErr    error
	RemoveErr   error
	Structural  []probe.StructuralFinding
	Dropped     bool
	ApplyDrifts bool              // Apply ставит не тот набор, что в плане
	Running     []backend.Program // запущенные программы (backend.ProgramLister)

	Snapshots int // число вызовов Snapshot

	Installed *Ruleset
	// RulesGone — установка на месте (постоянный слой), а правил в системе нет: Status.Active без правил.
	RulesGone bool
	Applies   []Ruleset
	Removes   int
}

var _ backend.Backend = (*Backend)(nil)

// Capabilities — заданные возможности.
func (b *Backend) Capabilities() policy.Capabilities { return b.Caps }

// Snapshot — заданный снимок.
func (b *Backend) Snapshot(policy.Policy) (env.Env, error) {
	b.Snapshots++
	return b.Env, b.SnapshotErr
}

// Plan — детерминированный текст из политики и снимка.
func (b *Backend) Plan(p policy.Policy, e env.Env) (backend.Ruleset, error) {
	if b.PlanErr != nil {
		return nil, b.PlanErr
	}
	var tun []string
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		tun = append(tun, fmt.Sprintf("%s#%d", i.Name, i.Index))
	}
	text := fmt.Sprintf("mode=%s tunnel=%s dns=%s health=%s lan=%t trust=%v repair=%v",
		p.Mode, strings.Join(tun, ","), p.DNS, e.Health, p.LAN, p.Trust, p.Repair.Programs)
	if p.Mode == policy.ModeRepair {
		for _, n := range p.Repair.Names {
			text += fmt.Sprintf(" name:%s=%v", n, e.Programs[backend.NameKey(n)])
		}
	}
	return Ruleset{Mode: p.Mode, Text: text}, nil
}

// RunningPrograms — заданный список запущенных программ.
func (b *Backend) RunningPrograms() ([]backend.Program, error) { return b.Running, nil }

// Apply «устанавливает» набор.
func (b *Backend) Apply(r backend.Ruleset) error {
	if b.ApplyErr != nil {
		return b.ApplyErr
	}
	rs := r.(Ruleset)
	if b.ApplyDrifts {
		rs.Text += " drifted"
	}
	b.Installed = &rs
	b.Applies = append(b.Applies, rs)
	var left []probe.StructuralFinding
	for _, f := range b.Structural {
		if !f.Repair {
			left = append(left, f)
		}
	}
	b.Structural = left // Apply устраняет устранимое
	return nil
}

// Remove снимает набор.
func (b *Backend) Remove() error {
	if b.RemoveErr != nil {
		return b.RemoveErr
	}
	b.Installed = nil
	b.Removes++
	return nil
}

// Status — хеш считается из «установленного» набора.
func (b *Backend) Status() (backend.Status, error) {
	if b.Installed == nil {
		return backend.Status{Structural: b.Structural}, nil
	}
	if b.RulesGone {
		return backend.Status{Active: true, Hash: "fact-gone", Structural: b.Structural}, nil
	}
	return backend.Status{Active: true, Mode: b.Installed.Mode, Rules: 1, Hash: backend.HashOf(*b.Installed),
		Structural: b.Structural}, nil
}

// Tamper имитирует чужую правку правил (дрейф).
func (b *Backend) Tamper() {
	b.Installed = &Ruleset{Mode: b.Installed.Mode, Text: b.Installed.Text + " tampered"}
}

// Evidence — заданное свидетельство.
func (b *Backend) Evidence(probe.ProbeID, time.Time) (bool, error) { return b.Dropped, nil }

// BindControl — без привязки.
func (b *Backend) BindControl(env.Iface) backend.ControlFunc { return nil }
