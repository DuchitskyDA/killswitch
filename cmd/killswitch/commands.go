package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/profile"
	"github.com/DuchitskyDA/killswitch/internal/state"
)

// enforceInterval — пересчёт наблюдателя без событий.
const enforceInterval = 60 * time.Second

func (a *app) uninstall() error {
	release, err := a.withLock()
	if err != nil {
		return err
	}
	defer release()
	if err := a.b.Remove(); err != nil {
		return fail(exitApply, "снятие правил: %v", err)
	}
	if err := state.Remove(a.statePath()); err != nil {
		return fail(exitApply, "state.json: %v", err)
	}
	fmt.Fprintln(a.d.out, "правила killswitch сняты, state.json удалён")
	return nil
}

func (a *app) plan(args []string) error {
	mode := policy.ModeOn
	st, err := state.Load(a.statePath())
	if err == nil && st.Mode != "" {
		mode = st.Mode
	}
	if len(args) > 0 {
		m, err := policy.ParseMode(args[0])
		if err != nil {
			return fail(exitConfig, "%v", err)
		}
		mode = m
	}
	p, err := a.loadPolicy(mode)
	if err != nil {
		return err
	}
	e, err := a.snapshot(p, st, env.HealthUnknown)
	if err != nil {
		return err
	}
	r, err := a.planFor(p, e)
	if err != nil {
		return err
	}
	fmt.Fprint(a.d.out, r.Render())
	if mode == policy.ModeRepair {
		a.reportRepairNames(p, e)
	}
	return nil
}

// reportRepairNames — какие файлы найдены по каждому имени repair.names (пути — из того же снимка, что правила).
func (a *app) reportRepairNames(p policy.Policy, e env.Env) {
	for _, n := range p.Repair.Names {
		files := "не найдено"
		if found := e.Programs[backend.NameFilesKey(n)]; len(found) > 0 {
			files = strings.Join(found, ", ")
		}
		fmt.Fprintf(a.d.out, "починка: %s — %s\n", n, files)
	}
}

func (a *app) status() error {
	st, stErr := state.Load(a.statePath())
	s, err := a.b.Status()
	if err != nil {
		return fail(exitApply, "статус backend: %v", err)
	}
	switch {
	case stErr == nil:
		fmt.Fprintf(a.d.out, "режим: %s (поколение %d)\n", st.Mode, st.Gen)
		if st.Intent != nil {
			fmt.Fprintf(a.d.out, "WARN незавершённый переход к %s (поколение %d): enforce доведёт\n", st.Intent.Target, st.Intent.Gen)
		}
		if s.Active && s.Hash != st.AppliedHash {
			fmt.Fprintln(a.d.out, "WARN фактические правила расходятся с записанными: enforce восстановит")
		}
	case errors.Is(stErr, fs.ErrNotExist):
		fmt.Fprintln(a.d.out, "режим: не установлен")
	default:
		fmt.Fprintf(a.d.out, "WARN %v: при наших правилах действует on\n", stErr)
	}
	fmt.Fprintf(a.d.out, "правила: активны=%t режим=%s фильтров=%d %s\n", s.Active, s.Mode, s.Rules, s.Details)
	snapErr := a.printTunnelMatches(st)
	for _, f := range s.Structural {
		fmt.Fprintf(a.d.out, "LEAK %s: %s\n", f.Kind, f.Detail)
	}
	if len(s.Structural) > 0 {
		return cliError{code: exitLeak, err: errors.New("")}
	}
	return snapErr
}

// printTunnelMatches — совпавшие туннельные адаптеры и, где есть repair, файлы по именам repair.names.
// Конфиг не читается — WARN (status работает и без него); сбой снимка — ошибка backend (код 3).
func (a *app) printTunnelMatches(st state.State) error {
	p, err := a.loadPolicy(policy.ModeOn)
	if err != nil {
		fmt.Fprintf(a.d.out, "WARN туннель не проверен: %v\n", err)
		return nil
	}
	e, err := a.snapshot(p, st, env.HealthUnknown)
	if err != nil {
		return err
	}
	a.reportTunnels(e.MatchIfaces(p.Tunnel.Interfaces))
	if a.b.Capabilities().Repair {
		a.reportRepairNames(p, e)
	}
	return nil
}

// severalTunnels — предупреждение: шаблону туннеля соответствует больше одного адаптера.
const severalTunnels = "WARN шаблону туннеля соответствует больше одного адаптера: чужой адаптер с тем же именем не отличить"

// reportTunnels печатает совпавшие адаптеры туннеля.
func (a *app) reportTunnels(matched []env.Iface) {
	var names []string
	for _, i := range matched {
		names = append(names, fmt.Sprintf("%s (index %d, up=%t)", i.Name, i.Index, i.Up))
	}
	fmt.Fprintf(a.d.out, "туннель: %s\n", strings.Join(names, ", "))
	if len(matched) > 1 {
		fmt.Fprintln(a.d.out, severalTunnels)
	}
}

// checkInput — вход проб по конфигу и снимку машины и совпавшие адаптеры туннеля. В out ничего
// не печатает: его используют команда check и окно.
func (a *app) checkInput() (probe.Input, []env.Iface, error) {
	p, err := a.loadPolicy(policy.ModeOn)
	if err != nil {
		return probe.Input{}, nil, err
	}
	st, _ := state.Load(a.statePath())
	e, err := a.snapshot(p, st, env.HealthUnknown)
	if err != nil {
		return probe.Input{}, nil, err
	}
	s, err := a.b.Status()
	if err != nil {
		return probe.Input{}, nil, fail(exitApply, "статус backend: %v", err)
	}
	in := probe.Input{Targets: p.Check.Targets, Routes: e.Routes, Structural: s.Structural}
	matched := e.MatchIfaces(p.Tunnel.Interfaces)
	for _, i := range matched {
		if i.Up {
			in.Tunnels = append(in.Tunnels, i)
		}
	}
	for _, i := range e.Ifaces {
		if i.Physical && i.Up {
			in.Physical = append(in.Physical, i)
		}
	}
	return in, matched, nil
}

func (a *app) check(ctx context.Context) error {
	in, matched, err := a.checkInput()
	if err != nil {
		return err
	}
	a.reportTunnels(matched)
	if len(in.Targets) == 0 {
		fmt.Fprintf(a.d.out, "простая проверка: HTTP к %s с каждого физического адаптера и обычным путём ([check] targets не заданы)\n", probe.SimpleHost)
	}
	res := probe.Run(ctx, in, a.d.prober(a.b), a.b, a.d.now)
	for _, r := range res.Probes {
		fmt.Fprintf(a.d.out, "%s %s %s %s %s: %s\n", r.Class, r.Iface, r.Family, r.Proto, r.Target, r.Detail)
	}
	for _, f := range res.Structural {
		fmt.Fprintf(a.d.out, "LEAK %s: %s\n", f.Kind, f.Detail)
	}
	fmt.Fprintf(a.d.out, "итог: %s\n", res.Overall)
	if res.Simple {
		fmt.Fprintln(a.d.out, simpleVerdict(res))
	}
	if code := probe.ExitCode(res.Overall); code != exitOK {
		return cliError{code: code, err: errors.New("")}
	}
	return nil
}

// simpleVerdict — итог простой проверки словами: что она показала и чего не проверяла.
func simpleVerdict(res probe.CheckResult) string {
	switch res.Overall {
	case probe.Blocked:
		return "утечек не найдено (простая проверка)\n" +
			"проверен только TCP; UDP и DNS не проверялись — для полной проверки задайте свои адреса ([check] targets)"
	case probe.Leak:
		return "УТЕЧКА (простая проверка)"
	}
	return "нет уверенности (простая проверка): " + inconclusiveReason(res)
}

// inconclusiveReason — почему итог не определён: подробность первой пробы без уверенности.
func inconclusiveReason(res probe.CheckResult) string {
	for _, r := range res.Probes {
		if r.Class == probe.Inconclusive {
			return r.Detail
		}
	}
	return "ни одной пробы не выполнено"
}

func (a *app) detect() error {
	all, err := profile.Load(a.d.profiles)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	found := 0
	for _, name := range profile.Names(all) {
		sec, _ := all[name].Section(a.d.goos)
		for _, pattern := range sec.Detect {
			paths, _ := a.d.glob(pattern)
			for _, path := range paths {
				fmt.Fprintf(a.d.out, "%s: %s\n", name, path)
				found++
			}
		}
	}
	if found == 0 {
		fmt.Fprintln(a.d.out, "клиенты из встроенных профилей не найдены")
	}
	return nil
}

// enforce — наблюдатель: шаг при старте, раз в enforceInterval, по событиям Watcher и при смене здоровья.
func (a *app) enforce(ctx context.Context) error {
	m := health.NewMachine()
	var p policy.Policy
	step := func() {
		var err error
		if p, err = a.reconcile(m.State()); err != nil {
			fmt.Fprintln(a.d.err, "killswitch enforce:", err)
		}
	}
	step()
	full := time.NewTicker(enforceInterval)
	defer full.Stop()
	hc := time.NewTicker(health.Interval)
	defer hc.Stop()
	var changes <-chan struct{}
	if w, ok := a.b.(backend.Watcher); ok {
		changes = w.Changes()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-full.C:
			step()
		case <-changes:
			step()
		case <-hc.C:
			if p.DNS != policy.DNSTunnelUp {
				continue
			}
			if a.healthChanged(ctx, m, p) {
				step()
			}
		}
	}
}

// healthChanged — одна проверка здоровья по свежему снимку (маршрут к dns.health мог смениться без события).
func (a *app) healthChanged(ctx context.Context, m *health.Machine, p policy.Policy) bool {
	before := m.State()
	e, err := a.b.Snapshot(p)
	if err != nil {
		return m.Observe(a.d.now(), false) != before
	}
	return m.Step(ctx, a.d.now(), e, p) != before
}
