package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/state"
)

// transition — команды on, off, repair. off и repair — до перезагрузки: после неё enforce вернёт on.
func (a *app) transition(target policy.Mode) error {
	release, err := a.withLock()
	if err != nil {
		return err
	}
	defer release()
	st, err := state.Load(a.statePath())
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, state.ErrCorrupt) {
			return fail(exitApply, "state.json: %v", err)
		}
		st = state.State{}
	}
	p, err := a.loadPolicy(target)
	if err != nil {
		return err
	}
	e, err := a.bootSnapshot(p, st, env.HealthUnknown)
	if err != nil {
		return err
	}
	r, err := a.planFor(p, e)
	if err != nil {
		return err
	}
	// Конфиг службы меняется только на принятый план: отвергнутый не сломает enforce.
	if err := a.adoptConfig(); err != nil {
		return fail(exitApply, "config.toml: %v", err)
	}
	if err := a.apply(st, target, r, e); err != nil {
		return err
	}
	fmt.Fprintf(a.d.out, "режим %s применён\n", target)
	return nil
}

// reconcile — один шаг enforce под замком: определить цель, сверить факт, довести.
// Возвращает политику для проверок здоровья между шагами.
func (a *app) reconcile(h env.HealthState) (policy.Policy, error) {
	release, err := a.withLock()
	if err != nil {
		return policy.Policy{}, err
	}
	defer release()
	st, err := state.Load(a.statePath())
	recorded := err == nil
	if !recorded {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, state.ErrCorrupt) {
			return policy.Policy{}, fail(exitApply, "state.json: %v", err)
		}
		s, serr := a.b.Status()
		if serr != nil {
			return policy.Policy{}, fail(exitApply, "статус backend: %v", serr)
		}
		if !s.Active {
			return policy.Policy{}, nil // не установлен: нечего охранять
		}
		st = state.State{} // наши правила есть, записи нет — fail-closed: on
	}
	p, err := a.loadPolicy(policy.ModeOn)
	if err != nil {
		return policy.Policy{}, err
	}
	e, err := a.bootSnapshot(p, st, h)
	if err != nil {
		return p, err
	}
	target := targetMode(st, recorded, e.BootID)
	if p, err = a.loadPolicy(target); err != nil {
		return p, err
	}
	r, err := a.planFor(p, e)
	if err != nil {
		return p, err
	}
	return p, a.converge(st, recorded, target, r, e)
}

// bootSnapshot — снимок для смены правил: без boot id нельзя отличить новую загрузку от перезапуска службы,
// поэтому пустой BootID — ошибка без Apply (fail-closed: после загрузки уже стоит on).
func (a *app) bootSnapshot(p policy.Policy, st state.State, h env.HealthState) (env.Env, error) {
	e, err := a.snapshot(p, st, h)
	if err == nil && e.BootID == "" {
		return env.Env{}, fail(exitApply, "снимок машины: backend не сообщил boot id")
	}
	return e, err
}

// targetMode: нет записи → on; новая загрузка → on; незавершённое намерение → его цель; иначе записанный режим.
func targetMode(st state.State, recorded bool, bootID string) policy.Mode {
	switch {
	case !recorded:
		return policy.ModeOn
	case st.BootID != "" && bootID != "" && st.BootID != bootID:
		return policy.ModeOn
	case st.Intent != nil:
		return st.Intent.Target
	}
	return st.Mode
}

// converge доводит факт до плана: дрейф — Apply; факт уже совпал (сбой после Apply) — только фиксация.
func (a *app) converge(st state.State, recorded bool, target policy.Mode, r backend.Ruleset, e env.Env) error {
	s, err := a.b.Status()
	if err != nil {
		return fail(exitApply, "статус backend: %v", err)
	}
	h := backend.HashOf(r)
	if s.Hash != h || repairable(s) {
		return a.apply(st, target, r, e)
	}
	settled := recorded && st.Intent == nil && st.Mode == target && st.PlanHash == h && st.BootID == e.BootID
	if settled {
		return nil
	}
	return a.save(commit(st, target, h, s, e, a.d.now))
}

// apply: намерение → Apply → Status → фиксация. Сбой Apply оставляет намерение для enforce.
// Намерение помечается текущей загрузкой: после перезагрузки незавершённый off/repair уступает on.
func (a *app) apply(st state.State, target policy.Mode, r backend.Ruleset, e env.Env) error {
	h := backend.HashOf(r)
	st.Intent = &state.Intent{Gen: st.Gen + 1, Target: target, PlanHash: h}
	st.BootID = e.BootID
	st.UpdatedAt = a.d.now()
	if err := a.save(st); err != nil {
		return err
	}
	if err := a.b.Apply(r); err != nil {
		return fail(exitApply, "применение %s: %v (намерение записано, enforce доведёт)", target, err)
	}
	s, err := a.b.Status()
	if err != nil {
		return fail(exitApply, "статус backend после применения: %v", err)
	}
	if err := a.save(commit(st, target, h, s, e, a.d.now)); err != nil {
		return err
	}
	if s.Hash != h {
		return fail(exitApply, "фактические правила после применения не совпали с планом")
	}
	if repairable(s) {
		return fail(exitApply, "после применения защита всё ещё не действует: %v", s.Structural)
	}
	return nil
}

// repairable — есть структурная находка, которую устраняет повторный Apply.
func repairable(s backend.Status) bool {
	for _, f := range s.Structural {
		if f.Repair {
			return true
		}
	}
	return false
}

func (a *app) save(st state.State) error {
	if err := state.Save(a.statePath(), st); err != nil {
		return fail(exitApply, "state.json: %v", err)
	}
	return nil
}

// commit фиксирует поколение: режим, хеши, boot id, признаки pf и последние известные адреса.
func commit(st state.State, target policy.Mode, planHash string, s backend.Status, e env.Env, now func() time.Time) state.State {
	next := st.Gen + 1
	if st.Intent != nil {
		next = st.Intent.Gen
	}
	last := make(map[string][]netip.Addr, len(st.LastKnown)+len(e.Resolved))
	for name, addrs := range st.LastKnown {
		last[name] = addrs
	}
	for name, addrs := range e.Resolved {
		if len(addrs) > 0 {
			last[name] = addrs
		}
	}
	return state.State{Gen: next, Mode: target, BootID: e.BootID, PlanHash: planHash, AppliedHash: s.Hash,
		PFToken: s.Token, AnchorOK: s.AnchorOK, LastKnown: last, UpdatedAt: now()}
}
