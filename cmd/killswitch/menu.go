package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/profile"
	"github.com/DuchitskyDA/killswitch/internal/state"
	"github.com/DuchitskyDA/killswitch/internal/ui"
)

// menu — killswitch без аргументов в терминале: права администратора, затем меню.
func (a *app) menu(ctx context.Context) error {
	if a.d.admin == nil || !a.d.admin() {
		return a.needAdmin()
	}
	b, err := a.d.backend()
	if err != nil {
		return fail(exitApply, "%v", err)
	}
	a.b = b
	ui.Run(ctx, b.Capabilities(), &menuActions{a: a}, a.d.in, a.d.out)
	return nil
}

// needAdmin: Windows — перезапуск с повышением (меню откроется в новом окне); Linux и macOS — sudo.
func (a *app) needAdmin() error {
	if a.d.elevate == nil {
		return fail(exitConfig, "нужны права root: запустите sudo killswitch")
	}
	if err := a.d.elevate(); err != nil {
		return fail(exitConfig, "права администратора не получены: %v", err)
	}
	fmt.Fprintln(a.d.out, "меню откроется в новом окне с правами администратора")
	return nil
}

// menuActions — действия меню поверх тех же функций, что команды on/off/repair/check.
type menuActions struct{ a *app }

var _ ui.Actions = (*menuActions)(nil)

var errNoSettings = errors.New("нет настроек — откройте «Настройки» и выберите «Применить и сохранить»")

func (m *menuActions) ownConfig() string { return filepath.Join(m.a.d.dir, "config.toml") }

// useOwnConfig — действия меню работают с конфигом службы.
func (m *menuActions) useOwnConfig() error {
	m.a.configPath, m.a.configData = m.ownConfig(), nil
	if _, err := os.Stat(m.a.configPath); errors.Is(err, fs.ErrNotExist) {
		return errNoSettings
	}
	return nil
}

func (m *menuActions) Transition(mode policy.Mode) error {
	if err := m.useOwnConfig(); err != nil {
		return err
	}
	return printed(m.a.transition(mode))
}

func (m *menuActions) Check(ctx context.Context) error {
	if err := m.useOwnConfig(); err != nil {
		return err
	}
	return printed(m.a.check(ctx))
}

// printed: ошибка без текста — итог команда уже напечатала (check: LEAK, INCONCLUSIVE).
func printed(err error) error {
	var ce cliError
	if errors.As(err, &ce) && (ce.err == nil || ce.err.Error() == "") {
		return nil
	}
	return err
}

// Header — шапка по тем же признакам, что status: режим, намерение, дрейф, Structural, совпавшие адаптеры.
func (m *menuActions) Header() ui.Header {
	a := m.a
	var h ui.Header
	note := func(format string, args ...any) { h.Notes = append(h.Notes, fmt.Sprintf(format, args...)) }
	st, stErr := state.Load(a.statePath())
	recorded := stErr == nil
	switch {
	case recorded:
		h.Mode = st.Mode
		if st.Intent != nil {
			note("WARN незавершённый переход к %s (поколение %d): enforce доведёт", st.Intent.Target, st.Intent.Gen)
		}
	case !errors.Is(stErr, fs.ErrNotExist):
		note("WARN %v: при наших правилах действует on", stErr)
	}
	s, err := a.b.Status()
	if err != nil {
		note("WARN статус backend: %v", err)
		return h
	}
	h.Active = s.Active
	if !recorded && s.Active {
		h.Mode = policy.ModeOn
	}
	if recorded && s.Active && s.Hash != st.AppliedHash {
		note("WARN фактические правила расходятся с записанными: enforce восстановит")
	}
	for _, f := range s.Structural {
		note("LEAK %s: %s", f.Kind, f.Detail)
	}
	var notes []string
	h.Tunnels, notes = m.tunnels(st)
	h.Notes = append(h.Notes, notes...)
	return h
}

// tunnels — совпавшие адаптеры туннеля; предупреждения снимка — строками шапки.
func (m *menuActions) tunnels(st state.State) ([]ui.Tunnel, []string) {
	a := m.a
	if err := m.useOwnConfig(); err != nil {
		return nil, []string{"WARN " + err.Error()}
	}
	p, err := a.loadPolicy(policy.ModeOn)
	if err != nil {
		return nil, []string{"WARN туннель не проверен: " + err.Error()}
	}
	var warn bytes.Buffer
	saved := a.d.err
	a.d.err = &warn
	e, err := a.snapshot(p, st, env.HealthUnknown)
	a.d.err = saved
	notes := splitLines(warn.String())
	if err != nil {
		return nil, append(notes, "WARN "+err.Error())
	}
	var out []ui.Tunnel
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		out = append(out, ui.Tunnel{Name: i.Name, Up: i.Up})
	}
	if len(out) > 1 {
		notes = append(notes, "WARN шаблону туннеля соответствует больше одного адаптера: чужой адаптер с тем же именем не отличить")
	}
	return out, notes
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Detect — профили, чей detect нашёл путь (как команда detect).
func (m *menuActions) Detect() []string {
	all, err := profile.Load(m.a.d.profiles)
	if err != nil {
		return nil
	}
	var found []string
	for _, name := range profile.Names(all) {
		sec, _ := all[name].Section(m.a.b.Capabilities().OS)
		for _, pattern := range sec.Detect {
			if paths, _ := m.a.d.glob(pattern); len(paths) > 0 {
				found = append(found, name)
				break
			}
		}
	}
	return found
}

// Running — запущенные программы, если backend умеет их перечислять (Windows).
func (m *menuActions) Running() ([]backend.Program, error) {
	if l, ok := m.a.b.(backend.ProgramLister); ok {
		return l.RunningPrograms()
	}
	return nil, nil
}

// Profiles — встроенные профили с секцией текущей ОС.
func (m *menuActions) Profiles() []ui.Profile {
	all, err := profile.Load(m.a.d.profiles)
	if err != nil {
		return nil
	}
	var out []ui.Profile
	for _, name := range profile.Names(all) {
		if sec, ok := all[name].Section(m.a.b.Capabilities().OS); ok {
			out = append(out, ui.Profile{Name: name, Description: all[name].Description, Layer: sec.Layer()})
		}
	}
	return out
}

func (m *menuActions) LoadConfig() (policy.Config, error) {
	data, err := os.ReadFile(m.ownConfig())
	if errors.Is(err, fs.ErrNotExist) {
		return policy.Config{}, nil
	}
	if err != nil {
		return policy.Config{}, err
	}
	return policy.ParseConfig(data)
}

// Save: байты — во временный файл каталога состояния, дальше путь команды on (ParseConfig → Build → Validate →
// Snapshot → Plan → adoptConfig → Apply). adoptConfig атомарно пишет config.toml только после принятого плана.
// Защита не установлена — та же проверка и запись без Apply. Выбор режима и применение — под одним замком.
func (m *menuActions) Save(data []byte) (string, error) {
	a := m.a
	defer func() { a.configPath, a.configData = m.ownConfig(), nil }()
	tmp, err := writeTemp(a.d.dir, data)
	if err != nil {
		return "", fmt.Errorf("не сохранено: %w", err)
	}
	defer os.Remove(tmp)
	var mode policy.Mode
	installed := false
	err = a.underLock(func() error {
		a.configPath, a.configData = tmp, nil
		var err error
		if mode, installed, err = m.currentMode(); err != nil {
			return err
		}
		if !installed {
			return m.verifyAndAdopt()
		}
		return a.transition(mode)
	})
	switch {
	case err == nil && installed:
		return fmt.Sprintf("сохранено и применено (%s)", mode), nil
	case err == nil:
		return "сохранено; защита не включена — «Включить защиту»", nil
	}
	if own, rerr := os.ReadFile(m.ownConfig()); rerr == nil && bytes.Equal(own, data) {
		return "сохранено, но не применено", err
	}
	return "", fmt.Errorf("не сохранено: %w", err)
}

// underLock держит общий замок всё время fn; вложенные шаги (transition) не ждут его повторно.
// Так параллельная команда не вклинится между выбором режима и применением.
func (a *app) underLock(fn func() error) error {
	release, err := a.withLock()
	if err != nil {
		return err
	}
	defer release()
	lock := a.d.lock
	a.d.lock = func(string) (func(), error) { return func() {}, nil }
	defer func() { a.d.lock = lock }()
	return fn()
}

// currentMode — режим для нового конфига по правилу enforce (targetMode): новая загрузка — on, незавершённое
// намерение — его цель, иначе записанный режим; записи нет при наших правилах — on. installed=false — защиты нет.
func (m *menuActions) currentMode() (policy.Mode, bool, error) {
	a := m.a
	st, err := state.Load(a.statePath())
	recorded := err == nil
	if !recorded {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, state.ErrCorrupt) {
			return "", false, fail(exitApply, "state.json: %v", err)
		}
		s, err := a.b.Status()
		if err != nil {
			return "", false, fail(exitApply, "статус backend: %v", err)
		}
		if !s.Active {
			return "", false, nil
		}
		st = state.State{}
	}
	p, err := a.loadPolicy(policy.ModeOn)
	if err != nil {
		return "", false, err
	}
	e, err := a.bootSnapshot(p, st, env.HealthUnknown)
	if err != nil {
		return "", false, err
	}
	if target := targetMode(st, recorded, e.BootID); target != "" {
		return target, true, nil
	}
	return policy.ModeOn, true, nil
}

// verifyAndAdopt — проверка конфига путём plan on (без Apply) и атомарная запись config.toml; замок держит Save.
func (m *menuActions) verifyAndAdopt() error {
	a := m.a
	out := a.d.out
	a.d.out = io.Discard
	err := a.plan([]string{string(policy.ModeOn)})
	a.d.out = out
	if err != nil {
		return err
	}
	if err := a.adoptConfig(); err != nil {
		return fail(exitApply, "config.toml: %v", err)
	}
	return nil
}

func writeTemp(dir string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "config.toml.menu-*.tmp")
	if err != nil {
		return "", err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
