package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/profile"
	"github.com/DuchitskyDA/killswitch/internal/state"
	"github.com/DuchitskyDA/killswitch/internal/window"
)

// Коды выхода CLI.
const (
	exitOK           = 0
	exitConfig       = 2
	exitApply        = 3
	exitLeak         = 4
	exitInconclusive = 5
)

const usage = `использование: killswitch [-config путь] <команда>
  (без команды в терминале — меню)
  on | off | repair     включить, выключить до перезагрузки, repair (Windows) до перезагрузки
  status                состояние; код 4 — структурная утечка
  check                 пробы утечки; 0 — блок, 4 — утечка, 5 — нет уверенности
  detect                найти установленные клиенты по профилям
  window                окно: состояние и настройки на локальной странице
  enforce               наблюдатель (служба)
  uninstall             снять всё без конфига и сети
  plan [on|off|repair]  напечатать правила без применения`

// deps — всё внешнее для ядра CLI; в тестах подменяется.
type deps struct {
	goos     string
	dir      string // каталог state.json и config.toml
	backend  func() (backend.Backend, error)
	lock     func(dir string) (release func(), err error)
	now      func() time.Time
	out, err io.Writer
	profiles fs.FS
	glob     func(pattern string) ([]string, error)
	prober   func(b backend.Backend) probe.Prober
	// Меню (killswitch без аргументов) и окно (killswitch window): ввод, терминал ли stdin/stdout,
	// права администратора, перезапуск команды с повышением (nil — ОС без повышения: нужен sudo).
	in       io.Reader
	terminal func() bool
	admin    func() bool
	elevate  func(command string) error
	// Окно: машина, на которой оно открывается, и срок ожидания первого открытия (0 — по умолчанию).
	host        window.Host
	windowStart time.Duration
}

type app struct {
	d          deps
	b          backend.Backend
	configPath string
	configData []byte // байты последнего проверенного loadPolicy конфига; их и принимает служба
}

// cliError — ошибка с кодом выхода.
type cliError struct {
	code int
	err  error
}

func (e cliError) Error() string { return e.err.Error() }

func fail(code int, format string, args ...any) error {
	return cliError{code: code, err: fmt.Errorf(format, args...)}
}

func run(ctx context.Context, args []string, d deps) int {
	fsFlags := flag.NewFlagSet("killswitch", flag.ContinueOnError)
	fsFlags.SetOutput(d.err)
	configPath := fsFlags.String("config", filepath.Join(d.dir, "config.toml"), "путь к config.toml")
	if len(args) == 0 && d.terminal != nil && d.terminal() {
		return exitCode(d, (&app{d: d, configPath: *configPath}).menu(ctx))
	}
	if err := fsFlags.Parse(args); err != nil || fsFlags.NArg() == 0 {
		fmt.Fprintln(d.err, usage)
		return exitConfig
	}
	a := &app{d: d, configPath: *configPath}
	return exitCode(d, a.dispatch(ctx, fsFlags.Arg(0), fsFlags.Args()[1:]))
}

// exitCode печатает ошибку и возвращает код выхода.
func exitCode(d deps, err error) int {
	var ce cliError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ce):
		if ce.err != nil && ce.err.Error() != "" {
			fmt.Fprintln(d.err, "killswitch:", ce.err)
		}
		return ce.code
	}
	fmt.Fprintln(d.err, "killswitch:", err)
	return exitApply
}

func (a *app) dispatch(ctx context.Context, cmd string, rest []string) error {
	switch cmd {
	case "detect":
		return a.detect()
	case "window":
		return a.window(ctx)
	}
	known := map[string]bool{"on": true, "off": true, "repair": true, "status": true, "check": true,
		"enforce": true, "uninstall": true, "plan": true}
	if !known[cmd] {
		return fail(exitConfig, "неизвестная команда %q\n%s", cmd, usage)
	}
	b, err := a.d.backend()
	if err != nil {
		return fail(exitApply, "%v", err)
	}
	a.b = b
	switch cmd {
	case "on", "off", "repair":
		return a.transition(policy.Mode(cmd))
	case "status":
		return a.status()
	case "check":
		return a.check(ctx)
	case "enforce":
		return a.enforce(ctx)
	case "uninstall":
		return a.uninstall()
	}
	return a.plan(rest)
}

func (a *app) statePath() string { return filepath.Join(a.d.dir, state.FileName) }

// adoptConfig: конфиг из флага -config становится конфигом службы (<каталог>/config.toml),
// чтобы enforce после загрузки и наблюдатель применяли тот же набор, что и команда.
func (a *app) adoptConfig() error {
	own := filepath.Join(a.d.dir, "config.toml")
	if filepath.Clean(a.configPath) == filepath.Clean(own) {
		return nil
	}
	data := a.configData
	if data == nil {
		return errors.New("конфиг не проверен до копирования")
	}
	if err := os.MkdirAll(a.d.dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.d.dir, "config.toml.*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), own)
}

// loadPolicy: конфиг → профиль → политика в режиме mode, проверенная по возможностям ОС. Ошибка — код 2.
func (a *app) loadPolicy(mode policy.Mode) (policy.Policy, error) {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return policy.Policy{}, fail(exitConfig, "конфиг: %v", err)
	}
	cfg, err := policy.ParseConfig(data)
	if err != nil {
		return policy.Policy{}, fail(exitConfig, "%v", err)
	}
	a.configData = data
	caps := a.b.Capabilities()
	layer, err := a.profileLayer(cfg.Profile, caps.OS)
	if err != nil {
		return policy.Policy{}, err
	}
	p, err := policy.Build(layer, cfg)
	if err != nil {
		return policy.Policy{}, fail(exitConfig, "%v", err)
	}
	p = p.WithMode(mode)
	if err := p.Validate(caps); err != nil {
		return policy.Policy{}, fail(exitConfig, "%v", err)
	}
	return p, nil
}

func (a *app) profileLayer(name, goos string) (policy.Layer, error) {
	if name == "" {
		return policy.Layer{}, nil
	}
	all, err := profile.Load(a.d.profiles)
	if err != nil {
		return policy.Layer{}, fail(exitConfig, "%v", err)
	}
	p, ok := all[name]
	if !ok {
		return policy.Layer{}, fail(exitConfig, "профиль %q не найден (есть: %v)", name, profile.Names(all))
	}
	sec, ok := p.Section(goos)
	if !ok {
		return policy.Layer{}, fail(exitConfig, "в профиле %q нет секции [%s]", name, goos)
	}
	return sec.Layer(), nil
}

// snapshot: снимок машины с последними известными адресами из state.json. Health — заданное ядром.
func (a *app) snapshot(p policy.Policy, st state.State, h env.HealthState) (env.Env, error) {
	e, err := a.b.Snapshot(p)
	if err != nil {
		return env.Env{}, fail(exitApply, "снимок машины: %v", err)
	}
	e, warns := env.WithLastKnown(e, st.LastKnown)
	for _, w := range warns {
		fmt.Fprintln(a.d.err, w)
	}
	e.Health = h
	return e, nil
}

// planFor: проверка списка repair и чистый план. Шаблон пути без файлов — ошибка; имя без файлов —
// предупреждение; по всему списку нет ни одного файла — ошибка.
func (a *app) planFor(p policy.Policy, e env.Env) (backend.Ruleset, error) {
	if p.Mode == policy.ModeRepair {
		found := 0
		for _, g := range p.Repair.Programs {
			if len(e.Programs[g]) == 0 {
				return nil, fail(exitConfig, "repair: по шаблону %q не найдено ни одной программы", g)
			}
			found += len(e.Programs[g])
		}
		for _, n := range p.Repair.Names {
			if len(e.Programs[backend.NameKey(n)]) == 0 {
				fmt.Fprintf(a.d.err, "WARN repair: по имени %q программа не найдена\n", n)
			}
			found += len(e.Programs[backend.NameKey(n)])
		}
		if found == 0 {
			return nil, fail(exitConfig, "repair: по именам %q не найдено ни одной программы", p.Repair.Names)
		}
	}
	r, err := a.b.Plan(p, e)
	switch {
	case errors.Is(err, backend.ErrConfig):
		return nil, fail(exitConfig, "план: %v", err)
	case err != nil:
		return nil, fail(exitApply, "план: %v", err)
	}
	return r, nil
}

func (a *app) withLock() (func(), error) {
	release, err := a.d.lock(a.d.dir)
	if err != nil {
		return nil, fail(exitApply, "замок: %v", err)
	}
	return release, nil
}
