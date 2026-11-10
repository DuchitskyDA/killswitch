package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/ui"
	"github.com/DuchitskyDA/killswitch/internal/window"
)

// window — killswitch window: локальный сервер окна с правами администратора и само окно.
// Работает, пока окно открыто; Ctrl+C завершает сразу.
func (a *app) window(ctx context.Context) error {
	if a.d.admin == nil || !a.d.admin() {
		return a.needAdmin("window", "окно откроется с правами администратора")
	}
	if err := a.d.host.Graphical(); err != nil {
		return fail(exitConfig, "окно не открыть: %v; меню в терминале — sudo killswitch", err)
	}
	b, err := a.d.backend()
	if err != nil {
		return fail(exitApply, "%v", err)
	}
	a.b = b
	srv, err := window.New(window.Options{Actions: windowActions{&menuActions{a: a}}, Caps: b.Capabilities(),
		StartTimeout: a.d.windowStart})
	if err != nil {
		return fail(exitApply, "окно: %v", err)
	}
	if err := a.d.host.Open(srv.URL()); err != nil {
		// Адрес с ключом печатается только здесь: без него окно не открыть вручную.
		fmt.Fprintf(a.d.out, "окно не открылось само (%v)\nоткройте в браузере: %s\n", err, srv.URL())
	} else {
		fmt.Fprintln(a.d.out, "окно killswitch открыто; закройте его или нажмите Ctrl+C, чтобы завершить")
	}
	if err := srv.Wait(ctx); err != nil {
		return fail(exitApply, "%v", err)
	}
	return nil
}

// windowActions — действия окна: те же, что у меню; отличаются проверка (итог вместо печати)
// и вид ошибок (окно отвечает по ним кодами).
type windowActions struct{ *menuActions }

var _ window.Actions = windowActions{}

func (w windowActions) Configured() bool {
	_, err := os.Stat(w.ownConfig())
	return err == nil
}

// Header — шапка меню без строки «нет настроек»: об этом окну говорит Configured.
func (w windowActions) Header() ui.Header {
	h := w.menuActions.Header()
	h.Notes = slices.DeleteFunc(h.Notes, func(n string) bool { return n == "WARN "+errNoSettings.Error() })
	return h
}

func (w windowActions) Transition(m policy.Mode) error {
	return windowError(w.menuActions.Transition(m))
}

func (w windowActions) Save(data []byte) (string, error) {
	saved, err := w.menuActions.Save(data)
	return saved, windowError(err)
}

// windowError помечает ошибку для окна: нет настроек, ошибка настроек (код 2 у CLI) или сбой.
func windowError(err error) error {
	var ce cliError
	switch {
	case errors.Is(err, errNoSettings):
		return window.ErrNotConfigured
	case errors.As(err, &ce) && ce.code == exitConfig:
		return window.InputError{Err: err}
	}
	return err
}

// Check — та же проверка, что команда check, но итог возвращается, а не печатается.
func (w windowActions) Check(ctx context.Context) (window.CheckReport, error) {
	a := w.a
	if err := w.useOwnConfig(); err != nil {
		return window.CheckReport{}, windowError(err)
	}
	var warn bytes.Buffer // предупреждения снимка — в итог, а не в консоль
	saved := a.d.err
	a.d.err = &warn
	in, matched, err := a.checkInput()
	a.d.err = saved
	if err != nil {
		return window.CheckReport{}, windowError(err)
	}
	res := probe.Run(ctx, in, a.d.prober(a.b), a.b, a.d.now)
	rep := window.CheckReport{Result: res, Notes: splitLines(warn.String())}
	rep.Summary, rep.Note = checkSummary(res)
	for _, i := range matched {
		rep.Tunnels = append(rep.Tunnels, ui.Tunnel{Name: i.Name, Up: i.Up})
	}
	if len(matched) > 1 {
		rep.Notes = append(rep.Notes, severalTunnels)
	}
	return rep, nil
}

// checkSummary — итог проверки строкой и пояснение к нему. Простая проверка — словами команды check.
func checkSummary(res probe.CheckResult) (summary, note string) {
	if res.Simple {
		summary, note, _ = strings.Cut(simpleVerdict(res), "\n")
	} else {
		switch res.Overall {
		case probe.Blocked:
			summary = "утечек не найдено"
		case probe.Leak:
			summary = "УТЕЧКА"
		default:
			summary = "нет уверенности: " + inconclusiveReason(res)
		}
	}
	if res.Overall == probe.Leak {
		note = leakSource(res)
	}
	return summary, note
}

// leakSource — где утечка: адаптер и цель первой пробы с ответом, иначе первая структурная находка.
func leakSource(res probe.CheckResult) string {
	for _, r := range res.Probes {
		if r.Class == probe.Leak {
			return fmt.Sprintf("адаптер %s: %s %s", r.Iface, r.Proto, r.Target)
		}
	}
	for _, f := range res.Structural {
		return f.Kind + ": " + f.Detail
	}
	return ""
}
