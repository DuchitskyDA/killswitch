package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/ui"
	"github.com/DuchitskyDA/killswitch/internal/window"
)

// Тесты окна: backend фейковый, браузер — подставная функция запуска процесса, сеть — loopback внутри теста.

// windowDeps — запуск окна на машине с графикой; browser играет роль открытого окна.
func (h *harness) windowDeps(browser func(url string) error) deps {
	d := h.menuDeps()
	d.host = window.Host{
		GOOS:   "linux",
		Getenv: func(k string) string { return map[string]string{"DISPLAY": ":0"}[k] },
		Exists: func(string) bool { return false },
		Home:   func(uint32) string { return "" },
		Start:  func(c window.Command) error { return browser(c.Args[len(c.Args)-1]) },
	}
	return d
}

func (h *harness) windowActions() windowActions { return windowActions{h.actions()} }

// tab — вкладка браузера в тесте.
type tab struct {
	t      *testing.T
	c      *http.Client
	origin string
}

func openTab(t *testing.T, address string) *tab {
	t.Helper()
	jar, err := cookiejar.New(nil)
	noErr(t, err)
	b := &tab{t: t, c: &http.Client{Jar: jar, Timeout: 10 * time.Second}, origin: address[:strings.Index(address, "/open")]}
	resp, err := b.c.Get(address)
	noErr(t, err)
	resp.Body.Close()
	eq(t, resp.StatusCode, http.StatusOK)
	return b
}

func (b *tab) call(method, path, body string, out any) int {
	b.t.Helper()
	r, err := http.NewRequest(method, b.origin+path, strings.NewReader(body))
	noErr(b.t, err)
	if method != http.MethodGet {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", b.origin)
	}
	resp, err := b.c.Do(r)
	noErr(b.t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	noErr(b.t, err)
	if out != nil {
		noErr(b.t, json.Unmarshal(data, out))
	}
	return resp.StatusCode
}

func TestWindowServesTheSameActionsAsMenu(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Dropped = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := h.windowDeps(func(address string) error {
		defer cancel() // окно закрыли: команда завершается
		b := openTab(t, address)
		var st struct {
			OS         string
			Configured bool
			Mode       string
			Active     bool
			Tunnels    []struct{ Name string }
		}
		eq(t, b.call(http.MethodGet, "/api/state", "", &st), http.StatusOK)
		eq(t, st.Configured, true)
		eq(t, st.Mode, "")
		eq(t, st.OS, "windows")

		eq(t, b.call(http.MethodPost, "/api/mode", `{"mode":"on"}`, &st), http.StatusOK)
		eq(t, st.Mode, "on")
		eq(t, st.Active, true)
		eq(t, len(st.Tunnels), 1)
		eq(t, h.installedMode(), policy.ModeOn)

		var check struct {
			Result string
			Code   int
		}
		eq(t, b.call(http.MethodPost, "/api/check", `{}`, &check), http.StatusOK)
		eq(t, check.Result, "clean")
		eq(t, check.Code, exitOK)

		var saved struct{ Message string }
		eq(t, b.call(http.MethodPut, "/api/config", `{"profile":"example","lan":false}`, &saved), http.StatusOK)
		eq(t, saved.Message, "сохранено и применено (on)")
		eq(t, h.config(), "profile = \"example\"\nlan = false\n")

		var bad struct{ Error string }
		eq(t, b.call(http.MethodPut, "/api/config", `{"profile":"нет такого"}`, &bad), http.StatusUnprocessableEntity)
		eq(t, strings.HasPrefix(bad.Error, "не сохранено: профиль"), true)
		return nil
	})
	eq(t, run(ctx, []string{"window"}, d), exitOK)
	eq(t, h.err.String(), "")
}

func TestWindowWithoutRootRefuses(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.windowDeps(func(string) error { t.Error("браузер запущен без прав"); return nil })
	d.admin = func() bool { return false }
	eq(t, run(context.Background(), []string{"window"}, d), exitConfig)
	eq(t, strings.Contains(h.err.String(), "запустите sudo killswitch window"), true)
}

func TestWindowElevatesWhenNotAdmin(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.windowDeps(func(string) error { t.Error("браузер запущен без прав"); return nil })
	d.admin = func() bool { return false }
	var asked []string
	d.elevate = func(command string) error { asked = append(asked, command); return nil }
	eq(t, run(context.Background(), []string{"window"}, d), exitOK)
	eq(t, asked, []string{"window"})

	d.elevate = func(string) error { return errors.New("отменено пользователем") }
	eq(t, run(context.Background(), []string{"window"}, d), exitConfig)
}

func TestWindowWithoutGraphicsRefuses(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.windowDeps(func(string) error { t.Error("браузер запущен без графики"); return nil })
	d.host.Getenv = func(string) string { return "" }
	eq(t, run(context.Background(), []string{"window"}, d), exitConfig)
	eq(t, strings.Contains(h.err.String(), "нет графического сеанса"), true)
	eq(t, strings.Contains(h.err.String(), "sudo killswitch"), true)
	eq(t, h.fb.Snapshots, 0)
}

func TestWindowPrintsAddressWhenBrowserFails(t *testing.T) {
	h := newHarness(t, baseConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var address string
	d := h.windowDeps(func(a string) error {
		address = a
		cancel()
		return errors.New("xdg-open не найден")
	})
	eq(t, run(ctx, []string{"window"}, d), exitOK)
	eq(t, strings.HasPrefix(address, "http://127.0.0.1:"), true)
	eq(t, strings.Contains(h.out.String(), "откройте в браузере: "+address), true)
}

func TestWindowThatNeverOpensIsError(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.windowDeps(func(string) error { return nil })
	d.windowStart = 50 * time.Millisecond
	eq(t, run(context.Background(), []string{"window"}, d), exitApply)
	eq(t, strings.Contains(h.err.String(), "окно не открыто"), true)
}

func TestWindowCheckReturnsReportWithoutPrinting(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Dropped = true
	rep, err := h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, rep.Result.Overall, probe.Blocked)
	eq(t, rep.Result.Simple, false)
	eq(t, len(rep.Result.Probes) > 0, true)
	eq(t, rep.Summary, "утечек не найдено")
	eq(t, rep.Note, "")
	eq(t, rep.Tunnels, []ui.Tunnel{{Name: "wg-example", Up: true}})
	eq(t, h.out.String(), "")
	eq(t, h.err.String(), "")
}

func TestWindowCheckLeakNamesAdapter(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.prober.answered = true
	rep, err := h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, rep.Result.Overall, probe.Leak)
	eq(t, rep.Summary, "УТЕЧКА")
	eq(t, strings.HasPrefix(rep.Note, "адаптер Ethernet: "), true)
}

func TestWindowCheckStructuralLeakNamesFinding(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Dropped = true
	h.fb.Structural = []probe.StructuralFinding{{Kind: "wfp-tie", Detail: "чужой permit"}}
	rep, err := h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, rep.Summary, "УТЕЧКА")
	eq(t, rep.Note, "wfp-tie: чужой permit")
}

func TestWindowSimpleCheckKeepsCLIWords(t *testing.T) {
	h := simpleCheck(t)
	rep, err := h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, rep.Result.Simple, true)
	eq(t, rep.Summary, "утечек не найдено (простая проверка)")
	eq(t, strings.HasPrefix(rep.Note, simpleNote), true)

	h.prober.answered = true
	rep, err = h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, rep.Summary, "УТЕЧКА (простая проверка)")
	eq(t, strings.HasPrefix(rep.Note, "адаптер Ethernet: "), true)

	h.prober.answered, h.prober.plainErr = false, errors.New("i/o timeout")
	rep, err = h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, rep.Summary, "нет уверенности (простая проверка): ответа нет, но и обычным путём example.com не ответил: i/o timeout")
	eq(t, rep.Note, "")
}

func TestWindowCheckWarnsOnSeveralTunnelAdapters(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Dropped = true
	h.fb.Env.Ifaces = append(h.fb.Env.Ifaces, h.fb.Env.Ifaces[0])
	h.fb.Env.Ifaces[len(h.fb.Env.Ifaces)-1].Index = 9
	rep, err := h.windowActions().Check(context.Background())
	noErr(t, err)
	eq(t, len(rep.Tunnels), 2)
	eq(t, len(rep.Notes), 1)
	eq(t, strings.HasPrefix(rep.Notes[0], "WARN шаблону туннеля соответствует больше одного адаптера"), true)
}

func TestWindowWithoutSettings(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, os.Remove(h.configPath()))
	w := h.windowActions()
	eq(t, w.Configured(), false)
	eq(t, len(w.Header().Notes), 0) // «нет настроек» окно показывает по configured, а не строкой
	eq(t, w.Transition(policy.ModeOn), window.ErrNotConfigured)
	_, err := w.Check(context.Background())
	eq(t, err, window.ErrNotConfigured)
	eq(t, len(h.fb.Applies), 0)

	msg, err := w.Save([]byte(baseConfig))
	noErr(t, err)
	eq(t, strings.HasPrefix(msg, "сохранено"), true)
	eq(t, w.Configured(), true)
}

func TestWindowInputErrorsAreMarked(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Caps = policy.CapabilitiesFor("linux")
	w := h.windowActions()
	var input window.InputError
	eq(t, errors.As(w.Transition(policy.ModeRepair), &input), true) // repair вне Windows — ошибка настроек

	_, err := w.Save([]byte("trust_mode = \"strict\"\n" + baseConfig))
	eq(t, errors.As(err, &input), true)
	eq(t, strings.HasPrefix(err.Error(), "не сохранено: trust_mode = strict"), true)

	h = newHarness(t, baseConfig)
	h.fb.ApplyErr = errors.New("транзакция отклонена")
	err = h.windowActions().Transition(policy.ModeOn)
	eq(t, err != nil && !errors.As(err, &input), true) // сбой применения — не ошибка ввода
}

func TestWindowCheckUsesOwnConfig(t *testing.T) {
	h := simpleCheck(t)
	h.prober.resolved = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	w := h.windowActions()
	w.a.configPath = "нет такого файла"
	_, err := w.Check(context.Background())
	noErr(t, err)
}
