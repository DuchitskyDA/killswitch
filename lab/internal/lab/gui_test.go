package lab

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/ui"
	"github.com/DuchitskyDA/killswitch/internal/window"
)

// fakeWindow — действия окна в тесте: режим и файл настроек в памяти; поля-дефекты ломают одно свойство.
type fakeWindow struct {
	mu      sync.Mutex
	mode    policy.Mode
	config  []byte
	iface   string
	up      bool
	overall probe.Class
	delay   time.Duration // сколько идёт проверка

	stuck  bool // дефект: режим не меняется
	mangle bool // дефект: сохранение дописывает в файл лишний ключ
	listed bool // дефект: список программ не пуст
}

var _ window.Actions = (*fakeWindow)(nil)

func (f *fakeWindow) Header() ui.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ui.Header{Mode: f.mode, Active: f.mode == policy.ModeOn, Tunnels: []ui.Tunnel{{Name: f.iface, Up: f.up}}}
}

func (f *fakeWindow) Configured() bool { return true }

func (f *fakeWindow) Transition(m policy.Mode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.stuck {
		f.mode = m
	}
	return nil
}

func (f *fakeWindow) Check(context.Context) (window.CheckReport, error) {
	time.Sleep(f.delay)
	return window.CheckReport{Result: probe.CheckResult{Overall: f.overall}, Summary: "итог"}, nil
}

func (f *fakeWindow) Detect() []string { return nil }

func (f *fakeWindow) Profiles() []ui.Profile {
	return []ui.Profile{{Name: "wireguard", Description: "WireGuard"}, {Name: "sing-box", Description: "sing-box"}}
}

func (f *fakeWindow) LoadConfig() (policy.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return policy.ParseConfig(f.config)
}

func (f *fakeWindow) Running() ([]backend.Program, error) {
	if f.listed {
		return []backend.Program{{Name: "node", Path: "/usr/bin/node"}}, nil
	}
	return nil, nil
}

func (f *fakeWindow) Save(data []byte) (string, error) {
	cfg, err := policy.ParseConfig(data)
	if err != nil {
		return "", window.InputError{Err: err}
	}
	if cfg.Profile != "" && cfg.Profile != "wireguard" && cfg.Profile != "sing-box" {
		return "", window.InputError{Err: fmt.Errorf("не сохранено: профиль %q не найден", cfg.Profile)}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.config = data
	if f.mangle {
		f.config = append([]byte("lan = false\n"), data...)
	}
	return "сохранено и применено (on)", nil
}

func (f *fakeWindow) rules() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mode == policy.ModeOn {
		return "table inet killswitch {\n\tchain postrouting {\n\t}\n}\n"
	}
	return "table inet killswitch {\n}\n"
}

func (f *fakeWindow) file() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.config), nil
}

type guiReport struct {
	name   string
	ok     bool
	detail string
}

// session гоняет сценарий «браузера» против настоящего сервера окна с действиями f.
func session(t *testing.T, f *fakeWindow, edit func(*guiHost)) (reports []guiReport, closed bool, wait error) {
	t.Helper()
	srv, err := window.New(window.Options{Actions: f, Caps: policy.CapabilitiesFor("linux"), CloseGrace: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Wait(context.Background()) }()
	addr, err := ParseWindowURL(srv.URL())
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	h := guiHost{do: DoHTTP, rules: f.rules, config: f.file, tunnel: f.iface, profile: "wireguard", beat: 20 * time.Millisecond,
		report: func(name string, ok bool, detail string) { reports = append(reports, guiReport{name, ok, detail}) }}
	if edit != nil {
		edit(&h)
	}
	closed = guiSession(h, addr)
	if !closed {
		srv.Close()
	}
	select {
	case wait = <-done:
	case <-time.After(5 * time.Second):
		srv.Close()
		t.Fatal("сервер окна не завершился")
	}
	return reports, closed, wait
}

func healthyWindow() *fakeWindow {
	return &fakeWindow{mode: policy.ModeOn, config: []byte(Clients["wireguard"].Config(ConfigOpts{})), iface: "wg0", up: true,
		overall: probe.Blocked}
}

func failed(reports []guiReport) []string {
	var out []string
	for _, r := range reports {
		if !r.ok {
			out = append(out, r.name+": "+r.detail)
		}
	}
	return out
}

// Настройки каждого клиента стенда проходят окно без потерь: сценарий даёт только PASS.
func TestGuiSessionPassesForEveryClient(t *testing.T) {
	for name, c := range Clients {
		t.Run(name, func(t *testing.T) {
			f := healthyWindow()
			f.config, f.iface = []byte(c.Config(ConfigOpts{CgroupPath: "system.slice/ksl-lab.scope/ksl-xray"})), c.Ifaces[0]
			if c.Redirect {
				f.overall = probe.Inconclusive // допуск сценария 9: 5 без leak при коде команды 0
			}
			reports, closed, wait := session(t, f, func(h *guiHost) { h.profile, h.redirect = c.Profile, c.Redirect })
			if bad := failed(reports); len(bad) > 0 || !closed || wait != nil {
				t.Errorf("closed=%t, Wait=%v, FAIL:\n%s", closed, wait, strings.Join(bad, "\n"))
			}
		})
	}
}

// Исправное окно: все проверки сценария проходят, сигнал закрытия завершает сервер без ошибки.
func TestGuiSessionPassesAgainstWindowServer(t *testing.T) {
	f := healthyWindow()
	f.delay = 90 * time.Millisecond // проверка длиннее шага сигнала жизни
	var modes []string
	reports, closed, wait := session(t, f, func(h *guiHost) { h.modeSet = func(m string) { modes = append(modes, m) } })
	if bad := failed(reports); len(bad) > 0 {
		t.Errorf("FAIL у исправного окна:\n%s", strings.Join(bad, "\n"))
	}
	if !closed || wait != nil {
		t.Errorf("закрытие: closed=%t, Wait=%v", closed, wait)
	}
	if !slices.Equal(modes, []string{"off", "on"}) {
		t.Errorf("смены режима для стенда: %v", modes)
	}
	var names []string
	for _, r := range reports {
		names = append(names, r.name)
	}
	all := strings.Join(names, "\n")
	for _, want := range []string{"обмен ключа", "повтор ключа", "без cookie", "чужой Host", "без Origin", "страница", "состояние",
		"адаптер туннеля wg0", "mode off", "mode on", "/api/check", "сигнал жизни", "PUT /api/config тем же телом",
		"несуществующим профилем", "/api/clients", "/api/programs", "сигнал закрытия"} {
		if !strings.Contains(all, want) {
			t.Errorf("нет проверки %q среди:\n%s", want, all)
		}
	}
	if f.mode != policy.ModeOn {
		t.Errorf("после сценария режим %q, ждали on", f.mode)
	}
}

// Дефект окна или стенда виден как FAIL своей проверки.
func TestGuiSessionCatchesDefects(t *testing.T) {
	cases := []struct {
		name string
		f    func(*fakeWindow)
		h    func(*guiHost)
		want string // проверка, которая обязана упасть
	}{
		{name: "режим не меняется", f: func(f *fakeWindow) { f.stuck = true }, want: "mode off"},
		{name: "off не снял цепочки", h: func(h *guiHost) {
			h.rules = func() string { return "table inet killswitch {\n\tchain postrouting {\n\t}\n}\n" }
		}, want: "mode off"},
		{name: "on не вернул цепочки", h: func(h *guiHost) { h.rules = func() string { return "table inet killswitch {\n}\n" } },
			want: "mode on"},
		{name: "сохранение портит файл", f: func(f *fakeWindow) { f.mangle = true }, want: "PUT /api/config тем же телом"},
		{name: "проверка расходится с командой check", f: func(f *fakeWindow) { f.overall = probe.Leak }, want: "/api/check"},
		{name: "код команды check другой", h: func(h *guiHost) { h.cliCode = 5 }, want: "/api/check"},
		{name: "адаптер туннеля опущен", f: func(f *fakeWindow) { f.up = false }, want: "адаптер туннеля wg0"},
		{name: "другой адаптер туннеля", h: func(h *guiHost) { h.tunnel = "wg9" }, want: "адаптер туннеля wg9"},
		{name: "профиля клиента нет в списке", h: func(h *guiHost) { h.profile = "нет-такого" }, want: "/api/clients"},
		{name: "список программ не пуст", f: func(f *fakeWindow) { f.listed = true }, want: "/api/programs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := healthyWindow()
			if c.f != nil {
				c.f(f)
			}
			reports, _, _ := session(t, f, c.h)
			bad := failed(reports)
			if !slices.ContainsFunc(bad, func(s string) bool { return strings.Contains(s, c.want) }) {
				t.Errorf("ждали FAIL проверки %q, упали: %v", c.want, bad)
			}
		})
	}
}

// Без обмена ключа сценарий дальше не идёт и окно не закрывает.
func TestGuiSessionStopsWithoutSession(t *testing.T) {
	f := healthyWindow()
	reports, closed, _ := session(t, f, func(h *guiHost) {
		h.do = func(s HTTPSpec) HTTPResult {
			s.URL = strings.Replace(s.URL, "key=", "key=x", 1)
			return DoHTTP(s)
		}
	})
	if closed || len(reports) != 1 || reports[0].ok {
		t.Errorf("closed=%t, проверки: %+v", closed, reports)
	}
}

// Запрос сценария идёт только на 127.0.0.1: другой адрес отклонён до соединения.
func TestDoHTTPRefusesNonLoopback(t *testing.T) {
	for _, u := range []string{"http://203.0.113.1:80/", "http://localhost:80/", "https://127.0.0.1:443/", "http://127.0.0.1/",
		"http://127.0.0.1:80@203.0.113.1/", "http://[::1]:80/", "http://127.0.0.2:80/", "::"} {
		r := DoHTTP(HTTPSpec{Method: http.MethodGet, URL: u, Timeout: 5 * time.Second})
		if !strings.HasPrefix(r.Err, "адрес не http://127.0.0.1:<порт>") {
			t.Errorf("%s: %+v", u, r)
		}
	}
}

// Запрос несёт свой Host, заголовки и тело; переход по 303 не выполняется, Set-Cookie возвращается как есть.
func TestDoHTTPSendsRequestAsGiven(t *testing.T) {
	var got *http.Request
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.Header().Add("Set-Cookie", "s=1; Path=/; HttpOnly; SameSite=Strict")
		http.Redirect(w, r, "/next", http.StatusSeeOther)
	}))
	defer srv.Close()
	r := DoHTTP(HTTPSpec{Method: http.MethodPost, URL: srv.URL + "/a?b=1", Host: "other.example:1",
		Header: map[string]string{"Origin": "http://o", "Cookie": "s=1"}, Body: `{"x":1}`})
	if r.Err != "" || r.Status != http.StatusSeeOther || r.Location != "/next" ||
		!slices.Equal(r.SetCookie, []string{"s=1; Path=/; HttpOnly; SameSite=Strict"}) {
		t.Errorf("ответ: %+v", r)
	}
	if got == nil || got.Host != "other.example:1" || got.Header.Get("Origin") != "http://o" || got.Header.Get("Cookie") != "s=1" ||
		got.URL.RequestURI() != "/a?b=1" || body != `{"x":1}` {
		t.Errorf("запрос: %+v, тело %q", got, body)
	}
	if r := DoHTTP(HTTPSpec{Method: http.MethodGet, URL: srv.URL}); r.Err != "" || got.Host != strings.TrimPrefix(srv.URL, "http://") {
		t.Errorf("Host по умолчанию: %q, %+v", got.Host, r)
	}
}

func TestParseWindowURL(t *testing.T) {
	key := strings.Repeat("aB3_-", 8) + "xyz"
	a, err := ParseWindowURL("http://127.0.0.1:40123/open?key=" + key + "\n")
	if err != nil || a != (windowAddr{Base: "http://127.0.0.1:40123", Port: "40123", Key: key}) {
		t.Errorf("адрес окна: %+v, %v", a, err)
	}
	for _, bad := range []string{"", "http://127.0.0.1:40123/", "http://203.0.113.1:40123/open?key=" + key,
		"https://127.0.0.1:40123/open?key=" + key, "http://127.0.0.1:40123/open?key=short",
		"http://127.0.0.1:40123/open?key=" + key + "&x=1", "http://localhost:40123/open?key=" + key} {
		if _, err := ParseWindowURL(bad); err == nil {
			t.Errorf("%q: ждали ошибку", bad)
		}
	}
}

// Окружение запуска: убранные переменные исчезают во всех вхождениях, заданные заменяют прежние.
func TestEnvWith(t *testing.T) {
	got := EnvWith([]string{"PATH=/a", "DISPLAY=:0", "SUDO_UID=1000", "HOME=/root", "DISPLAY=:1", "DISPLAYX=1"},
		[]string{"SUDO_UID", "DISPLAY"}, "KSL_OPEN_LOG=/x", "HOME=/tmp")
	want := []string{"PATH=/a", "DISPLAYX=1", "KSL_OPEN_LOG=/x", "HOME=/tmp"}
	if !slices.Equal(got, want) {
		t.Errorf("EnvWith = %q, ждали %q", got, want)
	}
}

// Настройки «те же по смыслу»: запись в другой форме равна, другое значение — нет.
func TestSameConfig(t *testing.T) {
	for name, c := range Clients {
		text := c.Config(ConfigOpts{CgroupPath: "system.slice/x.scope/ksl-xray"})
		cfg, err := policy.ParseConfig([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := policy.Encode(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if same, err := SameConfig(text, string(encoded)); err != nil || !same {
			t.Errorf("%s: запись в форме Encode не равна исходной (%v):\n%s\n---\n%s", name, err, text, encoded)
		}
		if same, err := SameConfig(text, "lan = false\n"+string(encoded)); err != nil || same {
			t.Errorf("%s: лишний ключ не замечен (%v)", name, err)
		}
	}
	if _, err := SameConfig("profile = \"a\"\n", "{не toml"); err == nil {
		t.Error("неразборчивый файл: ждали ошибку")
	}
}

// Слушающие сокеты порта из вывода ss -Hltn.
func TestPortListeners(t *testing.T) {
	ss := "LISTEN 0      4096       127.0.0.1:40123      0.0.0.0:*\n" +
		"LISTEN 0      128          0.0.0.0:22         0.0.0.0:*\n" +
		"LISTEN 0      4096               *:40123            *:*\n" +
		"LISTEN 0      4096       127.0.0.1:4012       0.0.0.0:*\n"
	if got := portListeners(ss, "40123"); !slices.Equal(got, []string{"127.0.0.1:40123", "*:40123"}) {
		t.Errorf("portListeners = %q", got)
	}
	if got := portListeners(ss, "40124"); len(got) != 0 {
		t.Errorf("чужой порт: %q", got)
	}
}

// Итог проверки окна против команды check: слово и код согласованы, код равен коду команды;
// при перехвате клиентом — 0 или 5 без утечки, как в сценарии 9.
func TestCheckAgrees(t *testing.T) {
	cases := []struct {
		result   string
		code     int
		leaks    int
		cli      int
		redirect bool
		want     bool
	}{
		{"clean", 0, 0, 0, false, true},
		{"leak", 4, 1, 4, false, true},
		{"clean", 0, 0, 5, false, false},
		{"unsure", 5, 0, 0, false, false},
		{"leak", 0, 0, 0, false, false},
		{"clean", 4, 0, 4, false, false},
		{"unsure", 5, 0, 0, true, true},
		{"clean", 0, 0, 5, true, true},
		{"leak", 4, 1, 4, true, false},
		{"unsure", 5, 1, 5, true, false},
		{"clean", 1, 0, 1, false, false},
	}
	for _, c := range cases {
		if got := CheckAgrees(c.result, c.code, c.leaks, c.cli, c.redirect); got != c.want {
			t.Errorf("%+v: %t", c, got)
		}
	}
}

// Ключ окна в журнал не попадает.
func TestMaskKey(t *testing.T) {
	got := maskKey("откройте в браузере: http://127.0.0.1:40123/open?key=aB3_-xyz\nдальше")
	if got != "откройте в браузере: http://127.0.0.1:40123/open?key=…\nдальше" {
		t.Errorf("maskKey = %q", got)
	}
}

// Строка «окно» видна в сводке.
func TestRenderTableWindowRow(t *testing.T) {
	out := RenderTable(Summarize([]Check{
		{Scenario: ScenarioWindow, Client: "xray", Family: "-", Name: "mode off", Status: Fail, Detail: "режим on"},
	}))
	if !strings.Contains(out, "| "+ScenarioWindow+" | FAIL | FAIL |") || !strings.Contains(out, "(FAIL): mode off: режим on") {
		t.Errorf("таблица:\n%s", out)
	}
}
