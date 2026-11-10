package window

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/ui"
)

// Тесты сервера — на подставных действиях; сеть — только loopback внутри теста.

type fakeActions struct {
	header        ui.Header
	configured    bool
	transitions   []policy.Mode
	transitionErr error
	report        CheckReport
	checkErr      error
	checks        int
	detected      []string
	profiles      []ui.Profile
	cfg           policy.Config
	cfgErr        error
	running       []backend.Program
	runningErr    error
	saved         []string
	saveMsg       string
	saveErr       error
}

func (f *fakeActions) Header() ui.Header { return f.header }
func (f *fakeActions) Configured() bool  { return f.configured }
func (f *fakeActions) Transition(m policy.Mode) error {
	f.transitions = append(f.transitions, m)
	if f.transitionErr == nil {
		f.header.Mode = m
	}
	return f.transitionErr
}
func (f *fakeActions) Check(context.Context) (CheckReport, error) {
	f.checks++
	return f.report, f.checkErr
}
func (f *fakeActions) Detect() []string                    { return f.detected }
func (f *fakeActions) Profiles() []ui.Profile              { return f.profiles }
func (f *fakeActions) LoadConfig() (policy.Config, error)  { return f.cfg, f.cfgErr }
func (f *fakeActions) Running() ([]backend.Program, error) { return f.running, f.runningErr }
func (f *fakeActions) Save(data []byte) (saved string, err error) {
	f.saved = append(f.saved, string(data))
	return f.saveMsg, f.saveErr
}

// page — окно в тесте: помнит cookie сеанса и шлёт запросы так, как их шлёт страница.
type page struct {
	t      *testing.T
	s      *Server
	origin string
	cookie *http.Cookie
}

func newServer(t *testing.T, act Actions, edit ...func(*Options)) *Server {
	t.Helper()
	opt := Options{Actions: act, Caps: policy.CapabilitiesFor("windows"),
		StartTimeout: time.Minute, IdleTimeout: time.Minute, CloseGrace: time.Minute}
	for _, e := range edit {
		e(&opt)
	}
	s, err := New(opt)
	noErr(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// opened — сервер с уже открытым окном.
func opened(t *testing.T, act Actions) *page {
	t.Helper()
	p := &page{t: t, s: newServer(t, act)}
	p.origin = origin(t, p.s)
	w := p.get(openPath(t, p.s))
	eq(t, w.Code, http.StatusSeeOther)
	p.cookie = sessionCookie(t, w)
	return p
}

func origin(t *testing.T, s *Server) string {
	t.Helper()
	u, err := url.Parse(s.URL())
	noErr(t, err)
	return u.Scheme + "://" + u.Host
}

// openPath — путь первого открытия с ключом.
func openPath(t *testing.T, s *Server) string {
	t.Helper()
	u, err := url.Parse(s.URL())
	noErr(t, err)
	return u.RequestURI()
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("ожидалась одна cookie, получено %d", len(cookies))
	}
	return cookies[0]
}

func (p *page) request(method, path, body string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	p.t.Helper()
	if p.origin == "" {
		p.origin = origin(p.t, p.s)
	}
	r := httptest.NewRequest(method, p.origin+path, strings.NewReader(body))
	if p.cookie != nil {
		r.AddCookie(p.cookie)
	}
	if method != http.MethodGet {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", p.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, e := range edit {
		e(r)
	}
	w := httptest.NewRecorder()
	p.s.ServeHTTP(w, r)
	return w
}

func (p *page) get(path string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	p.t.Helper()
	return p.request(http.MethodGet, path, "", edit...)
}

func (p *page) post(path, body string, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	p.t.Helper()
	return p.request(http.MethodPost, path, body, edit...)
}

func header(name, value string) func(*http.Request) {
	return func(r *http.Request) {
		if value == "" {
			r.Header.Del(name)
			return
		}
		r.Header.Set(name, value)
	}
}

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("получено %#v, ожидалось %#v", got, want)
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
}

func TestKeyOpensSessionOnce(t *testing.T) {
	p := &page{t: t, s: newServer(t, &fakeActions{})}
	w := p.get(openPath(t, p.s))
	eq(t, w.Code, http.StatusSeeOther)
	eq(t, w.Header().Get("Location"), "/")
	c := sessionCookie(t, w)
	eq(t, c.HttpOnly, true)
	eq(t, c.SameSite, http.SameSiteStrictMode)
	eq(t, c.Path, "/")
	eq(t, c.MaxAge, 0)
	eq(t, c.Expires.IsZero(), true)

	p.cookie = c
	eq(t, p.get("/api/state").Code, http.StatusOK)
	eq(t, p.get("/").Code, http.StatusOK)
}

func TestKeyIsThirtyTwoRandomBytes(t *testing.T) {
	a, b := newServer(t, &fakeActions{}), newServer(t, &fakeActions{})
	ua, err := url.Parse(a.URL())
	noErr(t, err)
	ub, err := url.Parse(b.URL())
	noErr(t, err)
	eq(t, ua.Hostname(), "127.0.0.1")
	eq(t, len(ua.Query().Get("key")), 43) // 32 байта в base64url без дополнения
	eq(t, ua.Query().Get("key") == ub.Query().Get("key"), false)
}

func TestWrongKeyIsUnauthorized(t *testing.T) {
	p := &page{t: t, s: newServer(t, &fakeActions{})}
	w := p.get("/open?key=" + strings.Repeat("A", 43))
	eq(t, w.Code, http.StatusUnauthorized)
	eq(t, len(w.Result().Cookies()), 0)
	eq(t, p.get("/open").Code, http.StatusUnauthorized)
	// верный ключ после неверного всё ещё действует
	eq(t, p.get(openPath(t, p.s)).Code, http.StatusSeeOther)
}

func TestUsedKeyGivesNoSecondSession(t *testing.T) {
	p := opened(t, &fakeActions{})
	thief := &page{t: t, s: p.s}
	w := thief.get(openPath(t, p.s))
	eq(t, w.Code, http.StatusUnauthorized)
	eq(t, len(w.Result().Cookies()), 0)
	eq(t, strings.Contains(w.Body.String(), "ключ уже использован"), true)
}

func TestUsedKeyWithSessionReturnsToPage(t *testing.T) {
	p := opened(t, &fakeActions{})
	w := p.get(openPath(t, p.s))
	eq(t, w.Code, http.StatusSeeOther)
	eq(t, len(w.Result().Cookies()), 0)
}

func TestNoSessionIsUnauthorized(t *testing.T) {
	p := &page{t: t, s: newServer(t, &fakeActions{})}
	for _, path := range []string{"/", "/index.html", "/api/state", "/api/config", "/nothing"} {
		eq(t, p.get(path).Code, http.StatusUnauthorized)
	}
	eq(t, p.post("/api/mode", `{"mode":"off"}`).Code, http.StatusUnauthorized)
	eq(t, p.post("/api/alive", `{}`).Code, http.StatusUnauthorized)

	// cookie до открытия окна и чужое значение — тоже отказ
	p.cookie = &http.Cookie{Name: p.s.cookie, Value: strings.Repeat("A", 43)}
	eq(t, p.get("/api/state").Code, http.StatusUnauthorized)
	w := p.get("/api/state")
	eq(t, w.Header().Get("Content-Type"), "application/json")
	eq(t, strings.Contains(w.Body.String(), `"error"`), true)
}

func TestForeignHostIsForbidden(t *testing.T) {
	p := opened(t, &fakeActions{})
	port := strings.TrimPrefix(p.origin, "http://127.0.0.1:")
	for _, host := range []string{"example.com", "example.com:" + port, "localhost:" + port, "127.0.0.1", "127.0.0.1:1"} {
		foreign := func(r *http.Request) { r.Host = host }
		eq(t, p.get("/api/state", foreign).Code, http.StatusForbidden)
		eq(t, p.get("/", foreign).Code, http.StatusForbidden)
		eq(t, p.get(openPath(t, p.s), foreign).Code, http.StatusForbidden)
		eq(t, p.post("/api/mode", `{"mode":"off"}`, foreign).Code, http.StatusForbidden)
	}
}

func TestForeignOriginIsForbidden(t *testing.T) {
	act := &fakeActions{}
	p := opened(t, act)
	for _, edit := range []func(*http.Request){
		header("Origin", "http://example.com"),
		header("Origin", "null"),
		header("Origin", ""),
		header("Origin", strings.Replace(p.origin, "127.0.0.1", "localhost", 1)),
		header("Sec-Fetch-Site", "cross-site"),
		header("Sec-Fetch-Site", "same-site"),
		header("Sec-Fetch-Site", "none"),
	} {
		eq(t, p.post("/api/mode", `{"mode":"off"}`, edit).Code, http.StatusForbidden)
		eq(t, p.request(http.MethodPut, "/api/config", `{}`, edit).Code, http.StatusForbidden)
	}
	eq(t, len(act.transitions), 0)
	eq(t, len(act.saved), 0)

	// чтение с чужой страницы тоже закрыто
	eq(t, p.get("/api/state", header("Origin", "http://example.com")).Code, http.StatusForbidden)
	eq(t, p.get("/api/state", header("Sec-Fetch-Site", "cross-site")).Code, http.StatusForbidden)
	eq(t, p.get("/", header("Sec-Fetch-Site", "cross-site")).Code, http.StatusForbidden)
	// переход по адресу и запросы самой страницы — можно
	eq(t, p.get("/", header("Sec-Fetch-Site", "none")).Code, http.StatusOK)
	eq(t, p.get("/api/state", header("Sec-Fetch-Site", "same-origin")).Code, http.StatusOK)
	// браузер без Sec-Fetch-Site: решает Origin
	eq(t, p.post("/api/alive", `{}`, header("Sec-Fetch-Site", "")).Code, http.StatusOK)
}

func TestChangesNeedJSONContentType(t *testing.T) {
	act := &fakeActions{}
	p := opened(t, act)
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
		eq(t, p.post("/api/mode", `{"mode":"off"}`, header("Content-Type", ct)).Code, http.StatusUnsupportedMediaType)
	}
	eq(t, len(act.transitions), 0)
	eq(t, p.post("/api/mode", `{"mode":"off"}`, header("Content-Type", "application/json; charset=utf-8")).Code, http.StatusOK)
}

func TestBodyLimit(t *testing.T) {
	act := &fakeActions{}
	p := opened(t, act)
	big := `{"profile":"` + strings.Repeat("a", maxBody) + `"}`
	eq(t, p.request(http.MethodPut, "/api/config", big).Code, http.StatusRequestEntityTooLarge)
	eq(t, len(act.saved), 0)
}

func TestWrongMethodIsNotAllowed(t *testing.T) {
	act := &fakeActions{}
	p := opened(t, act)
	eq(t, p.get("/api/mode").Code, http.StatusMethodNotAllowed)
	eq(t, p.get("/api/check").Code, http.StatusMethodNotAllowed)
	eq(t, p.post("/api/state", `{}`).Code, http.StatusMethodNotAllowed)
	eq(t, p.post("/api/config", `{}`).Code, http.StatusMethodNotAllowed)
	eq(t, p.request(http.MethodDelete, "/api/config", "").Code, http.StatusMethodNotAllowed)
	eq(t, p.post("/", `{}`).Code, http.StatusMethodNotAllowed)
	eq(t, p.get("/api/nothing").Code, http.StatusNotFound)
	eq(t, len(act.saved), 0)
}

func TestSecurityHeaders(t *testing.T) {
	p := opened(t, &fakeActions{})
	for _, w := range []*httptest.ResponseRecorder{
		p.get("/"), p.get("/api/state"), p.get("/api/nothing"),
		(&page{t: t, s: p.s}).get("/api/state"), // 401
		p.get("/", func(r *http.Request) { r.Host = "example.com" }),
	} {
		h := w.Header()
		eq(t, h.Get("Cache-Control"), "no-store")
		eq(t, h.Get("X-Content-Type-Options"), "nosniff")
		eq(t, h.Get("X-Frame-Options"), "DENY")
		eq(t, h.Get("Referrer-Policy"), "no-referrer")
		csp := h.Get("Content-Security-Policy")
		for _, part := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
			"frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, part) {
				t.Errorf("в CSP %q нет %q", csp, part)
			}
		}
		if strings.Contains(csp, "unsafe") || strings.Contains(csp, "*") {
			t.Errorf("CSP разрешает чужое: %q", csp)
		}
	}
}

func TestPageIsEmbedded(t *testing.T) {
	p := opened(t, &fakeActions{})
	w := p.get("/")
	eq(t, w.Code, http.StatusOK)
	eq(t, strings.Contains(w.Body.String(), `<div id="app">`), true)
	eq(t, p.get("/nothing.js").Code, http.StatusNotFound)
}

// serving запускает Wait и возвращает канал с его итогом и браузер с памятью cookie.
func serving(t *testing.T, s *Server) (context.CancelFunc, <-chan error, *http.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- s.Wait(ctx) }()
	jar, err := cookiejar.New(nil)
	noErr(t, err)
	return cancel, done, &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func wait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("сервер не завершился")
		return nil
	}
}

func stillServing(t *testing.T, done <-chan error, d time.Duration) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("сервер завершился раньше времени: %v", err)
	case <-time.After(d):
	}
}

func visit(t *testing.T, c *http.Client, target string) int {
	t.Helper()
	resp, err := c.Get(target)
	noErr(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func alive(t *testing.T, c *http.Client, s *Server, body string) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, origin(t, s)+"/api/alive", strings.NewReader(body))
	noErr(t, err)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin(t, s))
	resp, err := c.Do(r)
	noErr(t, err)
	resp.Body.Close()
	eq(t, resp.StatusCode, http.StatusOK)
}

func TestServeOverLoopback(t *testing.T) {
	s := newServer(t, &fakeActions{})
	cancel, done, c := serving(t, s)
	eq(t, visit(t, c, s.URL()), http.StatusOK) // обмен ключа и переход на страницу
	eq(t, visit(t, c, origin(t, s)+"/api/state"), http.StatusOK)
	cancel() // Ctrl+C
	eq(t, wait(t, done), nil)
	if _, err := c.Get(origin(t, s) + "/api/state"); err == nil {
		t.Error("сервер отвечает после остановки")
	}
}

func TestServeStopsWhenWindowNeverOpens(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.StartTimeout = 50 * time.Millisecond })
	_, done, _ := serving(t, s)
	eq(t, errors.Is(wait(t, done), ErrNotOpened), true)
}

func TestServeStopsWithoutAliveSignal(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.IdleTimeout = 100 * time.Millisecond })
	_, done, c := serving(t, s)
	eq(t, visit(t, c, s.URL()), http.StatusOK)
	eq(t, wait(t, done), nil)
}

func TestAliveSignalKeepsServing(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.IdleTimeout = 400 * time.Millisecond })
	_, done, c := serving(t, s)
	eq(t, visit(t, c, s.URL()), http.StatusOK)
	for range 8 { // вдвое дольше IdleTimeout
		stillServing(t, done, 100*time.Millisecond)
		alive(t, c, s, `{}`)
	}
	eq(t, wait(t, done), nil)
}

func TestClosingSignalStopsSoon(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.CloseGrace = 50 * time.Millisecond })
	_, done, c := serving(t, s)
	eq(t, visit(t, c, s.URL()), http.StatusOK)
	alive(t, c, s, `{"closing":true}`)
	eq(t, wait(t, done), nil)
}

func TestRequestAfterClosingSignalKeepsServing(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.CloseGrace = 300 * time.Millisecond })
	cancel, done, c := serving(t, s)
	eq(t, visit(t, c, s.URL()), http.StatusOK)
	alive(t, c, s, `{"closing":true}`)
	eq(t, visit(t, c, origin(t, s)+"/"), http.StatusOK) // страницу перезагрузили
	stillServing(t, done, 600*time.Millisecond)
	cancel()
	eq(t, wait(t, done), nil)
}

// Сигнал закрытия старой страницы, дочитанный после запроса новой, окно не закрывает.
func TestLateClosingSignalDoesNotStopReloadedWindow(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.CloseGrace = 50 * time.Millisecond })
	p := &page{t: t, s: s}
	p.cookie = sessionCookie(t, p.get(openPath(t, s)))
	_, done, _ := serving(t, s)

	body, send := io.Pipe()
	closing := httptest.NewRequest(http.MethodPost, p.origin+"/api/alive", body)
	closing.AddCookie(p.cookie)
	closing.Header.Set("Content-Type", "application/json")
	closing.Header.Set("Origin", p.origin)
	answered := make(chan int)
	go func() {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, closing)
		answered <- w.Code
	}()
	_, err := send.Write([]byte(`{"closing":`)) // сервер уже читает тело сигнала
	noErr(t, err)
	eq(t, p.get("/api/state").Code, http.StatusOK) // новая страница
	_, err = send.Write([]byte(`true}`))
	noErr(t, err)
	noErr(t, send.Close())
	eq(t, <-answered, http.StatusOK)
	stillServing(t, done, 300*time.Millisecond)
}

// Второе окно в том же браузере не отбирает сеанс у первого: браузер не делит cookie по портам,
// поэтому у каждого сервера своё имя cookie.
func TestSecondWindowKeepsFirstSession(t *testing.T) {
	first, second := newServer(t, &fakeActions{}), newServer(t, &fakeActions{})
	_, _, c := serving(t, first)
	eq(t, visit(t, c, first.URL()), http.StatusOK)
	eq(t, visit(t, c, second.URL()), http.StatusOK)
	eq(t, visit(t, c, origin(t, first)+"/api/state"), http.StatusOK)
	eq(t, visit(t, c, origin(t, second)+"/api/state"), http.StatusOK)
}

func TestSecondUseOfKeyStopsServer(t *testing.T) {
	s := newServer(t, &fakeActions{})
	_, done, c := serving(t, s)
	eq(t, visit(t, c, s.URL()), http.StatusOK)
	eq(t, visit(t, &http.Client{Timeout: 10 * time.Second}, s.URL()), http.StatusUnauthorized)
	eq(t, errors.Is(wait(t, done), ErrKeyReused), true)
}

func TestListensOnLoopbackOnly(t *testing.T) {
	s := newServer(t, &fakeActions{})
	u, err := url.Parse(s.URL())
	noErr(t, err)
	eq(t, u.Hostname(), "127.0.0.1")
	eq(t, u.Port() != "" && u.Port() != "0", true)
}
