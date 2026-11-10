// Package window — окно killswitch: локальный сервер со встроенной страницей и JSON-API поверх тех же
// действий, что у меню в терминале, и запуск окна. Контракт API — API.md.
package window

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/ui"
)

// dist — собранная страница окна; исходники — web/, сборка — npm run build.
//
//go:embed dist
var dist embed.FS

// Сроки жизни сервера.
const (
	// DefaultStartTimeout — сколько ждать первого открытия окна.
	DefaultStartTimeout = 2 * time.Minute
	// DefaultIdleTimeout — сколько жить без запросов окна. Страница шлёт сигнал жизни раз в 20 секунд,
	// но браузер замедляет таймеры фоновой вкладки до раза в минуту — срок больше минуты.
	DefaultIdleTimeout = 90 * time.Second
	// DefaultCloseGrace — сколько ждать после сигнала закрытия: перезагрузка страницы успевает отменить выход.
	DefaultCloseGrace = 3 * time.Second
)

const (
	cookiePrefix = "killswitch_session_" // имя cookie сеанса — с портом сервера
	maxBody      = 64 << 10              // байт в теле запроса
	secretSize   = 32                    // байт в ключе и в cookie сеанса
)

var (
	// ErrNotOpened — окно не пришло по адресу с ключом за StartTimeout.
	ErrNotOpened = errors.New("окно не открыто: по адресу с ключом никто не пришёл")
	// ErrKeyReused — ключ предъявлен второй раз без сеанса: сервер остановлен.
	ErrKeyReused = errors.New("ключ окна предъявлен повторно: окно закрыто, откройте его заново")
	// ErrNotConfigured — действие требует сохранённых настроек (ответ 409).
	ErrNotConfigured = errors.New("защита не настроена: сначала сохраните настройки")
)

// InputError — действие отклонило настройки или запрос пользователя (ответ 422).
type InputError struct{ Err error }

func (e InputError) Error() string { return e.Err.Error() }
func (e InputError) Unwrap() error { return e.Err }

// CheckReport — итог проверки утечек для окна.
type CheckReport struct {
	Result  probe.CheckResult
	Summary string      // итог одной строкой
	Note    string      // пояснение к итогу, может быть пустым
	Tunnels []ui.Tunnel // адаптеры туннеля на момент проверки
	Notes   []string    // строки WARN и LEAK, как в ui.Header
}

// Actions — действия окна: те же, что у меню (ui.Actions), но проверка возвращает итог, а не печатает.
// Сервер вызывает их по одному.
type Actions interface {
	Header() ui.Header
	Configured() bool // настройки сохранены (есть config.toml)
	Transition(m policy.Mode) error
	Check(ctx context.Context) (CheckReport, error)
	Detect() []string
	Profiles() []ui.Profile
	LoadConfig() (policy.Config, error)
	Running() ([]backend.Program, error)
	Save(data []byte) (saved string, err error)
}

// Options — настройки сервера. Нулевой срок — значение по умолчанию.
type Options struct {
	Actions      Actions
	Caps         policy.Capabilities
	StartTimeout time.Duration
	IdleTimeout  time.Duration
	CloseGrace   time.Duration
}

// Server — сервер одного окна: один ключ, один сеанс.
type Server struct {
	opt     Options
	http    *http.Server
	failed  chan error // http.Server.Serve вернулся
	host    string     // 127.0.0.1:<порт> — единственный допустимый Host
	cookie  string     // имя cookie сеанса
	key     string
	session string
	page    http.Handler
	api     map[string]map[string]handler

	actions sync.Mutex // действия не рассчитаны на одновременные вызовы
	mu      sync.Mutex
	opened  bool   // ключ обменян на сеанс
	seen    uint64 // сколько запросов окна пришло
	timer   *time.Timer
	done    chan error
}

// New занимает свободный порт на 127.0.0.1 и сразу начинает отвечать: окно, открытое следом, не ждёт.
// Отсчёт StartTimeout идёт с этого момента. Дальше — Wait; без Wait — Close.
func New(opt Options) (*Server, error) {
	if opt.StartTimeout == 0 {
		opt.StartTimeout = DefaultStartTimeout
	}
	if opt.IdleTimeout == 0 {
		opt.IdleTimeout = DefaultIdleTimeout
	}
	if opt.CloseGrace == 0 {
		opt.CloseGrace = DefaultCloseGrace
	}
	key, err := secret()
	if err != nil {
		return nil, err
	}
	session, err := secret()
	if err != nil {
		return nil, err
	}
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	// Браузер не делит cookie по портам: имя с портом — чтобы второе окно не затёрло сеанс первого.
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s := &Server{opt: opt, host: ln.Addr().String(), cookie: cookiePrefix + port, key: key, session: session,
		page: http.FileServerFS(files), done: make(chan error, 1), failed: make(chan error, 1)}
	s.api = s.routes()
	s.timer = time.AfterFunc(opt.StartTimeout, s.expire)
	s.http = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go func() { s.failed <- s.http.Serve(ln) }()
	return s, nil
}

// secret — 32 случайных байта в base64url.
func secret() (string, error) {
	b := make([]byte, secretSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// URL — адрес первого открытия окна; ключ в нём действует один раз.
func (s *Server) URL() string { return "http://" + s.host + "/open?key=" + s.key }

// Close останавливает сервер сразу.
func (s *Server) Close() error {
	s.timer.Stop()
	return s.http.Close()
}

// Wait ждёт закрытия окна (nil), отмены ctx (nil) или ошибки — ErrNotOpened, ErrKeyReused — и останавливает сервер.
func (s *Server) Wait(ctx context.Context) error {
	var result error
	select {
	case <-ctx.Done():
	case result = <-s.done:
	case result = <-s.failed:
	}
	s.timer.Stop()
	// Начатые ответы получают короткий срок; долгая проверка обрывается вместе со своим запросом.
	stop, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.http.Shutdown(stop); err != nil {
		_ = s.http.Close()
	}
	return result
}

// expire — срок вышел: окно закрыто или так и не открылось.
func (s *Server) expire() {
	s.mu.Lock()
	opened := s.opened
	s.mu.Unlock()
	if opened {
		s.finish(nil)
		return
	}
	s.finish(ErrNotOpened)
}

// touch — запрос окна: он продлевает жизнь сервера и отменяет начатое закрытие. Возвращает номер запроса.
func (s *Server) touch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen++
	s.timer.Reset(s.opt.IdleTimeout)
	return s.seen
}

// closing — окно сообщило о закрытии запросом request: ждём CloseGrace. Если после него уже пришёл
// другой запрос (страницу перезагрузили), сигнал опоздал и ничего не меняет.
func (s *Server) closing(request uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request == s.seen {
		s.timer.Reset(s.opt.CloseGrace)
	}
}

func (s *Server) finish(err error) {
	select {
	case s.done <- err:
	default:
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
		"font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")

	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	deny := func(code int, text string) {
		if isAPI {
			writeError(w, code, text)
			return
		}
		http.Error(w, text, code)
	}
	switch {
	case r.Host != s.host:
		// Чужое имя, указывающее на 127.0.0.1 (DNS rebinding), сюда не проходит.
		deny(http.StatusForbidden, "запрос не к адресу окна")
	case r.URL.Path == "/open":
		s.open(w, r)
	case !s.authorized(r):
		deny(http.StatusUnauthorized, "нет сеанса окна: откройте окно killswitch заново")
	case !s.sameOrigin(r, isAPI):
		deny(http.StatusForbidden, "запрос с чужой страницы")
	case isAPI:
		s.serveAPI(w, r, s.touch())
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		w.Header().Set("Allow", "GET, HEAD")
		deny(http.StatusMethodNotAllowed, "метод не поддерживается")
	default:
		s.touch()
		s.page.ServeHTTP(w, r)
	}
}

// open меняет ключ на cookie сеанса — один раз.
func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	if !same(r.URL.Query().Get("key"), s.key) {
		http.Error(w, "неверный ключ окна", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	first := !s.opened
	s.opened = true
	s.mu.Unlock()
	switch {
	case first:
		s.timer.Reset(s.opt.IdleTimeout)
		http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: s.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case s.authorized(r):
		http.Redirect(w, r, "/", http.StatusSeeOther) // то же окно открыло адрес с ключом ещё раз
	default:
		// Ключ знает кто-то ещё: либо он опоздал, либо опередил настоящее окно. Отличить нельзя —
		// сервер останавливается, сеанс первого пришедшего на этом кончается.
		http.Error(w, "ключ уже использован: закройте это окно и откройте killswitch заново", http.StatusUnauthorized)
		s.finish(ErrKeyReused)
	}
}

// authorized — запрос несёт cookie открытого сеанса.
func (s *Server) authorized(r *http.Request) bool {
	s.mu.Lock()
	opened := s.opened
	s.mu.Unlock()
	c, err := r.Cookie(s.cookie)
	return opened && err == nil && same(c.Value, s.session)
}

func same(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// sameOrigin — запрос пришёл от страницы окна, а не с чужого сайта. API принимает только запросы своей
// страницы; сама страница открывается ещё и переходом по адресу (Sec-Fetch-Site: none).
// У изменяющего запроса Origin обязателен: браузеры шлют его с каждым POST и PUT.
func (s *Server) sameOrigin(r *http.Request, isAPI bool) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && (isAPI || site != "none") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	}
	return origin == "http://"+s.host
}
