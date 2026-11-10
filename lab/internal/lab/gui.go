package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// ScenarioWindow — строка сводки: живой запуск killswitch window и его API.
const ScenarioWindow = "окно"

// HTTPSpec — один запрос «браузера» приёмки к окну. Исполняет его подкоманда kslab http внутри ksl-client.
type HTTPSpec struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Host    string            `json:"host,omitempty"` // заголовок Host; "" — из адреса
	Header  map[string]string `json:"header,omitempty"`
	Body    string            `json:"body,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"` // 0 — 30 с
}

// HTTPResult — ответ как есть: переходы не выполняются. Err — запрос не состоялся.
type HTTPResult struct {
	Status      int      `json:"status"`
	Location    string   `json:"location,omitempty"`
	SetCookie   []string `json:"set_cookie,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Body        string   `json:"body,omitempty"`
	Err         string   `json:"err,omitempty"`
}

const httpBodyLimit = 1 << 20

// DoHTTP выполняет запрос. Адрес — только http://127.0.0.1:<порт>: другой отклоняется до соединения,
// прокси из окружения не используется, соединение идёт ровно на адрес из запроса.
func DoHTTP(s HTTPSpec) HTTPResult {
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		return HTTPResult{Err: "адрес не http://127.0.0.1:<порт>: " + maskKey(s.URL)}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, s.Method, s.URL, strings.NewReader(s.Body))
	if err != nil {
		return HTTPResult{Err: maskKey(err.Error())}
	}
	if s.Host != "" {
		req.Host = s.Host
	}
	for k, v := range s.Header {
		req.Header.Set(k, v)
	}
	target := u.Host
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != target {
					return nil, fmt.Errorf("соединение не с %s", target)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp4", target)
			}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return HTTPResult{Err: maskKey(err.Error())}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpBodyLimit))
	out := HTTPResult{Status: resp.StatusCode, Location: resp.Header.Get("Location"), SetCookie: resp.Header.Values("Set-Cookie"),
		ContentType: resp.Header.Get("Content-Type"), Body: string(body)}
	if err != nil {
		out.Err = "тело ответа не прочитано: " + err.Error()
	}
	return out
}

// windowAddr — адрес окна, который killswitch window передал команде открытия.
type windowAddr struct {
	Base string // http://127.0.0.1:<порт>
	Port string
	Key  string
}

var windowURLRe = regexp.MustCompile(`^(http://127\.0\.0\.1:(\d{1,5}))/open\?key=([A-Za-z0-9_-]{43})$`)

// ParseWindowURL разбирает адрес окна; другой вид адреса — ошибка (ключ в текст ошибки не попадает).
func ParseWindowURL(line string) (windowAddr, error) {
	m := windowURLRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return windowAddr{}, fmt.Errorf("адрес окна не вида http://127.0.0.1:<порт>/open?key=<ключ>: %q", maskKey(strings.TrimSpace(line)))
	}
	return windowAddr{Base: m[1], Port: m[2], Key: m[3]}, nil
}

var keyRe = regexp.MustCompile(`key=[A-Za-z0-9_-]+`)

// maskKey убирает ключ окна из текста для журнала.
func maskKey(s string) string { return keyRe.ReplaceAllString(s, "key=…") }

// EnvWith — окружение запуска: переменные drop убраны, пары set ("ИМЯ=значение") заменяют прежние.
func EnvWith(env, drop []string, set ...string) []string {
	gone := map[string]bool{}
	for _, name := range drop {
		gone[name] = true
	}
	for _, kv := range set {
		name, _, _ := strings.Cut(kv, "=")
		gone[name] = true
	}
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		if name, _, _ := strings.Cut(kv, "="); !gone[name] {
			out = append(out, kv)
		}
	}
	return append(out, set...)
}

// SameConfig — два текста config.toml задают одни и те же настройки (разбор killswitch даёт равный итог).
func SameConfig(a, b string) (bool, error) {
	ca, err := policy.ParseConfig([]byte(a))
	if err != nil {
		return false, err
	}
	cb, err := policy.ParseConfig([]byte(b))
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(ca, cb), nil
}

// portListeners — локальные адреса слушающих сокетов порта из вывода `ss -Hltn`.
func portListeners(ss, port string) []string {
	var out []string
	for _, line := range strings.Split(ss, "\n") {
		if f := strings.Fields(line); len(f) >= 4 && strings.HasSuffix(f[3], ":"+port) {
			out = append(out, f[3])
		}
	}
	return out
}

// CheckAgrees — итог проверки окна сходится с командой check: слово result отвечает коду, код равен коду команды.
// При перехвате клиентом (redirect) — допуск сценария 9: 0 или 5 и ни одной пробы leak.
func CheckAgrees(result string, code, leaks, cliCode int, redirect bool) bool {
	word := map[int]string{0: "clean", 4: "leak", 5: "unsure"}[code]
	if word == "" || word != result {
		return false
	}
	if redirect {
		return code != 4 && leaks == 0
	}
	return code == cliCode
}

// guiHost — чем сценарий «браузера» ходит к окну и что стенд видит сам.
type guiHost struct {
	do       func(HTTPSpec) HTTPResult
	report   func(name string, ok bool, detail string)
	rules    func() string          // листинг таблицы inet killswitch в ns клиента
	config   func() (string, error) // файл настроек killswitch
	modeSet  func(mode string)      // наблюдения стенда после смены режима через окно; nil — нет
	tunnel   string                 // адаптер туннеля клиента
	profile  string                 // профиль клиента; "" — без профиля
	redirect bool                   // клиент перехватывает трафик (допуск сценария 9)
	cliCode  int                    // код команды check под той же защитой
	beat     time.Duration          // шаг сигнала жизни во время проверки
}

const checkTimeout = 3 * time.Minute

// guiSession играет окно: обмен ключа, границы доступа, состояние, смена режима, проверка, настройки, списки,
// сигнал закрытия. closed — сигнал закрытия принят последним запросом: сервер обязан завершиться сам.
func guiSession(h guiHost, addr windowAddr) (closed bool) {
	state := addr.Base + "/api/state"
	open := addr.Base + "/open?key=" + addr.Key
	jsonType := map[string]string{"Content-Type": "application/json"}

	r := h.do(HTTPSpec{Method: http.MethodGet, URL: open})
	cookie, attrs := sessionCookie(r.SetCookie, "killswitch_session_"+addr.Port)
	ok := r.Err == "" && r.Status == http.StatusSeeOther && r.Location == "/" && cookie != "" &&
		attrs == "HttpOnly, SameSite=Strict, Path=/"
	h.report("обмен ключа: 303 на /, cookie сеанса HttpOnly и SameSite=Strict", ok, brief(r)+"; cookie: "+attrs)
	if !ok {
		return false
	}
	with := func(extra ...map[string]string) map[string]string {
		out := map[string]string{"Cookie": cookie}
		for _, m := range extra {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	origin := map[string]string{"Origin": addr.Base}
	call := func(method, path, body string, timeout time.Duration) HTTPResult {
		hdr := with()
		if method != http.MethodGet {
			hdr = with(origin, jsonType)
		}
		return h.do(HTTPSpec{Method: method, URL: addr.Base + path, Header: hdr, Body: body, Timeout: timeout})
	}
	api := func(method, path, body string) HTTPResult { return call(method, path, body, 0) }
	status := func(name string, r HTTPResult, want int) bool {
		ok := r.Err == "" && r.Status == want
		h.report(name, ok, brief(r))
		return ok
	}

	r = h.do(HTTPSpec{Method: http.MethodGet, URL: open, Header: with()})
	h.report("повтор ключа с cookie: 303 на /", r.Err == "" && r.Status == http.StatusSeeOther && r.Location == "/", brief(r))
	status("запрос API без cookie: 401", h.do(HTTPSpec{Method: http.MethodGet, URL: state}), http.StatusUnauthorized)
	status("чужой Host: 403", h.do(HTTPSpec{Method: http.MethodGet, URL: state, Host: "localhost:" + addr.Port, Header: with()}),
		http.StatusForbidden)
	alive := addr.Base + "/api/alive"
	status("POST без Origin: 403", h.do(HTTPSpec{Method: http.MethodPost, URL: alive, Header: with(jsonType), Body: "{}"}),
		http.StatusForbidden)
	status("тот же POST с Origin: 200", api(http.MethodPost, "/api/alive", "{}"), http.StatusOK)
	r = h.do(HTTPSpec{Method: http.MethodGet, URL: addr.Base + "/", Header: with()})
	h.report("страница /: 200 text/html", r.Err == "" && r.Status == http.StatusOK && strings.HasPrefix(r.ContentType, "text/html"),
		fmt.Sprintf("%s; %s; %d байт", briefStatus(r), r.ContentType, len(r.Body)))

	var st guiState
	r = api(http.MethodGet, "/api/state", "")
	parsed := decodeBody(r, &st)
	h.report("состояние под защитой: linux, настройки есть, режим on, правила стоят",
		parsed && st.OS == "linux" && st.Configured && st.Mode == "on" && st.Active, brief(r)+"; "+st.String())
	h.report("адаптер туннеля "+h.tunnel+" поднят", parsed && slices.Contains(st.Tunnels, guiTunnel{Name: h.tunnel, Up: true}),
		fmt.Sprintf("адаптеры: %v", st.Tunnels))
	h.report("состояние под защитой: замечаний уровня leak нет", parsed && !st.leak(), fmt.Sprintf("замечания: %v", st.Warnings))

	st = guiState{}
	r = api(http.MethodPost, "/api/mode", `{"mode":"off"}`)
	parsed = decodeBody(r, &st)
	rules := h.rules()
	ok = parsed && st.Mode == "off" && !strings.Contains(rules, "chain")
	h.report("mode off: режим off, цепочек в таблице killswitch нет", ok,
		fmt.Sprintf("%s; %s; таблица: %s", brief(r), st.String(), oneLine(rules)))
	if ok && h.modeSet != nil {
		h.modeSet("off")
	}
	st = guiState{}
	r = api(http.MethodPost, "/api/mode", `{"mode":"on"}`)
	parsed = decodeBody(r, &st)
	rules = h.rules()
	ok = parsed && st.Mode == "on" && st.Active && strings.Contains(rules, "chain postrouting")
	h.report("mode on: режим on, правила стоят, цепочка postrouting на месте", ok,
		fmt.Sprintf("%s; %s; цепочка postrouting в таблице: %t", brief(r), st.String(), strings.Contains(rules, "chain postrouting")))
	if ok && h.modeSet != nil {
		h.modeSet("on")
	}

	guiCheck(h, api, func() HTTPResult { return call(http.MethodPost, "/api/check", "{}", checkTimeout) })
	guiConfig(h, api)

	var clients struct {
		Profiles []struct {
			Name string `json:"name"`
		} `json:"profiles"`
	}
	r = api(http.MethodGet, "/api/clients", "")
	parsed = decodeBody(r, &clients)
	var names []string
	for _, p := range clients.Profiles {
		names = append(names, p.Name)
	}
	name := "/api/clients: список профилей"
	if h.profile != "" {
		name += ", среди них " + h.profile
	}
	h.report(name, parsed && len(names) > 0 && (h.profile == "" || slices.Contains(names, h.profile)),
		fmt.Sprintf("%s; профили: %v", briefStatus(r), names))

	var programs struct {
		Programs *[]struct {
			Name string `json:"name"`
		} `json:"programs"`
	}
	r = api(http.MethodGet, "/api/programs", "")
	parsed = decodeBody(r, &programs)
	h.report("/api/programs: список есть и пуст", parsed && programs.Programs != nil && len(*programs.Programs) == 0, brief(r))

	return status("сигнал закрытия: 200", api(http.MethodPost, "/api/alive", `{"closing": true}`), http.StatusOK)
}

// guiCheck — проверка утечек через окно. Пока она идёт, окно шлёт сигналы жизни, как страница: без них сервер
// завершился бы по сроку простоя.
func guiCheck(h guiHost, api func(method, path, body string) HTTPResult, check func() HTTPResult) {
	done := make(chan HTTPResult, 1)
	go func() { done <- check() }()
	tick := time.NewTicker(h.beat)
	defer tick.Stop()
	beats, lost := 0, ""
	var r HTTPResult
wait:
	for {
		select {
		case r = <-done:
			break wait
		case <-tick.C:
			beats++
			if b := api(http.MethodPost, "/api/alive", "{}"); b.Err != "" || b.Status != http.StatusOK {
				lost = brief(b)
			}
		}
	}
	var res struct {
		Result  string `json:"result"`
		Code    int    `json:"code"`
		Summary string `json:"summary"`
		Probes  []struct {
			Class string `json:"class"`
		} `json:"probes"`
	}
	parsed := decodeBody(r, &res)
	leaks := 0
	for _, p := range res.Probes {
		if p.Class == "leak" {
			leaks++
		}
	}
	name := "/api/check под защитой: result и code как у команды check"
	if h.redirect {
		name = "/api/check под защитой при перехвате клиентом: 0 или 5, без leak"
	}
	h.report(name, parsed && CheckAgrees(res.Result, res.Code, leaks, h.cliCode, h.redirect),
		fmt.Sprintf("%s; result %q, code %d (команда check: %d), проб %d, из них leak %d; %s", briefStatus(r), res.Result, res.Code,
			h.cliCode, len(res.Probes), leaks, res.Summary))
	if beats > 0 {
		h.report("сигнал жизни во время проверки: 200", lost == "", fmt.Sprintf("сигналов %d; %s", beats, lost))
	}
}

// guiConfig — настройки: чтение, запись тем же телом (файл по смыслу прежний), отказ на неверное значение.
func guiConfig(h guiHost, api func(method, path, body string) HTTPResult) {
	before, err := h.config()
	if err != nil {
		h.report("файл настроек стенда читается", false, err.Error())
		return
	}
	got := api(http.MethodGet, "/api/config", "")
	var cfg map[string]any
	if !decodeBody(got, &cfg) {
		h.report("GET /api/config: 200 и настройки", false, brief(got))
		return
	}
	h.report("GET /api/config: 200 и настройки", true, briefStatus(got))

	var saved guiSaved
	r := api(http.MethodPut, "/api/config", got.Body)
	parsed := decodeBody(r, &saved)
	after, err := h.config()
	same, cmpErr := false, err
	if err == nil {
		same, cmpErr = SameConfig(before, after)
	}
	again := api(http.MethodGet, "/api/config", "")
	var cfg2 map[string]any
	reread := decodeBody(again, &cfg2) && reflect.DeepEqual(cfg, cfg2)
	h.report("PUT /api/config тем же телом: saved, применено (on), файл по смыслу прежний",
		parsed && saved.Saved && saved.Message == "сохранено и применено (on)" && same && reread,
		fmt.Sprintf("%s; saved %t, %q; файл по смыслу прежний: %t%s; повторный GET равен первому: %t", briefStatus(r), saved.Saved,
			saved.Message, same, errNote(cmpErr), reread))

	cfg["profile"] = "нет-такого-профиля"
	bad, _ := jsonText(cfg)
	saved = guiSaved{}
	r = api(http.MethodPut, "/api/config", bad)
	rejected := r.Err == "" && r.Status == http.StatusUnprocessableEntity && jsonInto(r.Body, &saved) && !saved.Saved && saved.Error != ""
	final, err := h.config()
	h.report("PUT /api/config с несуществующим профилем: 422, файл прежний", rejected && err == nil && final == after,
		fmt.Sprintf("%s; saved %t, %q; файл побайтно прежний: %t%s", briefStatus(r), saved.Saved, saved.Error, err == nil && final == after,
			errNote(err)))
}

type guiSaved struct {
	Error   string `json:"error"`
	Saved   bool   `json:"saved"`
	Message string `json:"message"`
}

type guiTunnel struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
}

type guiState struct {
	OS         string      `json:"os"`
	Configured bool        `json:"configured"`
	Mode       string      `json:"mode"`
	Active     bool        `json:"active"`
	Tunnels    []guiTunnel `json:"tunnels"`
	Warnings   []struct {
		Level string `json:"level"`
		Text  string `json:"text"`
	} `json:"warnings"`
}

func (s guiState) String() string {
	return fmt.Sprintf("os %s, configured %t, mode %s, active %t", s.OS, s.Configured, s.Mode, s.Active)
}

func (s guiState) leak() bool {
	for _, w := range s.Warnings {
		if w.Level == "leak" {
			return true
		}
	}
	return false
}

// sessionCookie — пара «имя=значение» cookie сеанса и её признаки без значения (для журнала).
func sessionCookie(set []string, name string) (pair, attrs string) {
	for _, line := range set {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name != name || c.Value == "" {
			continue
		}
		var a []string
		if c.HttpOnly {
			a = append(a, "HttpOnly")
		}
		if c.SameSite == http.SameSiteStrictMode {
			a = append(a, "SameSite=Strict")
		}
		if c.Path != "" {
			a = append(a, "Path="+c.Path)
		}
		return c.Name + "=" + c.Value, strings.Join(a, ", ")
	}
	return "", "нет cookie " + name
}

// decodeBody — ответ 200 с JSON-объектом разобран в v.
func decodeBody(r HTTPResult, v any) bool {
	return r.Err == "" && r.Status == http.StatusOK && jsonInto(r.Body, v)
}

func jsonInto(body string, v any) bool { return json.Unmarshal([]byte(body), v) == nil }

func jsonText(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func errNote(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

// briefStatus — код ответа или ошибка запроса.
func briefStatus(r HTTPResult) string {
	if r.Err != "" {
		return "запрос не прошёл: " + r.Err
	}
	return fmt.Sprintf("код %d", r.Status)
}

// brief — ответ для журнала: код, переход и начало тела отказа. Заголовок Set-Cookie сюда не попадает.
func brief(r HTTPResult) string {
	s := briefStatus(r)
	if r.Location != "" {
		s += " → " + r.Location
	}
	if r.Err == "" && r.Status >= 400 {
		s += ": " + oneLine(r.Body)
	}
	return s
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}
