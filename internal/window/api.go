package window

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/ui"
)

// call — запрос к методу API: номер запроса окна и тело (у GET — nil).
type call struct {
	*http.Request
	number uint64
	body   []byte
}

// handler — метод API: запрос → ответ 200 или ошибка.
type handler func(call) (any, error)

// apiError — ошибка с готовым кодом и телом ответа.
type apiError struct {
	status int
	body   any
}

func (e apiError) Error() string { return "ответ API с кодом ошибки" }

func badRequest(text string) error {
	return apiError{status: http.StatusBadRequest, body: errorJSON{Error: text}}
}

type errorJSON struct {
	Error string `json:"error"`
}

func (s *Server) routes() map[string]map[string]handler {
	return map[string]map[string]handler{
		"/api/state":    {http.MethodGet: s.getState},
		"/api/mode":     {http.MethodPost: s.postMode},
		"/api/check":    {http.MethodPost: s.postCheck},
		"/api/config":   {http.MethodGet: s.getConfig, http.MethodPut: s.putConfig},
		"/api/clients":  {http.MethodGet: s.getClients},
		"/api/programs": {http.MethodGet: s.getPrograms},
		"/api/alive":    {http.MethodPost: s.postAlive},
	}
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request, number uint64) {
	methods, ok := s.api[r.URL.Path]
	if !ok {
		writeError(w, http.StatusNotFound, "такого метода API нет")
		return
	}
	h, ok := methods[r.Method]
	if !ok {
		allowed := make([]string, 0, len(methods))
		for m := range methods {
			allowed = append(allowed, m)
		}
		sort.Strings(allowed)
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}
	var body []byte
	if r.Method != http.MethodGet {
		// Только JSON: форму с чужой страницы браузер с таким типом не отправит.
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "нужен Content-Type: application/json")
			return
		}
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			writeError(w, http.StatusRequestEntityTooLarge, "тело запроса слишком большое")
			return
		case err != nil:
			writeError(w, http.StatusBadRequest, "тело запроса не прочитано")
			return
		}
	}
	out, err := h(call{Request: r, number: number, body: body})
	var ae apiError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, out)
	case errors.As(err, &ae):
		writeJSON(w, ae.status, ae.body)
	default:
		writeError(w, actionStatus(err), err.Error())
	}
}

// actionStatus — код ответа по ошибке действия.
func actionStatus(err error) int {
	var input InputError
	switch {
	case errors.Is(err, ErrNotConfigured):
		return http.StatusConflict
	case errors.As(err, &input):
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		code, data = http.StatusInternalServerError, []byte(`{"error":"ответ не собран"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, code int, text string) {
	writeJSON(w, code, errorJSON{Error: text})
}

// decode разбирает тело — ровно один JSON-объект без неизвестных полей.
func decode(body []byte, v any) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return badRequest("нужен JSON-объект")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("неверный JSON: " + err.Error())
	}
	if _, err := dec.Token(); err != io.EOF {
		return badRequest("нужен один JSON-объект")
	}
	return nil
}

// decodeOptional — как decode, но тело может быть пустым.
func decodeOptional(body []byte, v any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return decode(body, v)
}

type tunnelJSON struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
}

type warningJSON struct {
	Level string `json:"level"` // warn | leak
	Text  string `json:"text"`
}

type capsJSON struct {
	Repair     bool     `json:"repair"`
	Endpoints  bool     `json:"endpoints"`
	TrustKinds []string `json:"trust_kinds"`
}

type stateJSON struct {
	OS           string        `json:"os"`
	Configured   bool          `json:"configured"`
	Mode         string        `json:"mode"`
	Active       bool          `json:"active"`
	Tunnels      []tunnelJSON  `json:"tunnels"`
	Warnings     []warningJSON `json:"warnings"`
	Capabilities capsJSON      `json:"capabilities"`
}

func tunnels(in []ui.Tunnel) []tunnelJSON {
	out := make([]tunnelJSON, 0, len(in))
	for _, t := range in {
		out = append(out, tunnelJSON(t))
	}
	return out
}

// warnings разбирает строки шапки: метка «LEAK » или «WARN » в начале — уровень, остальное — текст.
func warnings(notes []string) []warningJSON {
	out := make([]warningJSON, 0, len(notes))
	for _, n := range notes {
		w := warningJSON{Level: "warn", Text: n}
		if text, ok := strings.CutPrefix(n, "LEAK "); ok {
			w = warningJSON{Level: "leak", Text: text}
		} else if text, ok := strings.CutPrefix(n, "WARN "); ok {
			w.Text = text
		}
		out = append(out, w)
	}
	return out
}

// state — состояние под замком действий.
func (s *Server) state() stateJSON {
	act, caps := s.opt.Actions, s.opt.Caps
	h := act.Header()
	kinds := make([]string, 0, len(caps.Trust))
	for k, ok := range caps.Trust {
		if ok {
			kinds = append(kinds, string(k))
		}
	}
	sort.Strings(kinds)
	return stateJSON{OS: caps.OS, Configured: act.Configured(), Mode: string(h.Mode), Active: h.Active,
		Tunnels: tunnels(h.Tunnels), Warnings: warnings(h.Notes),
		Capabilities: capsJSON{Repair: caps.Repair, Endpoints: caps.Endpoints, TrustKinds: kinds}}
}

func (s *Server) getState(call) (any, error) {
	s.actions.Lock()
	defer s.actions.Unlock()
	return s.state(), nil
}

func (s *Server) postMode(c call) (any, error) {
	var in struct {
		Mode string `json:"mode"`
	}
	if err := decode(c.body, &in); err != nil {
		return nil, err
	}
	mode, err := policy.ParseMode(in.Mode)
	if err != nil {
		return nil, badRequest(err.Error())
	}
	s.actions.Lock()
	defer s.actions.Unlock()
	if err := s.opt.Actions.Transition(mode); err != nil {
		return nil, err
	}
	return s.state(), nil
}

type probeJSON struct {
	Target string `json:"target"`
	Family string `json:"family"`
	Proto  string `json:"proto"`
	Iface  string `json:"iface"`
	Class  string `json:"class"` // blocked | leak | unsure | skipped
	Detail string `json:"detail"`
}

type findingJSON struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type checkJSON struct {
	Result     string        `json:"result"` // clean | leak | unsure
	Code       int           `json:"code"`   // код возврата команды check
	Simple     bool          `json:"simple"`
	Summary    string        `json:"summary"`
	Note       string        `json:"note"`
	Probes     []probeJSON   `json:"probes"`
	Structural []findingJSON `json:"structural"`
	Tunnels    []tunnelJSON  `json:"tunnels"`
	Warnings   []warningJSON `json:"warnings"`
}

// classWord — класс пробы или итога словом API; итог blocked окно называет clean.
func classWord(c probe.Class) string {
	switch c {
	case probe.Blocked:
		return "blocked"
	case probe.Leak:
		return "leak"
	case probe.Skipped:
		return "skipped"
	}
	return "unsure"
}

func (s *Server) postCheck(c call) (any, error) {
	if err := decodeOptional(c.body, &struct{}{}); err != nil {
		return nil, err
	}
	s.actions.Lock()
	defer s.actions.Unlock()
	rep, err := s.opt.Actions.Check(c.Context())
	if err != nil {
		return nil, err
	}
	res := rep.Result
	out := checkJSON{Result: classWord(res.Overall), Code: probe.ExitCode(res.Overall), Simple: res.Simple,
		Summary: rep.Summary, Note: rep.Note,
		Probes: make([]probeJSON, 0, len(res.Probes)), Structural: make([]findingJSON, 0, len(res.Structural)),
		Tunnels: tunnels(rep.Tunnels), Warnings: warnings(rep.Notes)}
	if res.Overall == probe.Blocked {
		out.Result = "clean"
	}
	for _, p := range res.Probes {
		out.Probes = append(out.Probes, probeJSON{Target: p.Target, Family: p.Family, Proto: p.Proto, Iface: p.Iface,
			Class: classWord(p.Class), Detail: p.Detail})
	}
	for _, f := range res.Structural {
		out.Structural = append(out.Structural, findingJSON{Kind: f.Kind, Detail: f.Detail})
	}
	return out, nil
}

func (s *Server) getConfig(call) (any, error) {
	s.actions.Lock()
	defer s.actions.Unlock()
	cfg, err := s.opt.Actions.LoadConfig()
	if err != nil {
		return nil, err
	}
	return configToJSON(cfg), nil
}

type saveJSON struct {
	Error   string `json:"error,omitempty"`
	Saved   bool   `json:"saved"` // файл настроек записан
	Message string `json:"message,omitempty"`
}

func (s *Server) putConfig(c call) (any, error) {
	var in configJSON
	if err := decode(c.body, &in); err != nil {
		return nil, err
	}
	data, err := policy.Encode(in.config())
	if err != nil {
		return nil, badRequest(err.Error())
	}
	s.actions.Lock()
	defer s.actions.Unlock()
	saved, err := s.opt.Actions.Save(data)
	if err != nil {
		return nil, apiError{status: actionStatus(err), body: saveJSON{Error: err.Error(), Saved: saved != "", Message: saved}}
	}
	return saveJSON{Saved: true, Message: saved}, nil
}

type profileJSON struct {
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	Detected       bool        `json:"detected"` // клиент найден на этой машине
	Interfaces     []string    `json:"interfaces"`
	Trust          []trustJSON `json:"trust"`
	RepairPrograms []string    `json:"repair_programs"`
}

func (s *Server) getClients(call) (any, error) {
	s.actions.Lock()
	defer s.actions.Unlock()
	detected := s.opt.Actions.Detect()
	profiles := s.opt.Actions.Profiles()
	out := make([]profileJSON, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, profileJSON{Name: p.Name, Description: p.Description, Detected: slices.Contains(detected, p.Name),
			Interfaces: list(p.Layer.Interfaces), Trust: trustToJSON(p.Layer.Trust), RepairPrograms: list(p.Layer.RepairPrograms)})
	}
	return struct {
		Profiles []profileJSON `json:"profiles"`
	}{out}, nil
}

type programJSON struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}

func (s *Server) getPrograms(call) (any, error) {
	s.actions.Lock()
	defer s.actions.Unlock()
	progs, err := s.opt.Actions.Running()
	if err != nil {
		return nil, err
	}
	names := ui.RunningNames(progs)
	out := make([]programJSON, 0, len(names))
	for _, n := range names {
		out = append(out, programJSON{Name: n.Name, Paths: n.Paths})
	}
	return struct {
		Programs []programJSON `json:"programs"`
	}{out}, nil
}

// postAlive — сигнал жизни окна. Сам запрос уже продлил срок; closing сокращает его до CloseGrace.
// Замок действий не берётся: сигнал проходит и во время долгой проверки.
func (s *Server) postAlive(c call) (any, error) {
	var in struct {
		Closing bool `json:"closing"`
	}
	if err := decodeOptional(c.body, &in); err != nil {
		return nil, err
	}
	if in.Closing {
		s.closing(c.number)
	}
	return struct{}{}, nil
}

// list — список для JSON: пустой, а не null.
func list(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
