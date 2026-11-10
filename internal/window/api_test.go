package window

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/ui"
)

// sameJSON сравнивает ответ с ожидаемым JSON без учёта пробелов и порядка ключей.
func sameJSON(t *testing.T, w *httptest.ResponseRecorder, code int, want string) {
	t.Helper()
	eq(t, w.Code, code)
	eq(t, w.Header().Get("Content-Type"), "application/json")
	var got, exp any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("ответ не JSON: %v: %s", err, w.Body.String())
	}
	noErr(t, json.Unmarshal([]byte(want), &exp))
	if g, e := mustJSON(t, got), mustJSON(t, exp); g != e {
		t.Errorf("получено  %s\nожидалось %s", g, e)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	noErr(t, err)
	return string(b)
}

func TestStateReportsHeader(t *testing.T) {
	act := &fakeActions{configured: true, header: ui.Header{
		Mode: policy.ModeOn, Active: true,
		Tunnels: []ui.Tunnel{{Name: "wg-example", Up: true}},
		Notes:   []string{"WARN незавершённый переход к off", "LEAK wfp-tie: чужой permit", "строка без метки"},
	}}
	sameJSON(t, opened(t, act).get("/api/state"), http.StatusOK, `{
		"os": "windows", "configured": true, "mode": "on", "active": true,
		"tunnels": [{"name": "wg-example", "up": true}],
		"warnings": [
			{"level": "warn", "text": "незавершённый переход к off"},
			{"level": "leak", "text": "wfp-tie: чужой permit"},
			{"level": "warn", "text": "строка без метки"}],
		"capabilities": {"repair": true, "endpoints": true, "trust_kinds": ["program"]}}`)
}

func TestStateOfFreshInstall(t *testing.T) {
	s := newServer(t, &fakeActions{}, func(o *Options) { o.Caps = policy.CapabilitiesFor("linux") })
	p := &page{t: t, s: s}
	p.cookie = sessionCookie(t, p.get(openPath(t, s)))
	sameJSON(t, p.get("/api/state"), http.StatusOK, `{
		"os": "linux", "configured": false, "mode": "", "active": false, "tunnels": [], "warnings": [],
		"capabilities": {"repair": false, "endpoints": true, "trust_kinds": ["cgroup", "mark", "user"]}}`)
}

func TestModeAppliesAndReturnsState(t *testing.T) {
	act := &fakeActions{configured: true}
	p := opened(t, act)
	w := p.post("/api/mode", `{"mode":"repair"}`)
	eq(t, w.Code, http.StatusOK)
	eq(t, act.transitions, []policy.Mode{policy.ModeRepair})
	eq(t, strings.Contains(w.Body.String(), `"mode":"repair"`), true)
}

func TestModeRejectsBadInput(t *testing.T) {
	act := &fakeActions{}
	p := opened(t, act)
	for _, body := range []string{`{"mode":"sideways"}`, `{}`, ``, `{"mode":"on","extra":1}`, `{"mode":`, `[]`, `{"mode":"on"} {"mode":"off"}`,
		`{"mode":"off"}]`, `{"mode":"off"}}`, `{"mode":"off"} x`} {
		w := p.post("/api/mode", body)
		eq(t, w.Code, http.StatusBadRequest)
		eq(t, strings.Contains(w.Body.String(), `"error"`), true)
	}
	eq(t, len(act.transitions), 0)
}

func TestActionErrorsBecomeStatusCodes(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{InputError{Err: errors.New("tunnel.interfaces: не задан ни один интерфейс туннеля")}, http.StatusUnprocessableEntity},
		{ErrNotConfigured, http.StatusConflict},
		{errors.New("применение: отказ"), http.StatusInternalServerError},
	} {
		act := &fakeActions{transitionErr: c.err, checkErr: c.err, cfgErr: c.err, runningErr: c.err}
		p := opened(t, act)
		want := `{"error": ` + mustJSON(t, c.err.Error()) + `}`
		sameJSON(t, p.post("/api/mode", `{"mode":"on"}`), c.code, want)
		sameJSON(t, p.post("/api/check", ``), c.code, want)
		sameJSON(t, p.get("/api/config"), c.code, want)
		sameJSON(t, p.get("/api/programs"), c.code, want)
	}
}

func TestCheckReportsStructure(t *testing.T) {
	act := &fakeActions{report: CheckReport{
		Result: probe.CheckResult{
			Overall: probe.Leak,
			Probes: []probe.ProbeResult{
				{Target: "203.0.113.130:443", Family: "ipv4", Proto: "tcp", Iface: "Ethernet", Class: probe.Leak, Detail: "ответ получен"},
				{Target: "203.0.113.130:53", Family: "ipv4", Proto: "udp", Iface: "Ethernet", Class: probe.Blocked, Detail: "отброшено правилом"},
				{Target: "203.0.113.130:443", Family: "ipv6", Proto: "tcp", Iface: "Ethernet", Class: probe.Skipped, Detail: "нет адреса"},
				{Target: "203.0.113.130:443", Family: "ipv4", Proto: "tcp", Iface: "Wi-Fi", Class: probe.Inconclusive, Detail: "нет свидетельства"},
			},
			Structural: []probe.StructuralFinding{{Kind: "wfp-tie", Detail: "чужой permit", Repair: true}},
		},
		Summary: "УТЕЧКА", Note: "адаптер Ethernet: tcp 203.0.113.130:443",
		Tunnels: []ui.Tunnel{{Name: "wg-example", Up: true}},
		Notes:   []string{"WARN шаблону туннеля соответствует больше одного адаптера"},
	}}
	sameJSON(t, opened(t, act).post("/api/check", `{}`), http.StatusOK, `{
		"result": "leak", "code": 4, "simple": false, "summary": "УТЕЧКА", "note": "адаптер Ethernet: tcp 203.0.113.130:443",
		"probes": [
			{"target": "203.0.113.130:443", "family": "ipv4", "proto": "tcp", "iface": "Ethernet", "class": "leak", "detail": "ответ получен"},
			{"target": "203.0.113.130:53", "family": "ipv4", "proto": "udp", "iface": "Ethernet", "class": "blocked", "detail": "отброшено правилом"},
			{"target": "203.0.113.130:443", "family": "ipv6", "proto": "tcp", "iface": "Ethernet", "class": "skipped", "detail": "нет адреса"},
			{"target": "203.0.113.130:443", "family": "ipv4", "proto": "tcp", "iface": "Wi-Fi", "class": "unsure", "detail": "нет свидетельства"}],
		"structural": [{"kind": "wfp-tie", "detail": "чужой permit"}],
		"tunnels": [{"name": "wg-example", "up": true}],
		"warnings": [{"level": "warn", "text": "шаблону туннеля соответствует больше одного адаптера"}]}`)
}

func TestCheckRejectsBadBody(t *testing.T) {
	act := &fakeActions{configured: true}
	p := opened(t, act)
	for _, body := range []string{`not-json`, `[]`, `{"unknown":1}`, `{}]`} {
		eq(t, p.post("/api/check", body).Code, http.StatusBadRequest)
	}
	eq(t, act.checks, 0)
	for _, body := range []string{``, `{}`, " {} \n"} {
		eq(t, p.post("/api/check", body).Code, http.StatusOK)
	}
	eq(t, act.checks, 3)
}

func TestCheckResultWords(t *testing.T) {
	for _, c := range []struct {
		overall probe.Class
		want    string
	}{
		{probe.Blocked, `"result":"clean","code":0,"simple":true`},
		{probe.Leak, `"result":"leak","code":4,"simple":true`},
		{probe.Inconclusive, `"result":"unsure","code":5,"simple":true`},
	} {
		act := &fakeActions{report: CheckReport{Result: probe.CheckResult{Overall: c.overall, Simple: true}}}
		w := opened(t, act).post("/api/check", ``)
		eq(t, w.Code, http.StatusOK)
		if !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("в ответе %s нет %s", w.Body.String(), c.want)
		}
		eq(t, strings.Contains(w.Body.String(), `"probes":[]`), true)
	}
}

func strs(v ...string) *[]string { return &v }

func ptr[T any](v T) *T { return &v }

func TestConfigReadsEveryKey(t *testing.T) {
	cfg := policy.Config{Profile: "example", LAN: ptr(false), TrustMode: ptr("strict")}
	cfg.Tunnel.Interfaces, cfg.Tunnel.Endpoints = strs("wg*"), strs("203.0.113.1:51820")
	cfg.SetTrust([]policy.Trust{{Kind: policy.KindProgram, Value: `C:\Program Files\Example\tunnel.exe`, Destinations: policy.DestEndpoints},
		{Kind: policy.KindProgram, Value: `C:\Program Files\Example\helper.exe`}})
	cfg.DNS.Mode, cfg.DNS.Resolvers, cfg.DNS.Health = ptr("resolvers"), strs("192.0.2.53"), ptr("http://198.18.0.1:80/")
	cfg.Repair.Programs, cfg.Repair.Names = strs(), strs("node")
	cfg.Check.Targets = strs("203.0.113.130")
	sameJSON(t, opened(t, &fakeActions{cfg: cfg}).get("/api/config"), http.StatusOK, `{
		"profile": "example", "lan": false, "trust_mode": "strict",
		"tunnel": {"interfaces": ["wg*"], "endpoints": ["203.0.113.1:51820"]},
		"trust": [
			{"kind": "program", "value": "C:\\Program Files\\Example\\tunnel.exe", "destinations": "endpoints"},
			{"kind": "program", "value": "C:\\Program Files\\Example\\helper.exe", "destinations": ""}],
		"dns": {"mode": "resolvers", "resolvers": ["192.0.2.53"], "health": "http://198.18.0.1:80/"},
		"repair": {"programs": [], "names": ["node"]},
		"check": {"targets": ["203.0.113.130"]}}`)
}

func TestConfigOfEmptyFileIsNulls(t *testing.T) {
	sameJSON(t, opened(t, &fakeActions{}).get("/api/config"), http.StatusOK, `{
		"profile": "", "lan": null, "trust_mode": null,
		"tunnel": {"interfaces": null, "endpoints": null},
		"trust": null,
		"dns": {"mode": null, "resolvers": null, "health": null},
		"repair": {"programs": null, "names": null},
		"check": {"targets": null}}`)
}

func TestConfigSaveGoesThroughSave(t *testing.T) {
	act := &fakeActions{saveMsg: "сохранено и применено (on)"}
	p := opened(t, act)
	body := `{"profile": "example", "lan": false, "trust_mode": null,
		"tunnel": {"interfaces": ["wg*"], "endpoints": null},
		"trust": [{"kind": "program", "value": "C:\\Program Files\\Example\\tunnel.exe", "destinations": "any"}],
		"dns": {"mode": "open", "resolvers": null, "health": null},
		"repair": {"programs": null, "names": ["node"]},
		"check": {"targets": []}}`
	sameJSON(t, p.request(http.MethodPut, "/api/config", body), http.StatusOK,
		`{"saved": true, "message": "сохранено и применено (on)"}`)
	eq(t, len(act.saved), 1)

	// сохранённые байты — тот же конфиг, что прислало окно: ключ null не пишется, пустой список пишется
	got, err := policy.ParseConfig([]byte(act.saved[0]))
	noErr(t, err)
	want := policy.Config{Profile: "example", LAN: ptr(false)}
	want.Tunnel.Interfaces = strs("wg*")
	want.SetTrust([]policy.Trust{{Kind: policy.KindProgram, Value: `C:\Program Files\Example\tunnel.exe`, Destinations: policy.DestAny}})
	want.DNS.Mode = ptr("open")
	want.Repair.Names = strs("node")
	want.Check.Targets = &[]string{}
	wantTOML, err := policy.Encode(want)
	noErr(t, err)
	eq(t, act.saved[0], string(wantTOML))
	eq(t, got.Tunnel.Endpoints == nil && got.TrustMode == nil && got.Repair.Programs == nil, true)

	// прочитанное окном можно сохранить без правок
	act.cfg = got
	read := p.get("/api/config").Body.String()
	eq(t, p.request(http.MethodPut, "/api/config", read).Code, http.StatusOK)
	eq(t, act.saved[1], act.saved[0])
}

func TestConfigSaveErrors(t *testing.T) {
	act := &fakeActions{saveErr: InputError{Err: errors.New("не сохранено: trust_mode \"x\": нужен compat или strict")}}
	p := opened(t, act)
	sameJSON(t, p.request(http.MethodPut, "/api/config", `{"trust_mode":"x"}`), http.StatusUnprocessableEntity,
		`{"error": "не сохранено: trust_mode \"x\": нужен compat или strict", "saved": false}`)

	act.saveMsg, act.saveErr = "сохранено, но не применено", errors.New("применение: отказ")
	sameJSON(t, p.request(http.MethodPut, "/api/config", `{"profile":"example"}`), http.StatusInternalServerError,
		`{"error": "применение: отказ", "saved": true, "message": "сохранено, но не применено"}`)

	saved := len(act.saved)
	for _, body := range []string{``, `{"profile":`, `{"unknown":1}`, `{"tunnel":{"extra":1}}`, `[]`, `"profile"`, `null`} {
		eq(t, p.request(http.MethodPut, "/api/config", body).Code, http.StatusBadRequest)
	}
	eq(t, len(act.saved), saved)
}

func TestClientsListProfiles(t *testing.T) {
	act := &fakeActions{detected: []string{"example"}, profiles: []ui.Profile{
		{Name: "example", Description: "Пример клиента", Layer: policy.Layer{
			Interfaces:     []string{"wg-example"},
			RepairPrograms: []string{`C:\Program Files\Example\*.exe`},
			Trust:          []policy.Trust{{Kind: policy.KindProgram, Value: `C:\Program Files\Example\tunnel.exe`}},
		}},
		{Name: "other", Description: "Другой клиент"},
	}}
	sameJSON(t, opened(t, act).get("/api/clients"), http.StatusOK, `{"profiles": [
		{"name": "example", "description": "Пример клиента", "detected": true, "interfaces": ["wg-example"],
		 "trust": [{"kind": "program", "value": "C:\\Program Files\\Example\\tunnel.exe", "destinations": ""}],
		 "repair_programs": ["C:\\Program Files\\Example\\*.exe"]},
		{"name": "other", "description": "Другой клиент", "detected": false, "interfaces": [], "trust": [], "repair_programs": []}]}`)
	sameJSON(t, opened(t, &fakeActions{}).get("/api/clients"), http.StatusOK, `{"profiles": []}`)
}

func TestProgramsGroupByName(t *testing.T) {
	act := &fakeActions{running: []backend.Program{
		{Name: "node", Path: `C:\Program Files\nodejs\node.exe`},
		{Name: "Node", Path: `D:\tools\node.exe`},
		{Name: "editor", Path: `C:\Program Files\Editor\editor.exe`},
		{Name: "bad.exe", Path: `C:\bad.exe`}, // непригодное для repair.names имя в список не идёт
	}}
	sameJSON(t, opened(t, act).get("/api/programs"), http.StatusOK, `{"programs": [
		{"name": "node", "paths": ["C:\\Program Files\\nodejs\\node.exe", "D:\\tools\\node.exe"]},
		{"name": "editor", "paths": ["C:\\Program Files\\Editor\\editor.exe"]}]}`)
	sameJSON(t, opened(t, &fakeActions{}).get("/api/programs"), http.StatusOK, `{"programs": []}`)
}

func TestAliveAnswersEmptyObject(t *testing.T) {
	p := opened(t, &fakeActions{})
	sameJSON(t, p.post("/api/alive", `{}`), http.StatusOK, `{}`)
	sameJSON(t, p.post("/api/alive", ``), http.StatusOK, `{}`)
	eq(t, p.post("/api/alive", `{"closing":"да"}`).Code, http.StatusBadRequest)
}
