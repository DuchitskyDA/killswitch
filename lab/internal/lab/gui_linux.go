//go:build linux

package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/nsguard"
	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
)

// Сроки этапа «окно».
const (
	guiOpenWait  = 15 * time.Second        // window обязан вызвать команду открытия
	guiNoDisplay = 15 * time.Second        // window без дисплея обязан выйти сам
	guiExitMin   = 2500 * time.Millisecond // после сигнала закрытия сервер ждёт 3 с: вдруг страница перезагрузилась
	guiExitMax   = 8 * time.Second
	guiBeat      = 20 * time.Second // сигнал жизни страницы
)

// sudoEnv — переменные, по которым window запустил бы браузер от имени другого пользователя.
var sudoEnv = []string{"SUDO_UID", "SUDO_GID", "SUDO_USER"}

// gui — этап «окно»: настоящий killswitch window в ksl-client, стенд играет браузер по HTTP на loopback этого ns.
// Настоящий браузер не запускается: вместо xdg-open в PATH стоит заглушка стенда, она пишет адрес окна в файл.
func (a *acc) gui() (err error) {
	if err := a.writeConfig(ConfigOpts{CgroupPath: a.cgRel}); err != nil {
		return err
	}
	if _, code := a.ks("on"); code != 0 {
		return fmt.Errorf("on перед окном: код %d", code)
	}
	// Следующие этапы не зависят от исхода этого: файл настроек стенда записан заново (окно сохраняет его в своей
	// записи), защита возвращена той же командой, что в остальных сценариях.
	defer func() {
		werr := a.writeConfig(ConfigOpts{CgroupPath: a.cgRel})
		if _, code := a.ks("on"); code != 0 && err == nil {
			err = fmt.Errorf("on после окна: код %d", code)
		}
		if err == nil {
			err = werr
		}
	}()
	stub := filepath.Join(a.stub, "xdg-open")
	out, lookErr := a.inMnt("", "sh", "-c", `p=$(command -v xdg-open) && [ -x "$p" ] && echo "$p"`)
	if !a.expect(ScenarioWindow, "-", "xdg-open в PATH запуска — заглушка стенда", lookErr == nil && strings.TrimSpace(out) == stub,
		fmt.Sprintf("нашёлся %q, заглушка %q", strings.TrimSpace(out), stub)) {
		return errors.New("window не запускаю: xdg-open в PATH не заглушка стенда")
	}
	openLog := filepath.Join(a.run, "window-open.log")
	defer os.Remove(openLog)
	a.guiNoDisplay(openLog)
	return a.guiWindow(openLog)
}

// guiListeners — слушающие TCP-сокеты ns клиента.
func (a *acc) guiListeners() string {
	out, _ := a.ns[topo.ClientNS].Run(a.ctx, "ss", "-Hltn")
	return out
}

func listenAddrs(ss string) []string {
	var out []string
	for _, line := range strings.Split(ss, "\n") {
		if f := strings.Fields(line); len(f) >= 4 {
			out = append(out, f[3])
		}
	}
	slices.Sort(out)
	return out
}

// guiNoDisplay — window без графического сеанса: код 2, строка про меню в терминале, сервер не стартует.
func (a *acc) guiNoDisplay(openLog string) {
	const name = "window без дисплея: код 2, меню в терминале, сервер не стартует"
	before := listenAddrs(a.guiListeners())
	cmd, err := a.mntCmd(nil, a.ksBin, "window")
	if err != nil {
		a.add(ScenarioWindow, "-", name, Fail, err.Error())
		return
	}
	cmd.Env = EnvWith(cmd.Env, append([]string{"DISPLAY", "WAYLAND_DISPLAY"}, sudoEnv...), "KSL_OPEN_LOG="+openLog)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		a.add(ScenarioWindow, "-", name, Fail, err.Error())
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	timedOut := false
	select {
	case waitErr = <-done:
	case <-time.After(guiNoDisplay):
		timedOut = true
		cmd.Process.Kill()
		waitErr = <-done
	}
	text := maskKey(buf.String())
	a.printf("  $ killswitch window (без DISPLAY и WAYLAND_DISPLAY) → код %d\n%s", exitCodeOf(waitErr), indent(trimLines(text, 20)))
	if strings.Contains(text, "kslab: nsguard") {
		a.checkGuard(fmt.Errorf("%w: %s", nsguard.ErrInner, strings.TrimSpace(text)))
	}
	after := listenAddrs(a.guiListeners())
	_, statErr := os.Stat(openLog)
	os.Remove(openLog) // чужая строка не должна достаться следующему запуску
	ok := !timedOut && exitCodeOf(waitErr) == 2 && strings.Contains(text, "окно не открыть: нет графического сеанса") &&
		strings.Contains(text, "меню в терминале — sudo killswitch") && slices.Equal(before, after) && os.IsNotExist(statErr)
	a.expect(ScenarioWindow, "-", name, ok, fmt.Sprintf("код %d, убит по сроку: %t, слушающие сокеты прежние: %t, заглушка xdg-open вызвана: %t",
		exitCodeOf(waitErr), timedOut, slices.Equal(before, after), statErr == nil))
}

// exitCodeOf — код выхода команды: 0, код из ExitError (-1 — убита сигналом) или -2 — не запускалась.
func exitCodeOf(err error) int {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	}
	return -2
}

// guiWindow запускает window, играет браузер и ждёт, что после сигнала закрытия процесс выйдет сам.
func (a *acc) guiWindow(openLog string) error {
	cmd, err := a.mntCmd(nil, a.ksBin, "window")
	if err != nil {
		return err
	}
	cmd.Env = EnvWith(cmd.Env, append([]string{"WAYLAND_DISPLAY"}, sudoEnv...), "DISPLAY=:ksl", "KSL_OPEN_LOG="+openLog)
	logPath := filepath.Join(a.run, "window.log")
	logf, err := os.Create(logPath)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return err
	}
	p := &proc{name: "window", cmd: cmd, done: make(chan struct{})}
	a.procs = append(a.procs, p)
	var waitErr error
	go func() { waitErr = cmd.Wait(); logf.Close(); close(p.done) }()
	// Журнал окна уходит в отчёт прогона без ключа — и когда window сам напечатал адрес (команда открытия не сработала).
	windowLog := func() string {
		b, _ := os.ReadFile(logPath)
		return maskKey(string(b))
	}
	defer func() {
		a.stop(p)
		text := windowLog()
		_ = os.WriteFile(logPath, []byte(text), 0o600)
		a.printf("  window.log:\n%s", indent(trimLines(text, 20)))
		if strings.Contains(text, "kslab: nsguard") {
			a.checkGuard(fmt.Errorf("%w: %s", nsguard.ErrInner, strings.TrimSpace(text)))
		}
	}()

	var line string
	exited := false
	waitErrOpen := a.waitFor("window вызвал команду открытия", guiOpenWait, func() bool {
		b, _ := os.ReadFile(openLog)
		line = string(b)
		if strings.HasSuffix(line, "\n") {
			return true
		}
		select {
		case <-p.done:
			exited = true // процесс вышел: ждать нечего
		default:
		}
		return exited
	})
	os.Remove(openLog) // адрес с ключом на диске больше не нужен
	addr, parseErr := ParseWindowURL(line)
	started := waitErrOpen == nil && !exited && parseErr == nil
	detail := addr.Base
	switch {
	case waitErrOpen != nil:
		detail = waitErrOpen.Error()
	case exited:
		detail = fmt.Sprintf("window вышел до команды открытия, код %d", exitCodeOf(waitErr))
	case parseErr != nil:
		detail = parseErr.Error()
	}
	if !a.expect(ScenarioWindow, "-", "window запущен: команда открытия получила адрес окна", started, detail) {
		return nil
	}
	listen := portListeners(a.guiListeners(), addr.Port)
	a.expect(ScenarioWindow, "-", "окно слушает только 127.0.0.1", slices.Equal(listen, []string{"127.0.0.1:" + addr.Port}),
		fmt.Sprintf("слушают порт: %v", listen))

	// Браузер — обычная программа: запросы идут от её uid. Loopback недоступен такой программе — отдельный FAIL,
	// остальной сценарий тогда идёт от root.
	uid := a.direct().uid
	do := a.guiHTTP(uid)
	state := HTTPSpec{Method: http.MethodGet, URL: addr.Base + "/api/state"}
	r := do(state)
	a.expect(ScenarioWindow, "-", fmt.Sprintf("окно отвечает программе с uid %d по loopback: без сеанса 401", uid),
		r.Err == "" && r.Status == http.StatusUnauthorized, brief(r))
	if r.Err != "" {
		a.printf("  запросы сценария дальше идут от root\n")
		do = a.guiHTTP(0)
	}

	h := guiHost{do: do, tunnel: a.iface, profile: a.c.Profile, redirect: a.c.Redirect, cliCode: a.chkCode, beat: guiBeat,
		report: func(name string, ok bool, detail string) { a.expect(ScenarioWindow, "-", name, ok, detail) },
		rules:  func() string { return a.clientNFT("list", "table", "inet", "killswitch") },
		config: func() (string, error) { return a.inMnt("", "cat", stateDir+"/config.toml") },
		modeSet: func(mode string) {
			for _, p := range shortProbes[:2] {
				if mode == "off" {
					a.open(ScenarioWindow, p, a.direct(), "после off через окно прямая")
				} else {
					a.blocked(ScenarioWindow, p, a.direct(), "после on через окно прямая")
				}
			}
		},
	}
	if !guiSession(h, addr) {
		return nil
	}
	// Сигнал закрытия был последним запросом: до выхода процесса запросов нет — любой отменил бы закрытие.
	sent := time.Now()
	select {
	case <-p.done:
	case <-time.After(guiExitMax):
		a.add(ScenarioWindow, "-", "после сигнала закрытия window вышел сам", Fail, fmt.Sprintf("не вышел за %s", guiExitMax))
		return nil
	}
	took := time.Since(sent)
	a.expect(ScenarioWindow, "-", fmt.Sprintf("после сигнала закрытия window вышел сам: код 0, не раньше %s", guiExitMin),
		exitCodeOf(waitErr) == 0 && took >= guiExitMin, fmt.Sprintf("код %d через %s", exitCodeOf(waitErr), took.Round(100*time.Millisecond)))
	left := portListeners(a.guiListeners(), addr.Port)
	r = do(state)
	a.expect(ScenarioWindow, "-", "после выхода порт окна закрыт", len(left) == 0 && r.Err != "",
		fmt.Sprintf("слушают порт: %v; запрос: %s", left, briefStatus(r)))
	text, _ := os.ReadFile(logPath)
	a.expect(ScenarioWindow, "-", "вывод window: «окно killswitch открыто», ключа нет",
		strings.Contains(string(text), "окно killswitch открыто") && !strings.Contains(string(text), addr.Key),
		fmt.Sprintf("строк %d", strings.Count(string(text), "\n")))
	return nil
}

// guiHTTP — запрос «браузера»: подкоманда kslab http внутри ksl-client (сверка inode ns до работы) от uid.
// Запрос уходит через stdin: cookie сеанса не попадает в аргументы процесса.
func (a *acc) guiHTTP(uid int) func(HTTPSpec) HTTPResult {
	var mu sync.Mutex // сигнал жизни и проверка идут одновременно
	guard := func(f func()) {
		mu.Lock()
		defer mu.Unlock()
		f()
	}
	return func(s HTTPSpec) HTTPResult {
		cl := a.ns[topo.ClientNS]
		cmd, err := cl.Cmd(a.ctx, nil, a.self, "http", "--uid", strconv.Itoa(uid), "--expect-ino", strconv.FormatUint(cl.Ino, 10))
		if err != nil {
			guard(func() { a.checkGuard(err) })
			return HTTPResult{Err: err.Error()}
		}
		spec, err := json.Marshal(s)
		if err != nil {
			return HTTPResult{Err: err.Error()}
		}
		cmd.Stdin = bytes.NewReader(spec)
		out, err := cmd.Output()
		var r HTTPResult
		if jerr := json.Unmarshal(bytes.TrimSpace(out), &r); jerr != nil {
			guard(func() { err = a.checkInner(err) })
			return HTTPResult{Err: fmt.Sprintf("запрос не выполнился: %v", err)}
		}
		return r
	}
}
