// Command wfpspike — спайк WFP для backend Windows универсального killswitch.
// Запускается только на одноразовом раннере GitHub Actions (см. requireRunner).
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: wfpspike probe|inventory|t1|t2|t3|t4|t5-tx|t5-setup|state|remove|cleanup|marker|render")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	// wf@6fbb0a67: bump-аллокатор arena не выравнивает адреса, и запись
	// fwpmFilter0 с указателями при работающем GC падает (fatal error:
	// bulkBarrierPreWrite: unaligned arguments, run 42619450025). Процессы
	// короткие — GC выключен; боевому backend нужен форк с выравниванием.
	debug.SetGCPercent(-1)
	switch cmd {
	case "probe":
		os.Exit(runProbe(args))
	case "render":
		fmt.Println(Render(Plan{Tag: "demo", Block: true, Loopback: true, DHCP: true,
			Apps:   []AppPermit{{Name: "client", AppID: `\device\harddiskvolume1\client.exe`}},
			Ifaces: []IfacePermit{{Name: "tun", LUID: 0x6000000000000}}}.Rules()))
		return
	// Только чтение и снятие своего: безопасно где угодно, нужно задаче планировщика.
	case "state":
		os.Exit(cmdState())
	case "remove":
		os.Exit(cmdRemove())
	case "cleanup":
		os.Exit(cmdCleanup())
	}
	requireRunner()
	c := newCtx()
	limit := map[string]time.Duration{"t3": 6 * time.Minute, "marker": 10 * time.Minute}[cmd]
	if limit == 0 {
		limit = 4 * time.Minute
	}
	// Внутренний watchdog: выход процесса снимает dynamic-сессию.
	time.AfterFunc(limit, func() {
		fmt.Println("WATCHDOG: лимит процесса, выход")
		os.Exit(3)
	})
	switch cmd {
	case "inventory":
		cmdInventory()
	case "t1":
		t1(c)
	case "t2":
		t2(c)
	case "t3":
		t3(c)
	case "t4":
		t4(c)
	case "t5-tx":
		t5tx(c)
	case "t5-setup":
		t5setup(c)
	case "marker":
		cmdMarker()
	default:
		fmt.Println("неизвестная команда", cmd)
		os.Exit(2)
	}
}

// requireRunner — команды, которые ставят фильтры, работают только на
// одноразовом раннере GitHub; на любой другой машине — выход 2.
func requireRunner() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		fmt.Println("отказ: команда ставит фильтры WFP и запускается только на раннере GitHub (github-hosted)")
		os.Exit(2)
	}
}

type ctx struct {
	dir        string
	allowed    string
	denied     string
	runnerApps []string
}

func newCtx() *ctx {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	dir := filepath.Dir(exe)
	c := &ctx{
		dir:     dir,
		allowed: filepath.Join(dir, "probe-allowed", "wfpspike.exe"),
		denied:  filepath.Join(dir, "probe-denied", "wfpspike.exe"),
	}
	if b, err := os.ReadFile(filepath.Join(dir, "runner-apps.txt")); err == nil {
		seen := map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !seen[strings.ToLower(l)] {
				seen[strings.ToLower(l)] = true
				c.runnerApps = append(c.runnerApps, l)
			}
		}
	}
	return c
}

// appPermits — процессы раннера + дополнительные пути, с app-id.
func (c *ctx) appPermits(extra ...string) []AppPermit {
	var out []AppPermit
	for i, p := range append(append([]string{}, c.runnerApps...), extra...) {
		id, err := wf.AppID(p)
		if err != nil {
			fmt.Printf("app-id %s: %v (пропущен)\n", p, err)
			continue
		}
		out = append(out, AppPermit{Name: fmt.Sprintf("%02d-%s", i, filepath.Base(p)), AppID: id})
	}
	return out
}

// ---- результаты ----

func result(id, status, format string, a ...any) {
	detail := strings.ReplaceAll(fmt.Sprintf(format, a...), "\n", " ")
	line := fmt.Sprintf("RESULT %s %s %s", id, status, detail)
	fmt.Println(line)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		appendFile(p, fmt.Sprintf("| %s | %s | %s |\n", id, status, strings.ReplaceAll(detail, "|", "/")))
	}
	if p := os.Getenv("KS_RESULTS"); p != "" {
		appendFile(p, line+"\n")
	}
}

func appendFile(p, s string) {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(s)
}

func info(format string, a ...any) {
	fmt.Printf("%s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, a...))
}

// pr — итог пробы.
type pr struct {
	ok  bool
	out string
}

func (p pr) String() string {
	s := "ok"
	if !p.ok {
		s = "fail"
	}
	return s + ": " + strings.TrimSpace(p.out)
}

func (c *ctx) probe(exe string, args ...string) pr {
	cx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cx, exe, append([]string{"probe"}, args...)...).CombinedOutput()
	return pr{ok: err == nil, out: string(out)}
}

// pair — listener слушает addr, connector подключается и ждёт "pong".
func (c *ctx) pair(listener, connector, addr string) pr {
	cx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := exec.CommandContext(cx, listener, "probe", "listen", addr)
	stdout, _ := l.StdoutPipe()
	if err := l.Start(); err != nil {
		return pr{out: "listener start: " + err.Error()}
	}
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		var all []string
		for sc.Scan() {
			all = append(all, sc.Text())
			if sc.Text() == "LISTENING" {
				ready <- "LISTENING"
			}
		}
		ready <- strings.Join(all, "; ")
	}()
	select {
	case s := <-ready:
		if s != "LISTENING" {
			_ = l.Wait()
			return pr{out: "listener: " + s}
		}
	case <-time.After(5 * time.Second):
		_ = l.Process.Kill()
		return pr{out: "listener не готов"}
	}
	res := c.probe(connector, "connect", addr)
	_ = l.Process.Kill()
	_ = l.Wait()
	return res
}

// expect — PASS, если проба дала ожидаемое; INCONCLUSIVE, если baseline не прошёл.
func expect(id string, wantOK bool, baseline, got pr) {
	switch {
	case !baseline.ok:
		result(id, "INCONCLUSIVE", "baseline без правил не прошёл (%s); под правилами %s", baseline, got)
	case got.ok == wantOK:
		result(id, "PASS", "%s", got)
	default:
		result(id, "FAIL", "ожидали ok=%t, получили %s", wantOK, got)
	}
}

func runPS(script string) (string, error) {
	cx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ---- сессия и набор ----

func openSession(dynamic bool, name string) (*wf.Session, error) {
	return wf.New(&wf.Options{Name: name, Description: "killswitch spike", Dynamic: dynamic, TransactionStartTimeout: 5 * time.Second})
}

func addBase(s *wf.Session, persistent bool) error {
	if err := s.AddProvider(&wf.Provider{ID: providerID, Name: providerName, Description: "killswitch spike", Persistent: persistent}); err != nil {
		return fmt.Errorf("AddProvider: %w", err)
	}
	if err := s.AddSublayer(&wf.Sublayer{ID: sublayerID, Name: sublayerName, Provider: providerID, Weight: 0xFFFF, Persistent: persistent}); err != nil {
		return fmt.Errorf("AddSublayer: %w", err)
	}
	return nil
}

// apply добавляет правила в одной транзакции WFP.
func apply(s *wf.Session, rules []*wf.Rule) error {
	if err := txBegin(s); err != nil {
		return fmt.Errorf("txBegin: %w", err)
	}
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			_ = txAbort(s)
			return fmt.Errorf("AddRule %s: %w", r.Name, err)
		}
	}
	return txCommit(s)
}

func deleteRules(s *wf.Session, rules []*wf.Rule) {
	for _, r := range rules {
		if err := s.DeleteRule(r.ID); err != nil {
			info("DeleteRule %s: %v", r.Name, err)
		}
	}
}

func mustSession(dynamic bool, name string) *wf.Session {
	s, err := openSession(dynamic, name)
	if err != nil {
		result("session", "FAIL", "wf.New(dynamic=%t): %v", dynamic, err)
		os.Exit(1)
	}
	return s
}

// removeOurs снимает всё наше: фильтры provider (включая boot-time) на всех
// слоях, фильтры boot-time-вариантов без provider по детерминированным ключам,
// sublayer и provider. Конфиг не нужен.
func removeOurs(s *wf.Session) (int, error) {
	var errs []error
	n := 0
	fs, err := ourFilters(s)
	if err != nil {
		errs = append(errs, err)
	}
	for _, f := range fs {
		if err := deleteFilter(s, f.Key); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", f.Name, err))
		} else {
			n++
		}
	}
	// Фильтры без provider (запасные boot-time-варианты) — по префиксу имени.
	orphans, err := orphanFilters(s)
	if err != nil {
		errs = append(errs, err)
	}
	for _, f := range orphans {
		if err := deleteFilter(s, f.Key); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", f.Name, err))
		} else {
			n++
			info("снят по имени (без provider): %s", f.Name)
		}
	}
	if err := s.DeleteSublayer(sublayerID); err != nil && !isNotFound(err) {
		errs = append(errs, fmt.Errorf("DeleteSublayer: %w", err))
	}
	if err := s.DeleteProvider(providerID); err != nil && !isNotFound(err) {
		errs = append(errs, fmt.Errorf("DeleteProvider: %w", err))
	}
	return n, errors.Join(errs...)
}

func isNotFound(err error) bool {
	s := err.Error()
	return strings.Contains(s, "0x80320008") || strings.Contains(s, "0x80320007") ||
		strings.Contains(s, "0x80320003") || strings.Contains(strings.ToLower(s), "not exist") ||
		strings.Contains(strings.ToLower(s), "does not exist")
}

func cmdRemove() int {
	s, err := openSession(false, "ks-spike-remove")
	if err != nil {
		fmt.Println("RESULT remove FAIL", err)
		return 1
	}
	defer s.Close()
	n, err := removeOurs(s)
	left, _ := ourFilters(s)
	orph, _ := orphanFilters(s)
	left = append(left, orph...)
	status := "PASS"
	if err != nil || len(left) > 0 {
		status = "FAIL"
	}
	result("remove", status, "снято %d фильтров, осталось %d, ошибки: %v", n, len(left), err)
	if status != "PASS" {
		return 1
	}
	return 0
}

func cmdCleanup() int {
	rc := cmdRemove()
	out, err := runPS(`Get-NetFirewallRule -Group ks-spike -ErrorAction SilentlyContinue | Remove-NetFirewallRule;` +
		`$f='C:\ks\wdf-profiles.csv'; if (Test-Path $f) { Import-Csv $f | % { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction $_.DefaultOutboundAction -Enabled $_.Enabled } };` +
		`Get-NetFirewallProfile | ft Name,Enabled,DefaultOutboundAction | Out-String`)
	fmt.Println("WDF:", out, err)
	return rc
}

// cmdState — что видно из нового процесса: наши фильтры (с boot-time),
// provider, sublayer, маркер dynamic-сессии.
func cmdState() int {
	s, err := openSession(false, "ks-spike-state")
	if err != nil {
		fmt.Println("STATE session fail:", err)
		return 1
	}
	defer s.Close()
	fs, err := ourFilters(s)
	if err != nil {
		fmt.Println("STATE enum errors:", err)
	}
	persist, boot, other := 0, 0, 0
	for _, f := range fs {
		switch {
		case f.Flags&filterFlagBootTime != 0:
			boot++
		case f.Flags&filterFlagPersistent != 0:
			persist++
		default:
			other++
		}
	}
	orphans, _ := orphanFilters(s)
	byKey := len(orphans)
	provs, _ := s.Providers()
	hasProv := false
	for _, p := range provs {
		if p.ID == providerID {
			hasProv = true
		}
	}
	subs, _ := s.Sublayers()
	hasSub := false
	for _, sl := range subs {
		if sl.ID == sublayerID {
			hasSub = true
		}
	}
	marker, _ := markerExists(s)
	fmt.Printf("STATE filters=%d persistent=%d boottime=%d other=%d noprovider-by-key=%d provider=%t sublayer=%t marker=%t\n",
		len(fs), persist, boot, other, byKey, hasProv, hasSub, marker)
	var bootKeys []string
	for _, f := range fs {
		fmt.Printf("  %s flags=0x%x weight=%s eff=%s action=0x%x\n", f.Name, f.Flags, f.Weight, f.EffectiveWeight, f.Action)
		if f.Flags&filterFlagBootTime != 0 {
			bootKeys = append(bootKeys, strings.ToLower(strings.Trim(windows.GUID(f.Key).String(), "{}")))
		}
	}
	// Ключи boot-time — для сверки с netsh wfp show boottimepolicy (там нет имён).
	if p := os.Getenv("KS_BOOTKEYS"); p != "" && len(bootKeys) > 0 {
		_ = os.WriteFile(p, []byte(strings.Join(bootKeys, "\n")+"\n"), 0o644)
	}
	return 0
}

func filterExists(s *wf.Session, layer wf.LayerID, key windows.GUID) (bool, error) {
	fs, err := enumFilters(s, layer, nil, enumFlagIncludeBootTime|enumFlagIncludeDisabled)
	for _, f := range fs {
		if f.Key == key {
			return true, err
		}
	}
	return false, err
}

// ---- инвентарь ----

func cmdInventory() {
	s := mustSession(false, "ks-spike-inventory")
	defer s.Close()
	provs, err := s.Providers()
	if err != nil {
		info("Providers: %v", err)
	}
	pname := map[wf.ProviderID]string{}
	for _, p := range provs {
		pname[p.ID] = p.Name
		fmt.Printf("PROVIDER %s %q persistent=%t service=%q\n", p.ID, p.Name, p.Persistent, p.ServiceName)
	}
	subs, err := s.Sublayers()
	if err != nil {
		info("Sublayers: %v", err)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Weight > subs[j].Weight })
	for _, sl := range subs {
		fmt.Printf("SUBLAYER weight=0x%04X %s %q provider=%q persistent=%t\n", sl.Weight, sl.ID, sl.Name, pname[sl.Provider], sl.Persistent)
	}
	printLayerFilters(s, nil)
}

// printLayerFilters — сводка фильтров на наших четырёх слоях по sublayer.
func printLayerFilters(s *wf.Session, provider *windows.GUID) {
	subs, _ := s.Sublayers()
	sname := map[windows.GUID]string{}
	for _, sl := range subs {
		sname[windows.GUID(sl.ID)] = fmt.Sprintf("%q(0x%04X)", sl.Name, sl.Weight)
	}
	for _, l := range aleLayers {
		fs, err := enumFilters(s, l, provider, enumFlagIncludeBootTime|enumFlagIncludeDisabled)
		if err != nil {
			info("enum %s: %v", layerNames[l], err)
		}
		count := map[string]int{}
		for _, f := range fs {
			act := "permit"
			if f.Action == uint32(wf.ActionBlock) {
				act = "block"
			} else if f.Action != uint32(wf.ActionPermit) {
				act = fmt.Sprintf("0x%x", f.Action)
			}
			count[fmt.Sprintf("%s %s flags=0x%x", sname[f.Sublayer], act, f.Flags)]++
		}
		keys := make([]string, 0, len(count))
		for k := range count {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("LAYER %s %s x%d\n", layerNames[l], k, count[k])
		}
	}
}

// ---- маркер dynamic-сессии (для проверки после перезапуска BFE) ----

const markerName = "ks-spike-marker"

var markerKey = guidV5(ruleNamespace, markerName)

func cmdMarker() {
	s := mustSession(true, "ks-spike-marker")
	err := s.AddRule(&wf.Rule{
		ID: wf.RuleID(markerKey), Name: markerName, Layer: wf.LayerALEAuthConnectV4, Weight: 1, Action: wf.ActionPermit,
		Conditions: []*wf.Match{{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(9)}},
	})
	fmt.Println("MARKER add:", err)
	time.Sleep(9 * time.Minute)
}

func markerExists(s *wf.Session) (bool, error) {
	return filterExists(s, wf.LayerALEAuthConnectV4, markerKey)
}
