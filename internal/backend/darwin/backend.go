package darwin

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/state"
)

// Имена установки.
const (
	Label     = "io.github.duchitskyda.killswitch" // LaunchDaemon
	tokenName = "killswitchd"                      // копия pfctl: под этим именем наш токен виден в References
	pfctlPath = "/sbin/pfctl"
	pfConf    = "/etc/pf.conf"
)

// Paths — где лежит установка. Для тестов подменяется.
type Paths struct {
	Dir      string // каталог администратора: копии бинарника и pfctl, файлы якоря
	Plist    string // LaunchDaemon
	PfctlSrc string // откуда копировать pfctl
	Log      string // вывод наблюдателя
}

// SystemPaths — пути на macOS.
func SystemPaths() Paths {
	return Paths{
		Dir:      state.DefaultDir("darwin"),
		Plist:    "/Library/LaunchDaemons/" + Label + ".plist",
		PfctlSrc: pfctlPath,
		Log:      "/var/log/killswitch.log",
	}
}

func (p Paths) file(name string) string { return filepath.Join(p.Dir, name) }
func (p Paths) rulesFile() string       { return p.file("killswitch.pf") }
func (p Paths) loadedFile() string      { return p.file("killswitch.pf.loaded") }
func (p Paths) tokenTool() string       { return p.file(tokenName) }
func (p Paths) binary() string          { return p.file("killswitch") }

// Result — вывод команды: stdout и stderr раздельно (pfctl пишет предупреждения в stderr).
type Result struct{ Out, Err string }

// Runner выполняет внешние команды. В тестах — фейк с готовым выводом.
type Runner interface {
	Run(stdin, name string, args ...string) (Result, error)
}

type execRunner struct{}

func (execRunner) Run(stdin, name string, args ...string) (Result, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := Result{Out: out.String(), Err: errb.String()}
	if err != nil {
		return res, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(res.Err))
	}
	return res, nil
}

// Backend — pf-backend macOS.
type Backend struct {
	run    Runner
	paths  Paths
	exe    func() (string, error)
	canary func() error
	wait   func(time.Duration)

	mu     sync.Mutex
	before map[string]uint64 // счётчики правил проб до пробы

	watchOnce sync.Once
	changes   chan struct{}
}

var (
	_ backend.Backend = (*Backend)(nil)
	_ backend.Watcher = (*Backend)(nil)
	_ probe.Preparer  = (*Backend)(nil)
)

// New — backend с системными командами и путями.
func New() *Backend {
	return newBackend(execRunner{}, SystemPaths())
}

func newBackend(r Runner, p Paths) *Backend {
	return &Backend{run: r, paths: p, exe: os.Executable, canary: sendCanary, wait: time.Sleep, before: map[string]uint64{}}
}

// Capabilities — macOS: Trust{user} и endpoints, repair нет.
func (b *Backend) Capabilities() policy.Capabilities { return policy.CapabilitiesFor("darwin") }

// Plan — см. Plan пакета.
func (b *Backend) Plan(p policy.Policy, e env.Env) (backend.Ruleset, error) { return Plan(p, e) }

// BindControl — IP_BOUND_IF / IPV6_BOUND_IF по индексу интерфейса.
func (b *Backend) BindControl(iface env.Iface) backend.ControlFunc { return bindControl(iface.Index) }

func (b *Backend) pf(stdin string, args ...string) (string, error) {
	res, err := b.run.Run(stdin, pfctlPath, args...)
	return res.Out, err
}

// Apply: установка → anchor-точка → загрузка якоря (атомарно для якоря) → свой токен → сброс состояний.
// Ошибка до загрузки оставляет прежний набор; pfctl -d не вызывается никогда.
func (b *Backend) Apply(r backend.Ruleset) error {
	rules, ok := r.(Rules)
	if !ok {
		return fmt.Errorf("план не pf: %T", r)
	}
	if err := b.install(); err != nil {
		return fmt.Errorf("установка: %w", err)
	}
	if rules.Mode == policy.ModeOn {
		if err := b.ensureAnchorPoint(); err != nil {
			return err
		}
	}
	var prior priorSet
	if rules.Mode != policy.ModeOn {
		prior = b.priorSet() // фактический прежний набор — на случай отката хвоста
	}
	// Запись снимается до загрузки: любой сбой дальше (загрузка, токен, сброс) — дрейф, и enforce повторит Apply,
	// даже если план тот же, что записан.
	if err := removeIfExists(b.paths.loadedFile()); err != nil {
		return err
	}
	if err := b.load(rules.Text); err != nil {
		return err // pfctl грузит якорь атомарно: при отказе остаётся прежний набор
	}
	if err := b.finish(rules); err != nil {
		return b.failClosed(prior, err)
	}
	return nil
}

// finish — хвост Apply после загрузки: чтение обратно, свой токен и сброс состояний (on), запись.
func (b *Backend) finish(rules Rules) error {
	loaded, err := b.pf("", "-a", Anchor, "-sr")
	if err != nil {
		return fmt.Errorf("чтение якоря после загрузки: %w", err)
	}
	if rules.Mode == policy.ModeOn {
		if err := b.ensureToken(); err != nil {
			return err
		}
		// Сбрасываются все состояния pf: состояния чужих keep-state правил обходят наш якорь.
		// Наши pass без состояния, поэтому разрешённые потоки сброс не рвёт.
		if _, err := b.pf("", "-F", "states"); err != nil {
			return fmt.Errorf("сброс состояний pf: %w", err)
		}
	}
	return b.record(loaded)
}

// priorSet — чем защищал якорь до Apply набора слабее on: запись последнего завершённого on и фактические правила
// (Apply on мог упасть до записи — тогда запись говорит off, а в якоре on). Якорь не читается — считаем, что защищал.
type priorSet struct {
	protective bool
	texts      []string // кандидаты отката по порядку; последний — блок всего
}

func (b *Backend) priorSet() priorSet {
	var p priorSet
	if rec, ok := b.readRecord(); ok && rec.mode == policy.ModeOn {
		p.protective = true
		p.texts = append(p.texts, rec.text)
	}
	before, err := b.pf("", "-a", Anchor, "-sr")
	rules := ruleLines(before)
	if err != nil || len(rules) > 0 {
		p.protective = true
	}
	if err == nil && len(rules) > 0 {
		p.texts = append(p.texts, strings.Join(rules, "\n")+"\n")
	}
	p.texts = append(p.texts, blockAllText)
	return p
}

// failClosed — хвост Apply упал после загрузки набора слабее on, а прежний набор защищал: вернуть его (последним
// средством — блок всего), снова взять свой токен и отозвать состояния, открытые в окне, — ошибка не оставляет
// машину открытой (контракт Apply). Набор on загружен сам и защищает; прежний пустой якорь — прежний набор и так пуст.
// Откат грузится со stdin: хвост мог упасть как раз на записи файла. Запись остаётся снятой — enforce повторит Apply.
func (b *Backend) failClosed(prior priorSet, cause error) error {
	if !prior.protective {
		return cause
	}
	for _, text := range prior.texts {
		if _, err := b.pf(text, "-a", Anchor, "-f", "-"); err != nil {
			continue
		}
		// Оба шага независимы: сбой токена не отменяет отзыв состояний.
		var tail []error
		if err := b.ensureToken(); err != nil {
			tail = append(tail, fmt.Errorf("pf не включён своим токеном: %w", err))
		}
		if _, err := b.pf("", "-F", "states"); err != nil {
			tail = append(tail, fmt.Errorf("состояния pf не сброшены: %w", err))
		}
		if len(tail) > 0 {
			return fmt.Errorf("%w; прежняя защита возвращена, но: %w", cause, errors.Join(tail...))
		}
		return fmt.Errorf("%w (прежняя защита возвращена)", cause)
	}
	return fmt.Errorf("%w; вернуть прежнюю защиту не удалось", cause)
}

// blockAllText — последний рубеж отката: только lo0 и блок всего остального.
const blockAllText = headerMode + "on\npass out quick on lo0 all no state\nblock return out quick all\n"

// ensureAnchorPoint: в основном наборе нет `anchor "com.apple/*"` — вернуть /etc/pf.conf (как старый скрипт).
// Чужое правило выше якоря не трогаем: это только LEAK.
func (b *Backend) ensureAnchorPoint() error {
	main, err := b.pf("", "-sr")
	if err != nil {
		return fmt.Errorf("основной набор pf: %w", err)
	}
	for _, r := range mainFilter(main) {
		if isAnchorPoint(r) {
			return nil
		}
	}
	if _, err := b.pf("", "-f", pfConf); err != nil {
		return fmt.Errorf("возврат %s: %w", pfConf, err)
	}
	return nil
}

// load грузит текст якоря из временного файла (атомарно для якоря).
func (b *Backend) load(text string) error {
	tmp := b.paths.rulesFile() + ".new"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	if _, err := b.pf("", "-a", Anchor, "-f", tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("загрузка якоря: %w", err)
	}
	return nil
}

// record фиксирует пару «план + прочитанное после загрузки»: по ней Status отличает наш набор от дрейфа,
// не завися от формы печати pfctl. Пишется последним шагом Apply: до записи факт считается дрейфом.
func (b *Backend) record(loaded string) error {
	if err := writeAtomic(b.paths.loadedFile(), []byte(loaded), 0o644); err != nil {
		return err
	}
	return os.Rename(b.paths.rulesFile()+".new", b.paths.rulesFile())
}

// ensureToken: ровно один наш токен (по имени процесса killswitchd в References).
func (b *Backend) ensureToken() error {
	ours, _, err := b.references()
	if err != nil {
		return err
	}
	if len(ours) == 0 {
		res, err := b.run.Run("", b.paths.tokenTool(), "-E")
		if err != nil {
			return fmt.Errorf("включение pf своим токеном: %w", err)
		}
		if parseToken(res.Out+"\n"+res.Err) == "" {
			return fmt.Errorf("pfctl -E не вернул токен: %q", res.Out+res.Err)
		}
		return nil
	}
	for _, r := range ours[1:] {
		if _, err := b.pf("", "-X", r.Token); err != nil {
			return fmt.Errorf("лишний токен %s: %w", r.Token, err)
		}
	}
	return nil
}

// references — наши и чужие ссылки на pf.
func (b *Backend) references() (ours, foreign []ref, err error) {
	out, err := b.pf("", "-s", "References")
	if err != nil {
		return nil, nil, fmt.Errorf("pfctl -s References: %w", err)
	}
	for _, r := range parseReferences(out) {
		if r.Name == tokenName {
			ours = append(ours, r)
		} else {
			foreign = append(foreign, r)
		}
	}
	return ours, foreign, nil
}

// install — копии pfctl и бинарника в каталог администратора, LaunchDaemon. Повтор ничего не меняет.
func (b *Backend) install() error {
	if err := os.MkdirAll(b.paths.Dir, 0o755); err != nil {
		return err
	}
	if err := copyIfDiffers(b.paths.PfctlSrc, b.paths.tokenTool(), 0o755); err != nil {
		return err
	}
	exe, err := b.exe()
	if err != nil {
		return err
	}
	if err := copyIfDiffers(exe, b.paths.binary(), 0o755); err != nil {
		return err
	}
	plist := []byte(Plist(b.paths.binary(), b.paths.Log))
	if cur, err := os.ReadFile(b.paths.Plist); err != nil || !bytes.Equal(cur, plist) {
		if err := writeAtomic(b.paths.Plist, plist, 0o644); err != nil {
			return err
		}
	}
	if _, err := b.run.Run("", "/bin/launchctl", "print", "system/"+Label); err == nil {
		return nil // уже загружен; наблюдатель сам вызывает Apply — bootout здесь убил бы его
	}
	if _, err := b.run.Run("", "/bin/launchctl", "bootstrap", "system", b.paths.Plist); err != nil {
		return fmt.Errorf("LaunchDaemon: %w", err)
	}
	return nil
}

// Remove снимает всё наше без конфига и сети: LaunchDaemon, якорь, токены killswitchd, файлы установки.
func (b *Backend) Remove() error {
	_, _ = b.run.Run("", "/bin/launchctl", "bootout", "system/"+Label) // не загружен — не ошибка
	var errs []error
	errs = append(errs, removeIfExists(b.paths.Plist))
	if _, err := b.pf("", "-a", Anchor, "-F", "all"); err != nil {
		errs = append(errs, fmt.Errorf("очистка якоря: %w", err))
	}
	ours, _, err := b.references()
	errs = append(errs, err)
	for _, r := range ours {
		if _, err := b.pf("", "-X", r.Token); err != nil {
			errs = append(errs, fmt.Errorf("токен %s: %w", r.Token, err))
		}
	}
	for _, f := range []string{b.paths.rulesFile(), b.paths.loadedFile(), b.paths.tokenTool(), b.paths.binary()} {
		errs = append(errs, removeIfExists(f))
	}
	return errors.Join(errs...)
}

// record — что мы загрузили последним: план, его чтение сразу после загрузки и режим из заголовка.
type record struct {
	text, loaded string
	hasLoaded    bool // readback записан: без него набор не наш — Apply не завершился
	mode         policy.Mode
}

func (b *Backend) readRecord() (record, bool) {
	text, err := os.ReadFile(b.paths.rulesFile())
	if err != nil {
		return record{}, false
	}
	loaded, err := os.ReadFile(b.paths.loadedFile())
	rec := record{text: string(text), loaded: string(loaded), hasLoaded: err == nil}
	first, _, _ := strings.Cut(rec.text, "\n")
	if m, ok := strings.CutPrefix(first, headerMode); ok {
		rec.mode = policy.Mode(m)
	}
	return rec, true
}

// Status читает факт: хеш — из обратного чтения якоря; находки — только в записанном режиме on.
func (b *Backend) Status() (backend.Status, error) {
	rec, recorded := b.readRecord()
	_, plistErr := os.Stat(b.paths.Plist)
	s := backend.Status{Active: recorded || plistErr == nil, Mode: rec.mode}
	if !s.Active {
		return s, nil
	}
	cur, err := b.pf("", "-a", Anchor, "-sr")
	if err != nil {
		return s, fmt.Errorf("чтение якоря: %w", err)
	}
	now := ruleLines(cur)
	s.Rules = len(now)
	consistent := recorded && rec.hasLoaded && slicesEqual(now, ruleLines(rec.loaded))
	if consistent {
		s.Hash = backend.HashOf(Rules{Text: rec.text})
	} else {
		s.Hash = backend.HashOf(Rules{Text: strings.Join(now, "\n")})
	}
	info, err := b.pf("", "-s", "info")
	if err != nil {
		return s, fmt.Errorf("pfctl -s info: %w", err)
	}
	enabled := pfEnabled(info)
	ours, _, err := b.references()
	if err != nil {
		return s, err
	}
	if len(ours) > 0 {
		s.Token = ours[0].Token
	}
	s.Details = fmt.Sprintf("якорь %s, pf %s, токен %s", Anchor, map[bool]string{true: "Enabled", false: "Disabled"}[enabled], orDash(s.Token))
	if rec.mode != policy.ModeOn {
		return s, nil
	}
	s.Structural, s.AnchorOK, err = b.structural(consistent, enabled, len(ours) > 0)
	return s, err
}

// structural — структурные находки. Repair=true устраняет повторный Apply; без Repair — только LEAK.
func (b *Backend) structural(consistent, enabled, token bool) ([]probe.StructuralFinding, bool, error) {
	var f []probe.StructuralFinding
	add := func(kind, detail string, repair bool) {
		f = append(f, probe.StructuralFinding{Kind: kind, Detail: detail, Repair: repair})
	}
	switch {
	case !enabled:
		add("pf-disabled", "pf выключен: правила якоря не действуют", true)
	case !token:
		add("pf-token-lost", "нашего токена killswitchd нет в pfctl -s References: pf держит чужая ссылка", true)
	}
	if !consistent {
		add("anchor-drift", "правила якоря "+Anchor+" расходятся с загруженными", true)
	}
	main, err := b.pf("", "-sr")
	if err != nil {
		return nil, false, fmt.Errorf("основной набор pf: %w", err)
	}
	rules := mainFilter(main)
	point := false
	for _, r := range rules {
		point = point || isAnchorPoint(r)
	}
	switch {
	case !point:
		add("no-anchor-point", `в основном наборе нет anchor "com.apple/*"`, true)
	case !isAnchorPoint(rules[0]):
		add("rule-above-anchor", "первое правило основного набора не наш якорь: "+rules[0], false)
	}
	siblings, err := b.siblingsBefore()
	if err != nil {
		return nil, false, err
	}
	for _, s := range siblings {
		add("sibling-before", "соседний якорь com.apple/"+s+" раньше нашего и содержит pass quick", false)
	}
	if !enabled || !consistent || !point || !isAnchorPoint(rules[0]) {
		return f, false, nil
	}
	hit, err := b.canaryHit()
	if err != nil {
		return nil, false, err
	}
	if !hit {
		add("anchor-unreachable", "канарейка на lo0 не дошла до якоря "+Anchor, false)
	}
	return f, hit, nil
}

func (b *Backend) siblingsBefore() ([]string, error) {
	out, err := b.pf("", "-a", "com.apple", "-sA")
	if err != nil {
		return nil, fmt.Errorf("соседи com.apple: %w", err)
	}
	own := Anchor[strings.LastIndex(Anchor, "/")+1:]
	var found []string
	for _, name := range anchorChildren(out) {
		if name >= own {
			continue
		}
		rules, err := b.pf("", "-a", "com.apple/"+name, "-sr")
		if err != nil {
			return nil, fmt.Errorf("сосед %s: %w", name, err)
		}
		if hasPassQuick(rules) {
			found = append(found, name)
		}
	}
	return found, nil
}

// canaryHit: пакет на 127.0.0.1:9 должен увеличить счётчик правила-канарейки нашего якоря.
func (b *Backend) canaryHit() (bool, error) {
	before, err := b.labelCount(canaryLabel)
	if err != nil {
		return false, err
	}
	if err := b.canary(); err != nil {
		return false, fmt.Errorf("канарейка: %w", err)
	}
	for i := 0; i < 5; i++ {
		after, err := b.labelCount(canaryLabel)
		if err != nil {
			return false, err
		}
		if after > before {
			return true, nil
		}
		b.wait(100 * time.Millisecond)
	}
	return false, nil
}

func (b *Backend) labelCount(label string) (uint64, error) {
	out, err := b.pf("", "-a", Anchor, "-vsr")
	if err != nil {
		return 0, fmt.Errorf("счётчики якоря: %w", err)
	}
	n, ok := labelPackets(out)[label]
	if !ok {
		return 0, fmt.Errorf("в якоре нет правила %q (режим не on?)", label)
	}
	return n, nil
}

func probeKey(id probe.ProbeID) string { return probeLabel(id.Proto, id.Src.Port()) }

// BeforeProbe — счётчик правила порта-источника пробы до неё (probe.Preparer).
func (b *Backend) BeforeProbe(id probe.ProbeID) error {
	n, err := b.labelCount(probeKey(id))
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.before[probeKey(id)] = n
	b.mu.Unlock()
	return nil
}

// Evidence: счётчик block-правила порта-источника пробы вырос — пробу отбросило наше правило.
func (b *Backend) Evidence(id probe.ProbeID, _ time.Time) (bool, error) {
	key := probeKey(id)
	b.mu.Lock()
	before, ok := b.before[key]
	delete(b.before, key)
	b.mu.Unlock()
	if !ok {
		return false, errors.New("счётчик до пробы не снят")
	}
	n, err := b.labelCount(key)
	if err != nil {
		return false, err
	}
	return n > before, nil
}

func sendCanary() error {
	c, err := net.Dial("udp4", net.JoinHostPort(canaryAddr, strconv.Itoa(canaryPort)))
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("killswitch-canary"))
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func copyIfDiffers(src, dst string, mode fs.FileMode) error {
	if same, err := sameFile(src, dst); err != nil || same {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, data) {
		return nil
	}
	return writeAtomic(dst, data, mode)
}

func sameFile(a, b string) (bool, error) {
	ia, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false, nil
	}
	return os.SameFile(ia, ib), nil
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
