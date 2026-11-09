package linux

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// Пути на машине (абсолютные, от корня Backend.root).
const (
	stateDir     = "/var/lib/killswitch"
	onFile       = stateDir + "/on.nft"
	fallbackFile = stateDir + "/fallback.nft"
	appliedFile  = stateDir + "/nft-applied.json" // отпечаток факта после Apply → хеш плана
	binFile      = stateDir + "/bin/killswitch"   // копия бинарника для юнитов: пишет только root
)

// runner выполняет программу из PATH; stdin — вход, результат — stdout.
type runner func(stdin, name string, args ...string) (string, error)

// Backend — nftables. Внешние вызовы (nft, ip, systemctl) и корень ФС подменяются в тестах.
type Backend struct {
	run     runner
	root    string
	self    func() (string, error)
	systemd func() bool
	// Snapshot: источники, которые в тестах подменяются.
	ifaces     func() ([]env.Iface, error)
	lookupUser func(name string) (int, error)
	resolve    func(host string) ([]netip.Addr, error)

	mu     sync.Mutex
	before map[uint16]counterSnap // счётчик порта пробы до пробы (BeforeProbe)

	watchOnce sync.Once
	changes   chan struct{}
}

var (
	_ backend.Backend = (*Backend)(nil)
	_ probe.Preparer  = (*Backend)(nil)
	_ backend.Watcher = (*Backend)(nil)
)

// New — backend системы.
func New() *Backend {
	return newBackend("/", execRun, os.Executable, func() bool { _, err := exec.LookPath("systemctl"); return err == nil })
}

func newBackend(root string, run runner, self func() (string, error), systemd func() bool) *Backend {
	return &Backend{run: run, root: root, self: self, systemd: systemd, before: map[uint16]counterSnap{},
		ifaces: systemIfaces, lookupUser: systemLookupUser, resolve: systemResolve}
}

func execRun(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func (b *Backend) path(p string) string { return filepath.Join(b.root, filepath.FromSlash(p)) }

// Capabilities — user, cgroup, mark и endpoints; repair на linux нет.
func (b *Backend) Capabilities() policy.Capabilities { return policy.CapabilitiesFor("linux") }

// Plan — чистая функция, см. Plan.
func (b *Backend) Plan(p policy.Policy, e env.Env) (backend.Ruleset, error) {
	r, err := Plan(p, e)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Apply: проверенный `nft -c` постоянный слой (on.nft, запасной набор, копия бинарника, юниты), затем таблица одной
// транзакцией `nft -f` и отпечаток факта для Status. Любая ошибка до загрузки оставляет прежнюю таблицу (fail-closed,
// в том числе для off), а on.nft всегда остаётся грузимым on-набором.
func (b *Backend) Apply(r backend.Ruleset) error {
	rs, ok := r.(Ruleset)
	if !ok {
		return fmt.Errorf("план не для linux: %T", r)
	}
	if _, err := b.run(rs.Persist, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("проверка on.nft: %w", err)
	}
	if err := b.install(rs.Persist); err != nil {
		return err
	}
	if _, err := b.run(rs.Load, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("загрузка таблицы: %w", err)
	}
	if err := b.record(rs); err != nil {
		if rs.Mode == policy.ModeOff {
			// Защита не снимается при ошибке: вместо off — проверенный on-набор (блок).
			_, _ = b.run(rs.Persist, "nft", "-f", "-")
		}
		return err
	}
	return nil
}

// record пишет отпечаток факта после Apply → хеш плана (по нему Status отдаёт хеш плана).
func (b *Backend) record(rs Ruleset) error {
	f, err := b.readFact()
	if err != nil {
		return err
	}
	data, _ := json.Marshal(applied{Fingerprint: f.fingerprint(), PlanHash: backend.HashOf(rs)})
	return writeFile(b.path(appliedFile), data, 0o600)
}

type applied struct {
	Fingerprint string `json:"fingerprint"`
	PlanHash    string `json:"plan_hash"`
}

func (b *Backend) install(persist string) error {
	if err := writeFile(b.path(onFile), []byte(persist), 0o600); err != nil {
		return err
	}
	if err := writeFile(b.path(fallbackFile), []byte(fallbackScript), 0o600); err != nil {
		return err
	}
	if err := b.copySelf(); err != nil {
		return err
	}
	if !b.systemd() {
		return nil
	}
	return b.installUnits()
}

// copySelf кладёт копию бинарника туда, куда пишет только root: юниты не должны запускать файл из каталога пользователя.
func (b *Backend) copySelf() error {
	src, err := b.self()
	if err != nil {
		return fmt.Errorf("путь бинарника: %w", err)
	}
	dst := b.path(binFile)
	if same, _ := filepath.Abs(src); same == dst {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("копия бинарника: %w", err)
	}
	if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return writeFile(dst, data, 0o755)
}

func (b *Backend) installUnits() error {
	changed := false
	for _, u := range units {
		if old, err := os.ReadFile(b.path(u.file)); err == nil && string(old) == u.text {
			continue
		}
		if err := writeFile(b.path(u.file), []byte(u.text), 0o644); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if _, err := b.run("", "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if b.enabled() {
		return nil
	}
	if _, err := b.run("", "systemctl", "enable", units[0].name, units[1].name); err != nil {
		return err
	}
	_, err := b.run("", "systemctl", "start", "--no-block", units[1].name)
	return err
}

func (b *Backend) enabled() bool {
	for _, u := range units {
		if _, err := os.Lstat(b.path(u.wants)); err != nil {
			return false
		}
	}
	return true
}

// Remove снимает юниты, таблицу и свои файлы без конфига и сети. Остановка enforce — без ожидания: он может ждать замок,
// который держит uninstall.
func (b *Backend) Remove() error {
	var errs []error
	if b.systemd() {
		_, _ = b.run("", "systemctl", "disable", "--now", "--no-block", units[1].name, units[0].name)
	}
	present, _, err := b.readTable()
	switch {
	case err != nil:
		errs = append(errs, err)
	case present:
		if _, err := b.run("", "nft", "delete", "table", "inet", table); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range []string{units[0].wants, units[1].wants, units[0].file, units[1].file, onFile, fallbackFile, appliedFile, binFile} {
		if err := os.Remove(b.path(p)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(filepath.Dir(b.path(binFile)))
	if b.systemd() {
		_, _ = b.run("", "systemctl", "daemon-reload")
	}
	return errors.Join(errs...)
}

// Status — факт: таблица из ядра и постоянный слой с диска. Hash — хеш плана, если отпечаток факта тот же, что после
// последнего Apply; иначе отпечаток (дрейф). Пустой — установки нет.
func (b *Backend) Status() (backend.Status, error) {
	f, err := b.readFact()
	if err != nil {
		return backend.Status{}, err
	}
	s := backend.Status{Active: f.present || f.has(onFile) || f.has(units[0].file), Details: f.details()}
	if f.present {
		s.Mode, s.Rules = f.mode(), f.rules()
	}
	if !s.Active {
		return s, nil
	}
	fp := f.fingerprint()
	s.Hash = "fact-" + fp
	var a applied
	if data, err := os.ReadFile(b.path(appliedFile)); err == nil && json.Unmarshal(data, &a) == nil && a.Fingerprint == fp {
		s.Hash = a.PlanHash
	}
	return s, nil
}

// fact — прочитанное обратно: листинг таблицы без счётчиков и файлы постоянного слоя.
type fact struct {
	present bool
	listing string
	files   map[string]string // путь → содержимое; нет файла — ключа нет
}

func (b *Backend) readFact() (fact, error) {
	present, listing, err := b.readTable()
	if err != nil {
		return fact{}, err
	}
	f := fact{present: present, listing: listing, files: map[string]string{}}
	content := []string{onFile, fallbackFile, units[0].file, units[1].file}
	for _, p := range content {
		if data, err := os.ReadFile(b.path(p)); err == nil {
			f.files[p] = string(data)
		}
	}
	for _, p := range []string{binFile, units[0].wants, units[1].wants} { // только наличие
		if _, err := os.Lstat(b.path(p)); err == nil {
			f.files[p] = "есть"
		}
	}
	return f, nil
}

// readTable: таблицы нет — (false, "", nil); сбой nft — ошибка, а не «нет таблицы».
func (b *Backend) readTable() (bool, string, error) {
	out, err := b.run("", "nft", "-s", "list", "table", "inet", table)
	if err == nil {
		return true, out, nil
	}
	tables, lerr := b.run("", "nft", "list", "tables")
	if lerr != nil {
		return false, "", fmt.Errorf("nft: %w", lerr)
	}
	for _, line := range strings.Split(tables, "\n") {
		if strings.TrimSpace(line) == "table inet "+table {
			return false, "", fmt.Errorf("чтение таблицы: %w", err)
		}
	}
	return false, "", nil
}

func (f fact) has(p string) bool { _, ok := f.files[p]; return ok }

func (f fact) fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "table %t\n%s\n", f.present, f.listing)
	keys := make([]string, 0, len(f.files))
	for k := range f.files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "file %s %d\n%s\n", k, len(f.files[k]), f.files[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (f fact) mode() policy.Mode {
	if strings.Contains(f.listing, "chain postrouting") {
		return policy.ModeOn
	}
	return policy.ModeOff
}

// rules — число правил в листинге: строки внутри цепочек, кроме заголовка type … policy.
func (f fact) rules() int {
	n := 0
	for _, line := range strings.Split(f.listing, "\n") {
		if strings.HasPrefix(line, "\t\t") && !strings.HasPrefix(line, "\t\ttype ") {
			n++
		}
	}
	return n
}

func (f fact) details() string {
	state := func(ok bool) string {
		if ok {
			return "есть"
		}
		return "нет"
	}
	return fmt.Sprintf("таблица inet %s: %s; on.nft: %s; ранний юнит: %s (включён: %s)", table, state(f.present),
		state(f.has(onFile)), state(f.has(units[0].file)), state(f.has(units[0].wants)))
}

// counterSnap — счётчик правила порта пробы; ok=false — цепочки отброса нет (off или таблица снята).
type counterSnap struct {
	n  uint64
	ok bool
}

// BeforeProbe запоминает счётчик правила порта пробы (рев. 5: свидетельство — рост счётчика нашего drop).
func (b *Backend) BeforeProbe(id probe.ProbeID) error {
	c, err := b.probeCount(id.Src.Port())
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.before[id.Src.Port()] = c
	b.mu.Unlock()
	return nil
}

// Evidence: счётчик правила порта пробы вырос после BeforeProbe. Нет цепочки отброса — нет и свидетельства
// (с ответом сервера ядро назовёт это утечкой). since не нужен — сравнение со снимком.
func (b *Backend) Evidence(id probe.ProbeID, _ time.Time) (bool, error) {
	port := id.Src.Port()
	b.mu.Lock()
	before, ok := b.before[port]
	delete(b.before, port)
	b.mu.Unlock()
	if !ok {
		return false, fmt.Errorf("нет снимка счётчика порта %d до пробы", port)
	}
	now, err := b.probeCount(port)
	if err != nil {
		return false, err
	}
	return before.ok && now.ok && now.n > before.n, nil
}

func (b *Backend) probeCount(port uint16) (counterSnap, error) {
	if port < probe.SrcPortFirst || port > probe.SrcPortLast {
		return counterSnap{}, fmt.Errorf("порт %d вне диапазона проб", port)
	}
	out, err := b.run("", "nft", "-j", "list", "chain", "inet", table, denyChain)
	if err != nil {
		present, listing, terr := b.readTable()
		if terr != nil {
			return counterSnap{}, terr
		}
		if !present || !strings.Contains(listing, "chain "+denyChain+" {") {
			return counterSnap{}, nil
		}
		return counterSnap{}, fmt.Errorf("счётчики: %w", err)
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string `json:"comment"`
				Expr    []struct {
					Counter *struct {
						Packets uint64 `json:"packets"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return counterSnap{}, fmt.Errorf("счётчики: %w", err)
	}
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment != probeComment(port) {
			continue
		}
		for _, e := range item.Rule.Expr {
			if e.Counter != nil {
				return counterSnap{n: e.Counter.Packets, ok: true}, nil
			}
		}
	}
	return counterSnap{}, fmt.Errorf("нет правила пробы порта %d", port)
}

// writeFile — атомарно: временный файл, fsync, rename.
func writeFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
