package linux

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// fakeSys — nft и systemctl в памяти: таблица хранит загруженный скрипт без двух первых строк (как листинг ядра).
type fakeSys struct {
	root     string
	table    *string
	failLoad bool
	counters map[uint16]uint64
	calls    []string
}

func (f *fakeSys) run(stdin, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == "nft -c -f -":
		if f.failLoad {
			return "", errors.New("Error: syntax error")
		}
	case cmd == "nft -f -":
		if f.failLoad {
			return "", errors.New("Error: syntax error")
		}
		lines := strings.SplitN(stdin, "\n", 3)
		listing := lines[len(lines)-1]
		f.table = &listing
	case cmd == "nft -s list table inet killswitch":
		if f.table == nil {
			return "", errors.New("Error: No such file or directory")
		}
		return *f.table, nil
	case cmd == "nft list tables":
		if f.table != nil {
			return "table inet filter\ntable inet killswitch\n", nil
		}
		return "table inet filter\n", nil
	case cmd == "nft delete table inet killswitch":
		f.table = nil
	case cmd == "nft -j list chain inet killswitch deny":
		if f.table == nil || !strings.Contains(*f.table, "chain deny") {
			return "", errors.New("Error: No such file or directory")
		}
		var rules []string
		for port, n := range f.counters {
			rules = append(rules, fmt.Sprintf(`{"rule":{"chain":"deny","comment":"probe %d","expr":[{"counter":{"packets":%d,"bytes":0}},{"drop":null}]}}`, port, n))
		}
		return `{"nftables":[{"metainfo":{}},` + strings.Join(rules, ",") + `]}`, nil
	case strings.HasPrefix(cmd, "systemctl enable "):
		for _, u := range units {
			link := filepath.Join(f.root, filepath.FromSlash(u.wants))
			os.MkdirAll(filepath.Dir(link), 0o755)
			os.WriteFile(link, nil, 0o644)
		}
	case name == "systemctl":
	default:
		return "", fmt.Errorf("неожиданная команда %q", cmd)
	}
	return "", nil
}

func (f *fakeSys) count(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func newTestBackend(t *testing.T) (*Backend, *fakeSys) {
	t.Helper()
	root := t.TempDir()
	self := filepath.Join(root, "src-killswitch")
	if err := os.WriteFile(self, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeSys{root: root, counters: map[uint16]uint64{}}
	b := newBackend(root, f.run, func() (string, error) { return self, nil }, func() bool { return true })
	return b, f
}

func plan(t *testing.T, m policy.Mode) Ruleset {
	t.Helper()
	r, err := Plan(basePolicy().WithMode(m), baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (b *Backend) exists(p string) bool {
	_, err := os.Lstat(b.path(p))
	return err == nil
}

func TestApplyThenStatusHashMatchesPlan(t *testing.T) {
	b, _ := newTestBackend(t)
	r := plan(t, policy.ModeOn)
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
	s, err := b.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Active || s.Mode != policy.ModeOn || s.Hash != backend.HashOf(r) {
		t.Fatalf("status = %+v, ждали on с хешем плана", s)
	}
}

func TestStatusDriftWhenTableChanged(t *testing.T) {
	b, f := newTestBackend(t)
	r := plan(t, policy.ModeOn)
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(*f.table, `oifname "wg0" accept`, "", 1)
	f.table = &changed
	s, _ := b.Status()
	if s.Hash == backend.HashOf(r) || s.Hash == "" {
		t.Fatalf("дрейф не виден: hash=%q", s.Hash)
	}
}

func TestStatusDriftWhenEarlyUnitDisabled(t *testing.T) {
	b, _ := newTestBackend(t)
	r := plan(t, policy.ModeOn)
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
	os.Remove(b.path(units[0].wants))
	s, _ := b.Status()
	if s.Hash == backend.HashOf(r) {
		t.Fatal("выключенный ранний юнит не виден как дрейф")
	}
}

func TestStatusInstalledWithoutTable(t *testing.T) {
	b, f := newTestBackend(t)
	r := plan(t, policy.ModeOn)
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
	f.table = nil // `nft flush ruleset` чужой программой
	s, _ := b.Status()
	if !s.Active || s.Hash == "" || s.Hash == backend.HashOf(r) || s.Mode != "" {
		t.Fatalf("status = %+v, ждали установку без таблицы", s)
	}
}

func TestStatusNotInstalled(t *testing.T) {
	b, _ := newTestBackend(t)
	s, err := b.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.Active || s.Hash != "" {
		t.Fatalf("status = %+v, ждали «не установлен»", s)
	}
}

func TestStatusFailsWhenNftBroken(t *testing.T) {
	b, _ := newTestBackend(t)
	b.run = func(string, string, ...string) (string, error) { return "", errors.New("nft: not found") }
	if _, err := b.Status(); err == nil {
		t.Fatal("сбой nft выдан за «таблицы нет»")
	}
}

func TestApplyFailureKeepsPreviousSet(t *testing.T) {
	b, f := newTestBackend(t)
	if err := b.Apply(plan(t, policy.ModeOn)); err != nil {
		t.Fatal(err)
	}
	before := *f.table
	onBefore, _ := os.ReadFile(b.path(onFile))
	f.failLoad = true
	p := basePolicy()
	p.LAN = false
	r, _ := Plan(p, baseEnv())
	if err := b.Apply(r); err == nil {
		t.Fatal("ошибка nft не вернулась")
	}
	onAfter, _ := os.ReadFile(b.path(onFile))
	if *f.table != before || string(onAfter) != string(onBefore) {
		t.Fatal("после ошибки загрузки набор или on.nft изменились")
	}
}

// Сбой постоянного слоя (ENOSPC, нет бинарника) при off не снимает защиту: таблица остаётся прежней (контракт Apply).
func TestApplyOffInstallFailureKeepsOnTable(t *testing.T) {
	b, f := newTestBackend(t)
	if err := b.Apply(plan(t, policy.ModeOn)); err != nil {
		t.Fatal(err)
	}
	before := *f.table
	b.self = func() (string, error) { return "", errors.New("нет места") }
	if err := b.Apply(plan(t, policy.ModeOff)); err == nil {
		t.Fatal("ошибка постоянного слоя не вернулась")
	}
	if f.table == nil || *f.table != before {
		t.Fatal("после ошибки off таблица on снята")
	}
}

func TestApplyOffKeepsOnInPersist(t *testing.T) {
	b, _ := newTestBackend(t)
	off := plan(t, policy.ModeOff)
	if err := b.Apply(off); err != nil {
		t.Fatal(err)
	}
	persisted, _ := os.ReadFile(b.path(onFile))
	s, _ := b.Status()
	if string(persisted) != plan(t, policy.ModeOn).Persist || s.Mode != policy.ModeOff || s.Hash != backend.HashOf(off) {
		t.Fatalf("off: on.nft должен быть on-набором, status = %+v", s)
	}
}

func TestApplyInstallsUnitsOnce(t *testing.T) {
	b, f := newTestBackend(t)
	r := plan(t, policy.ModeOn)
	b.Apply(r)
	b.Apply(r)
	unit, _ := os.ReadFile(b.path(units[1].file))
	if !strings.Contains(string(unit), "ExecStart="+binFile+" enforce") || !b.exists(binFile) {
		t.Fatalf("юнит enforce или копия бинарника не на месте:\n%s", unit)
	}
	if n := f.count("systemctl enable"); n != 1 {
		t.Fatalf("systemctl enable вызван %d раз, ждали 1", n)
	}
	if n := f.count("systemctl start --no-block killswitch.service"); n != 1 {
		t.Fatalf("enforce запущен %d раз, ждали 1", n)
	}
}

func TestRemoveClearsEverything(t *testing.T) {
	b, f := newTestBackend(t)
	if err := b.Apply(plan(t, policy.ModeOn)); err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(); err != nil {
		t.Fatal(err)
	}
	s, _ := b.Status()
	for _, p := range []string{onFile, fallbackFile, appliedFile, binFile, units[0].file, units[1].file, units[0].wants} {
		if b.exists(p) {
			t.Errorf("%s остался", p)
		}
	}
	if s.Active || f.count("systemctl disable --now --no-block") != 1 {
		t.Fatalf("после Remove: status = %+v, вызовы %v", s, f.calls)
	}
}

func TestRemoveWithoutInstallIsOK(t *testing.T) {
	b, _ := newTestBackend(t)
	if err := b.Remove(); err != nil {
		t.Fatalf("Remove на чистой машине: %v", err)
	}
}

func probeID(port uint16) probe.ProbeID {
	return probe.ProbeID{Proto: "tcp", Src: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.2"), port),
		Dst: netip.MustParseAddrPort("203.0.113.130:80"), Iface: "c0"}
}

func TestEvidenceCountsProbePort(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[61005] = 3
	id := probeID(61005)
	if err := b.BeforeProbe(id); err != nil {
		t.Fatal(err)
	}
	f.counters[61005] = 4
	dropped, err := b.Evidence(id, id.At)
	if err != nil || !dropped {
		t.Fatalf("Evidence = %v, %v; ждали отброс", dropped, err)
	}
}

func TestEvidenceNoDropWhenCounterSame(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[61006] = 2
	id := probeID(61006)
	b.BeforeProbe(id)
	dropped, err := b.Evidence(id, id.At)
	if err != nil || dropped {
		t.Fatalf("Evidence = %v, %v; ждали «не отброшено»", dropped, err)
	}
}

// В off (пустая таблица) отброса нет: проба без ответа — без свидетельства, с ответом — утечка; это решает ядро.
func TestEvidenceWithoutDenyChainIsNoDrop(t *testing.T) {
	b, f := newTestBackend(t)
	if err := b.Apply(plan(t, policy.ModeOff)); err != nil {
		t.Fatal(err)
	}
	f.counters[61008] = 5
	id := probeID(61008)
	if err := b.BeforeProbe(id); err != nil {
		t.Fatalf("BeforeProbe в off: %v", err)
	}
	dropped, err := b.Evidence(id, id.At)
	if err != nil || dropped {
		t.Fatalf("Evidence в off = %v, %v; ждали «не отброшено» без ошибки", dropped, err)
	}
}

// Счётчик сброшен между снимками (таблицу пересоздали) — отброса пробы не видно.
func TestEvidenceCounterResetIsNoDrop(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[61009] = 3
	id := probeID(61009)
	b.BeforeProbe(id)
	f.counters[61009] = 0
	if dropped, err := b.Evidence(id, id.At); err != nil || dropped {
		t.Fatalf("Evidence после сброса = %v, %v; ждали «не отброшено»", dropped, err)
	}
}

// Запуск enforce при первой установке не тянет ранний юнит: тот перезаписал бы полный набор урезанным on.nft.
func TestEnforceUnitDoesNotPullEarlyUnit(t *testing.T) {
	if strings.Contains(units[1].text, "Wants=") || strings.Contains(units[1].text, "Requires=") {
		t.Fatalf("killswitch.service тянет другие юниты:\n%s", units[1].text)
	}
}

func TestEvidenceNeedsBeforeProbe(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[61007] = 1
	if _, err := b.Evidence(probeID(61007), probeID(61007).At); err == nil {
		t.Fatal("свидетельство без снимка счётчика")
	}
}

func TestUnitsText(t *testing.T) {
	for _, u := range units {
		golden(t, filepath.Join("testdata", filepath.Base(u.file)), u.text)
	}
	golden(t, filepath.Join("testdata", "fallback.nft"), fallbackScript)
}

// Сбой после загрузки пустой таблицы off (запись отпечатка) возвращает on-набор: при ошибке Apply защита не снята.
func TestApplyOffLateFailureRestoresOn(t *testing.T) {
	b, f := newTestBackend(t)
	if err := b.Apply(plan(t, policy.ModeOn)); err != nil {
		t.Fatal(err)
	}
	os.Remove(b.path(appliedFile))
	os.MkdirAll(filepath.Join(b.path(appliedFile), "x"), 0o755) // rename поверх непустого каталога не пройдёт
	if err := b.Apply(plan(t, policy.ModeOff)); err == nil {
		t.Fatal("ошибка записи отпечатка не вернулась")
	}
	if f.table == nil || !strings.Contains(*f.table, "chain postrouting") {
		t.Fatal("после поздней ошибки off защита снята")
	}
}

// Границы диапазона проб включены: 61000 и 61063 — пробы, соседние порты — нет.
func TestProbePortBounds(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[61000], f.counters[61063] = 1, 1
	for port, ok := range map[uint16]bool{60999: false, 61000: true, 61063: true, 61064: false} {
		if err := b.BeforeProbe(probeID(port)); (err == nil) != ok {
			t.Errorf("порт %d: BeforeProbe err=%v", port, err)
		}
	}
}

// Поздний сбой Apply(on) не подменяет полный набор урезанным on.nft (без cgroup): откат — только для off.
func TestApplyOnLateFailureKeepsFullSet(t *testing.T) {
	b, f := newTestBackend(t)
	p := basePolicy()
	p.Trust = []policy.Trust{{Kind: policy.KindCgroup, Value: "system.slice/sing-box*.service", Destinations: policy.DestAny}}
	r, err := Plan(p, baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(b.path(appliedFile), "x"), 0o755)
	if err := b.Apply(r); err == nil {
		t.Fatal("ошибка записи отпечатка не вернулась")
	}
	if f.table == nil || !strings.Contains(*f.table, "cgroupv2") {
		t.Fatal("после поздней ошибки on полный набор заменён урезанным")
	}
}
