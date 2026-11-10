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
	egress   map[uint16]uint64
	loads    int // загрузок таблицы: handle таблицы в ядре растёт с каждым пересозданием
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
		f.loads++
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
	case cmd == "nft -j list tables":
		if f.table == nil {
			return `{"nftables":[{"metainfo":{}}]}`, nil
		}
		return fmt.Sprintf(`{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"killswitch","handle":%d}}]}`, f.loads), nil
	case cmd == "nft delete table inet killswitch":
		f.table = nil
	case cmd == "nft -j list chain inet killswitch deny":
		if f.table == nil || !strings.Contains(*f.table, "chain deny") {
			return "", errors.New("Error: No such file or directory")
		}
		rules := []string{`{"metainfo":{}}`}
		for port, n := range f.counters {
			rules = append(rules, fmt.Sprintf(`{"rule":{"chain":"deny","comment":"probe %d","expr":[{"counter":{"packets":%d,"bytes":0}},{"drop":null}]}}`, port, n))
		}
		return `{"nftables":[` + strings.Join(rules, ",") + `]}`, nil
	case cmd == "nft -j list chain inet killswitch egress":
		if f.table == nil || !strings.Contains(*f.table, "chain egress") {
			return "", errors.New("Error: No such file or directory")
		}
		rules := []string{`{"metainfo":{}}`}
		for port, n := range f.egress {
			rules = append(rules, fmt.Sprintf(`{"rule":{"chain":"egress","comment":"egress %d","expr":[{"counter":{"packets":%d,"bytes":0}}]}}`, port, n))
		}
		return `{"nftables":[` + strings.Join(rules, ",") + `]}`, nil
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
	f := &fakeSys{root: root, counters: map[uint16]uint64{}, egress: map[uint16]uint64{}}
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
	f.counters[30005] = 3
	id := probeID(30005)
	if err := b.BeforeProbe(id); err != nil {
		t.Fatal(err)
	}
	f.counters[30005] = 4
	dropped, err := b.Evidence(id, id.At)
	if err != nil || !dropped {
		t.Fatalf("Evidence = %v, %v; ждали отброс", dropped, err)
	}
}

func TestEvidenceNoDropWhenCounterSame(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[30006] = 2
	id := probeID(30006)
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
	f.counters[30008] = 5
	id := probeID(30008)
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
	f.counters[30009] = 3
	id := probeID(30009)
	b.BeforeProbe(id)
	f.counters[30009] = 0
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
	f.counters[30007] = 1
	if _, err := b.Evidence(probeID(30007), probeID(30007).At); err == nil {
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

// Границы диапазона проб включены: 30000 и 30063 — пробы, соседние порты — нет.
func TestProbePortBounds(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	f.counters[30000], f.counters[30063] = 1, 1
	for port, ok := range map[uint16]bool{60999: false, 30000: true, 30063: true, 30064: false} {
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

// egressed — проба с ответом: был ли рост счётчика выхода порта между BeforeProbe и Egressed.
func egressed(t *testing.T, m policy.Mode, before, after uint64) (bool, error) {
	t.Helper()
	b, f := newTestBackend(t)
	if err := b.Apply(plan(t, m)); err != nil {
		t.Fatal(err)
	}
	id := probeID(30010)
	f.counters[30010] = 0
	f.egress[30010] = before
	if err := b.BeforeProbe(id); err != nil {
		t.Fatal(err)
	}
	f.egress[30010] = after
	return b.Egressed(id)
}

func TestEgressedWhenCounterGrew(t *testing.T) {
	if sent, err := egressed(t, policy.ModeOn, 1, 2); err != nil || !sent {
		t.Fatalf("Egressed = %v, %v; ждали «ушёл»", sent, err)
	}
}

// Счётчик выхода не вырос — доказано, что проба через физику не уходила (перехвачена клиентом туннеля).
func TestNotEgressedWhenCounterSame(t *testing.T) {
	if sent, err := egressed(t, policy.ModeOn, 2, 2); err != nil || sent {
		t.Fatalf("Egressed = %v, %v; ждали «не ушёл»", sent, err)
	}
}

// Нет цепочки egress (off, таблица снята, старый набор) — признака нет: ядро назовёт ответ утечкой.
func TestEgressUnknownWithoutEgressChain(t *testing.T) {
	if _, err := egressed(t, policy.ModeOff, 2, 2); err == nil {
		t.Fatal("в off признак выхода есть; ждали ошибку")
	}
}

// Счётчик сброшен между снимками (таблицу пересоздали) — «не ушёл» не доказано.
func TestEgressUnknownAfterCounterReset(t *testing.T) {
	if _, err := egressed(t, policy.ModeOn, 3, 0); err == nil {
		t.Fatal("после сброса счётчика признак есть; ждали ошибку")
	}
}

// Таблицу пересоздали между снимками (снята и возвращена, счётчик снова с нуля) — «не ушёл» не доказано.
func TestEgressUnknownWhenTableReloaded(t *testing.T) {
	b, f := newTestBackend(t)
	b.Apply(plan(t, policy.ModeOn))
	id := probeID(30011)
	f.counters[30011], f.egress[30011] = 0, 0
	if err := b.BeforeProbe(id); err != nil {
		t.Fatal(err)
	}
	b.Apply(plan(t, policy.ModeOn))
	if sent, err := b.Egressed(id); err == nil {
		t.Fatalf("Egressed после пересоздания = %v, nil; ждали ошибку", sent)
	}
}
