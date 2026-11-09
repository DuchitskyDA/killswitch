//go:build windows && wfplive

// Живые тесты WFP: только на одноразовом раннере GitHub Actions (workflow smoke-windows), никогда на рабочей машине.
// Сборка: go test -tags wfplive -c; запуск — отдельными шагами workflow с -test.run.
package windows

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
)

// onRunner — защита машины: без признаков одноразового раннера тест падает до любого вызова WFP.
func onRunner(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("живые тесты WFP — только на раннере GitHub (GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted)")
	}
}

// configPolicy — политика из конфига дыма (KS_CONFIG), как её строит CLI без профиля.
func configPolicy(t *testing.T) policy.Policy {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("KS_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Build(policy.Layer{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p.WithMode(policy.ModeOn)
}

func applyConfig(t *testing.T, b *Backend) {
	t.Helper()
	p := configPolicy(t)
	e, err := b.Snapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Plan(p, e)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
}

// TestLiveEvidence: при on проба этого (недоверенного) процесса отброшена, и есть событие отброса нашим фильтром.
func TestLiveEvidence(t *testing.T) {
	onRunner(t)
	b := New()
	id := probe.ProbeID{Proto: "tcp", Src: netip.MustParseAddrPort("0.0.0.0:30010"),
		Dst: netip.MustParseAddrPort("1.1.1.1:80"), At: time.Now()}
	if err := b.BeforeProbe(id); err != nil {
		t.Fatal(err)
	}
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: net.TCPAddrFromAddrPort(id.Src)}
	conn, dialErr := d.Dial("tcp4", id.Dst.String())
	if dialErr == nil {
		conn.Close()
		t.Fatal("проба вышла мимо защиты")
	}
	dropped, err := b.Evidence(id, id.At)
	if err != nil || !dropped {
		dumpDrops(t, id.At)
		t.Fatalf("нет свидетельства отброса нашим фильтром: dropped=%v err=%v (dial: %v)", dropped, err, dialErr)
	}
	b.AfterProbe(id)
	t.Logf("проба отброшена: %v", dialErr)
}

// dumpDrops — диагностика: состояние сбора, наши block-id и все события отброса около пробы.
func dumpDrops(t *testing.T, since time.Time) {
	t.Helper()
	s, err := wf.New(&wf.Options{Name: "ks-smoke-diag", Dynamic: true})
	if err != nil {
		t.Logf("diag: %v", err)
		return
	}
	defer s.Close()
	on, err := s.CollectNetEvents()
	t.Logf("diag: сбор событий=%v err=%v", on, err)
	ours, err := ourBlockIDs(s)
	t.Logf("diag: наши block id=%v err=%v", ours, err)
	all, err := s.DropEvents()
	t.Logf("diag: всего событий без окна=%d err=%v", len(all), err)
	evs, err := s.DropEventsSince(since.Add(-time.Minute), time.Now().Add(time.Minute))
	t.Logf("diag: событий в окне ±1 мин=%d err=%v", len(evs), err)
	for i, ev := range evs {
		if i >= 30 {
			break
		}
		t.Logf("diag: %s proto=%d %s -> %s filter=%d layer=%d app=%q", ev.Timestamp.Format(time.RFC3339Nano),
			ev.IPProtocol, ev.LocalAddr, ev.RemoteAddr, ev.FilterID, ev.LayerID, ev.AppID)
	}
}

// dumpSublayers — диагностика: порядок перечисления sublayer и hard permit чужих на CONNECT_V4.
func dumpSublayers(t *testing.T) {
	t.Helper()
	s, err := wf.New(&wf.Options{Name: "ks-smoke-diag", Dynamic: true})
	if err != nil {
		t.Logf("diag: %v", err)
		return
	}
	defer s.Close()
	subs, err := s.Sublayers()
	t.Logf("diag: sublayers err=%v", err)
	for i, sl := range subs {
		t.Logf("diag: #%d %s %q weight=0x%X provider=%s", i, sl.ID, sl.Name, sl.Weight, sl.Provider)
	}
	rs, err := s.RulesOf(wf.RuleFilter{Layer: wf.LayerALEAuthConnectV4, IncludeDisabled: true})
	t.Logf("diag: фильтров CONNECT_V4=%d err=%v", len(rs), err)
	for _, r := range rs {
		if r.Action == wf.ActionPermit && r.HardAction {
			t.Logf("diag: hard permit %q sublayer=%s weight=%d conds=%d", r.Name, r.Sublayer, r.Weight, len(r.Conditions))
		}
	}
}

// TestLiveCollectionRestored: сбор событий выключен до пробы — BeforeProbe включает, AfterProbe выключает обратно.
func TestLiveCollectionRestored(t *testing.T) {
	onRunner(t)
	s, err := openSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetCollectNetEvents(false); err != nil {
		t.Fatal(err)
	}
	b := New()
	id := probe.ProbeID{Proto: "tcp", Dst: netip.MustParseAddrPort("1.1.1.1:80"), At: time.Now()}
	if err := b.BeforeProbe(id); err != nil {
		t.Fatal(err)
	}
	during, _ := s.CollectNetEvents()
	b.AfterProbe(id)
	after, err := s.CollectNetEvents()
	if err != nil || !during || after {
		t.Errorf("сбор: во время пробы=%v (нужно true), после=%v (нужно false), err=%v", during, after, err)
	}
}

// foreignPermit — чужой sublayer 0xFFFF с hard permit всего на CONNECT_V4 в dynamic-сессии (исчезает с сессией).
func foreignPermit(t *testing.T) *wf.Session {
	t.Helper()
	s, err := wf.New(&wf.Options{Name: "ks-smoke-foreign", Dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	sub := wf.SublayerID(xwin.GUID{Data1: 0x5a5a0001, Data2: 0x1, Data3: 0x4000, Data4: [8]byte{0x80, 1, 2, 3, 4, 5, 6, 7}})
	if err := s.AddSublayer(&wf.Sublayer{ID: sub, Name: "ks-smoke-foreign", Weight: 0xFFFF}); err != nil {
		t.Fatal(err)
	}
	rule := &wf.Rule{ID: wf.RuleID(xwin.GUID{Data1: 0x5a5a0002, Data2: 0x1, Data3: 0x4000, Data4: [8]byte{0x80, 1, 2, 3, 4, 5, 6, 8}}),
		Name: "ks-smoke-foreign permit all", Layer: wf.LayerALEAuthConnectV4, Sublayer: sub, Weight: 15,
		Action: wf.ActionPermit, HardAction: true}
	if err := s.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	return s
}

func tieKinds(t *testing.T, b *Backend) []string {
	t.Helper()
	st, err := b.Status()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status: active=%v rules=%d details=%s", st.Active, st.Rules, st.Details)
	dumpSublayers(t)
	var kinds []string
	for _, f := range st.Structural {
		kinds = append(kinds, f.Kind)
		t.Logf("находка %s: %s", f.Kind, f.Detail)
	}
	return kinds
}

// TestLiveTie: чужой sublayer 0xFFFF после нашего — не утечка; наш создан после чужого — LEAK (wfp-tie).
// В конце наш набор переустановлен по конфигу уже без чужого.
func TestLiveTie(t *testing.T) {
	onRunner(t)
	b := New()
	foreign := foreignPermit(t) // наш уже есть: WFP понизит чужой до 0xFFFE
	after := tieKinds(t, b)
	foreign.Close()
	if err := b.Remove(); err != nil {
		t.Fatal(err)
	}
	foreign = foreignPermit(t) // нашего нет: чужой получает 0xFFFF
	defer foreign.Close()
	applyConfig(t, b) // наш sublayer создан после чужого и понижен
	before := tieKinds(t, b)
	foreign.Close()
	gone := tieKinds(t, b)
	if len(after) != 0 || len(before) != 1 || before[0] != "wfp-tie" || len(gone) != 0 {
		t.Errorf("ожидалось: после нашего — нет, раньше нашего — wfp-tie, без чужого — нет; получено %v / %v / %v", after, before, gone)
	}
}

// TestLiveBootKeys: boot-time-набор установлен (block + loopback + DHCP на 4 слоях); ключи — в KS_BOOTKEYS
// для независимой сверки с `netsh wfp show boottimepolicy`.
func TestLiveBootKeys(t *testing.T) {
	onRunner(t)
	s, err := openSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rules, err := ourRules(s)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range rules {
		if r.BootTime {
			keys = append(keys, strings.ToLower(strings.Trim(r.ID.String(), "{}")))
		}
	}
	if err := os.WriteFile(os.Getenv("KS_BOOTKEYS"), []byte(strings.Join(keys, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3*len(Layers) {
		t.Errorf("boot-time фильтров %d, ожидалось %d", len(keys), 3*len(Layers))
	}
}

// TestLiveGone: после uninstall нет ни provider, ни sublayer, ни одного нашего фильтра на всех слоях (с boot-time).
func TestLiveGone(t *testing.T) {
	onRunner(t)
	s, err := wf.New(&wf.Options{Name: "ks-smoke-check", Dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	provs, err := s.Providers()
	if err != nil {
		t.Fatal(err)
	}
	subs, err := s.Sublayers()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := s.Layers()
	if err != nil {
		t.Fatal(err)
	}
	pid, left := providerID, 0
	for _, l := range layers {
		rs, _ := s.RulesOf(wf.RuleFilter{Provider: &pid, Layer: l.ID, IncludeBootTime: true, IncludeDisabled: true})
		left += len(rs)
	}
	if hasProvider(provs) || hasSublayer(subs) || left != 0 {
		t.Errorf("после uninstall остались: provider=%v sublayer=%v фильтров=%d", hasProvider(provs), hasSublayer(subs), left)
	}
}

func hasSublayer(subs []*wf.Sublayer) bool {
	for _, s := range subs {
		if s.ID == sublayerID {
			return true
		}
	}
	return false
}
