package darwin

import (
	"net/netip"
	"os"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

func kinds(s backend.Status) map[string]bool {
	m := map[string]bool{}
	for _, f := range s.Structural {
		m[f.Kind] = f.Repair
	}
	return m
}

func status(t *testing.T, b *Backend) backend.Status {
	t.Helper()
	s, err := b.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return s
}

func TestStatusNotInstalledHasNoHash(t *testing.T) {
	f := newFixture(t)
	s := status(t, f.b)
	if s.Active || s.Hash != "" {
		t.Errorf("без установки: Active=false и пустой Hash, получено %+v", s)
	}
}

func TestStatusHashEqualsPlanAfterApply(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := onRules()
	f.apply(r)
	s := status(t, f.b)
	if !s.Active || s.Hash != backend.HashOf(r) || s.Mode != "on" {
		t.Errorf("после Apply: Active, Hash плана и режим on, получено %+v", s)
	}
	if len(s.Structural) != 0 || !s.AnchorOK || s.Token != "18446744071234567890" {
		t.Errorf("исправная установка без находок, канарейка дошла, токен наш: %+v", s)
	}
}

func TestStatusDriftWhenAnchorFlushedByOther(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := onRules()
	f.apply(r)
	f.run.replies["pfctl -a "+Anchor+" -sr"] = []Result{{Out: ""}}
	s := status(t, f.b)
	if s.Hash == backend.HashOf(r) {
		t.Error("чужой flush якоря должен дать хеш, отличный от плана")
	}
	if repair, ok := kinds(s)["anchor-drift"]; !ok || !repair {
		t.Errorf("дрейф якоря — находка с Repair, получено %+v", s.Structural)
	}
}

func TestStatusPfDisabledIsRepairable(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.replies["pfctl -s info"] = []Result{{Out: infoDisabled}}
	s := status(t, f.b)
	if repair, ok := kinds(s)["pf-disabled"]; !ok || !repair || s.AnchorOK {
		t.Errorf("pf выключен — Repair, канарейка не проверяется, получено %+v", s)
	}
}

func TestStatusLostTokenIsRepairable(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.replies["pfctl -s References"] = []Result{{Out: refsForeign}}
	if repair, ok := kinds(status(t, f.b))["pf-token-lost"]; !ok || !repair {
		t.Error("потерянный токен при включённом чужим pf — находка с Repair")
	}
}

func TestStatusRuleAboveAnchorIsLeakOnly(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.replies["pfctl -sr"] = []Result{{Out: "pass out quick all\n" + mainDefault}}
	if repair, ok := kinds(status(t, f.b))["rule-above-anchor"]; !ok || repair {
		t.Error("чужое правило выше якоря — только LEAK, без Repair (решение «А»)")
	}
}

func TestStatusNoAnchorPointIsRepairable(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.replies["pfctl -sr"] = []Result{{Out: "pass all\n"}}
	if repair, ok := kinds(status(t, f.b))["no-anchor-point"]; !ok || !repair {
		t.Error("нет anchor-точки — находка с Repair")
	}
}

func TestStatusSiblingBeforeWithPassQuickIsLeakOnly(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.on("pfctl -a com.apple -sA", "  com.apple/000.a-other\n  com.apple/000.killswitch\n  com.apple/250.ApplicationFirewall\n")
	f.run.on("pfctl -a com.apple/000.a-other -sr", "pass out quick proto tcp all\n")
	f.run.on("pfctl -a com.apple/250.ApplicationFirewall -sr", "pass out quick all\n")
	got := kinds(status(t, f.b))
	if repair, ok := got["sibling-before"]; !ok || repair || len(got) != 1 {
		t.Errorf("сосед раньше нашего с pass quick — одна находка без Repair (позже нашего — не находка), получено %v", got)
	}
}

func TestStatusCanaryMissIsLeakOnly(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.replies["pfctl -a "+Anchor+" -vsr"] = []Result{{Out: canaryCounters("3")}}
	s := status(t, f.b)
	if repair, ok := kinds(s)["anchor-unreachable"]; !ok || repair || s.AnchorOK {
		t.Errorf("канарейка не дошла — LEAK без Repair, AnchorOK=false, получено %+v", s)
	}
}

func TestStatusOffHasNoFindings(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.replies["pfctl -a "+Anchor+" -sr"] = []Result{{Out: ""}}
	off := Rules{Mode: "off", Text: headerMode + "off\n"}
	f.apply(off)
	f.run.replies["pfctl -s info"] = []Result{{Out: infoDisabled}}
	s := status(t, f.b)
	if s.Hash != backend.HashOf(off) || len(s.Structural) != 0 {
		t.Errorf("off: хеш off-набора и без находок, получено %+v", s)
	}
}

func TestApplyOnTakesOwnTokenAndFlushesStates(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.replies["pfctl -s References"] = []Result{{Out: refsForeign}}
	f.run.on("killswitchd -E", "pf enabled\nToken : 18446744071234567890\n")
	f.apply(onRules())
	if !f.run.called("killswitchd -E") || !f.run.called("pfctl -F states") {
		t.Errorf("on без нашего токена: -E из копии pfctl и сброс состояний, вызовы %q", f.run.calls)
	}
	if f.run.called("pfctl -d") {
		t.Error("pfctl -d не вызывается никогда")
	}
}

func TestApplyOffKeepsStatesAndToken(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(Rules{Mode: "off", Text: headerMode + "off\n"})
	if f.run.called("pfctl -F states") || f.run.called("killswitchd -E") || f.run.called("pfctl -X") {
		t.Errorf("off только грузит пустой якорь, вызовы %q", f.run.calls)
	}
}

func TestApplyRestoresMissingAnchorPoint(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.replies["pfctl -sr"] = []Result{{Out: "pass all\n"}}
	f.apply(onRules())
	if !f.run.called("pfctl -f " + pfConf) {
		t.Error("нет anchor-точки — Apply возвращает /etc/pf.conf")
	}
}

func TestApplyLeavesForeignRuleAboveAnchor(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.replies["pfctl -sr"] = []Result{{Out: "pass out quick all\n" + mainDefault}}
	f.apply(onRules())
	if f.run.called("pfctl -f " + pfConf) {
		t.Error("anchor-точка есть: основной набор не перезаписывается (решение «А»)")
	}
}

// Сбой загрузки: прежние правила pf остаются (pfctl грузит якорь атомарно), а запись снята —
// enforce видит дрейф и повторяет Apply, а не фиксирует несостоявшийся переход.
func TestApplyFailedLoadLeavesDriftForRetry(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	f.run.fails["pfctl -a "+Anchor+" -f "+f.paths.rulesFile()+".new"] = true
	if err := f.b.Apply(onRules()); err == nil {
		t.Fatal("сбой загрузки якоря — ошибка Apply")
	}
	if repair, ok := kinds(status(t, f.b))["anchor-drift"]; !ok || !repair || f.run.called("pfctl -a "+Anchor+" -F") {
		t.Error("после сбоя загрузки: дрейф с Repair, прежние правила якоря не сброшены")
	}
}

// Повторный Apply того же плана с упавшим сбросом состояний не должен выглядеть завершённым.
func TestReapplySamePlanFailedFlushLeavesDrift(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := onRules()
	f.apply(r)
	f.run.fails["pfctl -F states"] = true
	if err := f.b.Apply(r); err == nil {
		t.Fatal("сбой сброса состояний — ошибка Apply")
	}
	if s := status(t, f.b); s.Hash == backend.HashOf(r) {
		t.Error("незавершённый повтор того же плана: хеш не должен совпасть, enforce применит заново")
	}
}

func TestApplyKeepsOneOwnToken(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.replies["pfctl -s References"] = []Result{{Out: refsOurs + "813      killswitchd                 18446744071234567892      5 secs ago\n"}}
	f.apply(onRules())
	if !f.run.called("pfctl -X 18446744071234567892") || f.run.called("pfctl -X 18446744071234567890") || f.run.called("killswitchd -E") {
		t.Errorf("два своих токена: лишний отпущен, первый оставлен, новый не берётся; вызовы %q", f.run.calls)
	}
}

func TestApplyInstallsDaemonOnce(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.fails["launchctl print system/"+Label] = true
	f.apply(onRules())
	plist, err := os.ReadFile(f.paths.Plist)
	if err != nil || string(plist) != Plist(f.paths.binary(), f.paths.Log) || !f.run.called("launchctl bootstrap system") {
		t.Errorf("Apply ставит plist и загружает LaunchDaemon: err=%v вызовы %q", err, f.run.calls)
	}
}

func TestRemoveReleasesOnlyOurTokensAndFiles(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	if err := f.b.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !f.run.called("pfctl -X 18446744071234567890") || f.run.called("pfctl -X 18446744071234567891") {
		t.Errorf("Remove отпускает только токены killswitchd, вызовы %q", f.run.calls)
	}
	if s := status(t, f.b); s.Active || !f.run.called("launchctl bootout system/"+Label) || !f.run.called("pfctl -a "+Anchor+" -F all") {
		t.Errorf("после Remove установки нет, якорь очищен, демон снят: %+v", s)
	}
}

func probeID() probe.ProbeID {
	return probe.ProbeID{Proto: "tcp", Src: netip.MustParseAddrPort("192.168.1.20:61000"), Dst: netip.MustParseAddrPort("1.1.1.1:80")}
}

func TestEvidenceWhenProbeRuleCounted(t *testing.T) {
	f := newFixture(t)
	f.run.on("pfctl -a "+Anchor+" -vsr", canaryCounters("3"), canaryCounters("4"))
	if err := f.b.BeforeProbe(probeID()); err != nil {
		t.Fatal(err)
	}
	if dropped, err := f.b.Evidence(probeID(), probeID().At); err != nil || !dropped {
		t.Errorf("счётчик правила порта пробы вырос — свидетельство, получено %t %v", dropped, err)
	}
}

func TestNoEvidenceWhenCounterSame(t *testing.T) {
	f := newFixture(t)
	f.run.on("pfctl -a "+Anchor+" -vsr", canaryCounters("3"))
	_ = f.b.BeforeProbe(probeID())
	if dropped, err := f.b.Evidence(probeID(), probeID().At); err != nil || dropped {
		t.Errorf("счётчик не вырос — свидетельства нет, получено %t %v", dropped, err)
	}
}

func TestEvidenceWithoutBeforeProbeIsError(t *testing.T) {
	f := newFixture(t)
	f.run.on("pfctl -a "+Anchor+" -vsr", canaryCounters("4"))
	if _, err := f.b.Evidence(probeID(), probeID().At); err == nil {
		t.Error("без снимка счётчика до пробы свидетельства не бывает")
	}
}

// Запись о загруженном наборе — только после сброса состояний: иначе сбой между загрузкой и сбросом
// выглядел бы для enforce как совпавший план, и чужие состояния пережили бы on.
func TestApplyFailedFlushLeavesDrift(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.run.fails["pfctl -F states"] = true
	r := onRules()
	if err := f.b.Apply(r); err == nil {
		t.Fatal("сбой сброса состояний — ошибка Apply")
	}
	if s := status(t, f.b); s.Hash == backend.HashOf(r) {
		t.Error("без сброса состояний хеш не должен совпасть с планом: enforce применит заново")
	}
}

func TestApplyCopiesBinaryForDaemon(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	f.apply(onRules())
	exe, _ := f.b.exe()
	want, _ := os.ReadFile(exe)
	got, err := os.ReadFile(f.paths.binary())
	if err != nil || string(got) != string(want) {
		t.Errorf("копия бинарника для LaunchDaemon: err=%v содержимое %q", err, got)
	}
}
