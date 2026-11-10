package ui

import (
	"errors"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Настройки Windows: 1 клиент, 2 LAN, 3 DNS, 4 строгий, 5 доверенные, 6 починка, 7 проверка, 8 применить, 0 назад.
// Linux и macOS — без починки: 6 проверка, 7 применить. Вход в настройки: Windows 5, Linux и macOS 4.
// Хвост «8, 0, 0» — применить, назад, выход.

var saveAndExit = []string{"8", "0", "0"}

func steps(head ...string) []string { return append(head, saveAndExit...) }

func TestLANToggleSaved(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "2")...)
	eq(t, f.lastSaved(t).LAN, ptrTo(false))
}

func TestBackWithoutSaveDiscards(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("windows", f, "5", "2", "0", "1", "0")
	contains(t, out, "Изменения не сохранены.", true)
	eq(t, len(f.saved), 0)
}

func TestBackCanStayAndSave(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, "5", "2", "0", "0", "8", "0", "0")
	eq(t, len(f.saved), 1)
}

func TestSaveErrorShownAndEditsKept(t *testing.T) {
	f := &fakeActions{saveErr: errInvalid}
	out := runMenu("windows", f, "5", "2", "8", "0", "1", "0")
	contains(t, out, "не сохранено: trust_mode = strict", true)
	contains(t, out, "Изменения не сохранены.", true)
}

func TestSavedButNotAppliedClearsEdits(t *testing.T) {
	f := &fakeActions{saveErr: errors.New("применение on: отказ"), savedMsg: "сохранено, но не применено"}
	out := runMenu("windows", f, "5", "2", "8", "0", "0")
	contains(t, out, "сохранено, но не применено\nприменение on: отказ", true)
	contains(t, out, "Изменения не сохранены.", false)
}

func TestDetectSetsProfile(t *testing.T) {
	f := &fakeActions{detected: []string{"happ", "unknown"}}
	runMenu("windows", f, steps("5", "1", "1", "0")...)
	eq(t, f.lastSaved(t).Profile, "happ")
}

func TestDetectNothingFound(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("windows", f, "5", "1", "1", "0", "0", "0")
	contains(t, out, "установленные клиенты не найдены", true)
}

func TestPickProfileFromList(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "1", "2", "2", "0")...)
	eq(t, f.lastSaved(t).Profile, "wireguard")
}

func TestProfileChangeDropsListEqualToOldProfile(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n[tunnel]\ninterfaces = [\"happ-xray\"]\n")}
	out := runMenu("windows", f, steps("5", "1", "2", "2", "0")...)
	contains(t, out, "заданы вручную", false)
	eq(t, f.lastSaved(t).Tunnel.Interfaces, (*[]string)(nil))
}

func TestProfileChangeKeepsOwnListOnRequest(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n[tunnel]\ninterfaces = [\"my-tun\"]\n")}
	runMenu("windows", f, steps("5", "1", "2", "2", "1", "0")...)
	got := f.lastSaved(t)
	eq(t, got.Profile, "wireguard")
	eq(t, got.Tunnel.Interfaces, &[]string{"my-tun"})
}

func TestProfileChangeTakesNewTrustByDefault(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n[[trust]]\nkind = \"program\"\nvalue = 'C:\\own.exe'\n")}
	runMenu("windows", f, steps("5", "1", "2", "2", "0", "0")...)
	_, set := f.lastSaved(t).TrustEntries()
	eq(t, set, false)
}

func TestWithoutProfileKeepsEffectiveLists(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n")}
	runMenu("windows", f, steps("5", "1", "2", "3", "0")...)
	got := f.lastSaved(t)
	trust, _ := got.TrustEntries()
	eq(t, got.Tunnel.Interfaces, &[]string{"happ-xray"})
	eq(t, trust, []policy.Trust{{Kind: policy.KindProgram, Value: happExe}})
}

func TestInterfacesEditStartsFromProfile(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n")}
	runMenu("windows", f, steps("5", "1", "3", "1", "wg9", "0", "0")...)
	eq(t, f.lastSaved(t).Tunnel.Interfaces, &[]string{"happ-xray", "wg9"})
}

func TestInterfacesBackToProfile(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n[tunnel]\ninterfaces = [\"x\"]\n")}
	runMenu("windows", f, steps("5", "1", "3", "3", "0", "0")...)
	eq(t, f.lastSaved(t).Tunnel.Interfaces, (*[]string)(nil))
}

func TestDNSTunnelUpSetsHealth(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "3", "2", "http://198.18.0.1:80/")...)
	got := f.lastSaved(t)
	eq(t, got.DNS.Mode, ptrTo("tunnel-up"))
	eq(t, got.DNS.Health, ptrTo("http://198.18.0.1:80/"))
}

func TestDNSTunnelUpRejectsBadURL(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("windows", f, "5", "3", "2", "ftp://x", "0", "0")
	contains(t, out, "не принято: dns.health", true)
	eq(t, len(f.saved), 0)
}

func TestDNSResolversSetsModeAndList(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "3", "3", "1", "192.0.2.53", "0")...)
	got := f.lastSaved(t)
	eq(t, got.DNS.Mode, ptrTo("resolvers"))
	eq(t, got.DNS.Resolvers, &[]string{"192.0.2.53"})
}

func TestDNSOpenClearsResolvers(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "[dns]\nmode = \"resolvers\"\nresolvers = [\"192.0.2.53\"]\n")}
	runMenu("windows", f, steps("5", "3", "1")...)
	got := f.lastSaved(t)
	eq(t, got.DNS.Mode, ptrTo("open"))
	eq(t, got.DNS.Resolvers, (*[]string)(nil))
}

func TestStrictWithEndpoint(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "4", "1", "2", "1", "192.0.2.1:443/tcp", "0", "0")...)
	got := f.lastSaved(t)
	eq(t, got.TrustMode, ptrTo("strict"))
	eq(t, got.Tunnel.Endpoints, &[]string{"192.0.2.1:443/tcp"})
}

func TestStrictWithoutEndpointWarns(t *testing.T) {
	out := runMenu("windows", &fakeActions{}, "5", "4", "1")
	contains(t, out, "добавьте хотя бы один сервер туннеля", true)
}

func TestEndpointRejected(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("windows", f, "5", "4", "2", "1", "192.0.2.1:443", "0", "0", "0", "0")
	contains(t, out, "не принято: endpoint", true)
	eq(t, len(f.saved), 0)
}

func TestTrustAddProgramOnWindows(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n")}
	out := runMenu("windows", f, steps("5", "5", "1", `C:\x.exe`, "2", "0")...)
	trust, _ := f.lastSaved(t).TrustEntries()
	eq(t, trust, []policy.Trust{{Kind: policy.KindProgram, Value: happExe},
		{Kind: policy.KindProgram, Value: `C:\x.exe`, Destinations: policy.DestEndpoints}})
	contains(t, out, "Вид:", false)
}

func TestTrustKindsOnLinux(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("linux", f, "4", "5", "1", "3", "0xca6c", "1", "0", "7", "0", "0")
	trust, _ := f.lastSaved(t).TrustEntries()
	eq(t, trust, []policy.Trust{{Kind: policy.KindMark, Value: "0xca6c"}})
	contains(t, out, "программа", false)
}

func TestTrustOnlyUserOnDarwin(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("darwin", f, "4", "5", "1", "root", "1", "0", "7", "0", "0")
	trust, _ := f.lastSaved(t).TrustEntries()
	eq(t, trust, []policy.Trust{{Kind: policy.KindUser, Value: "root"}})
	contains(t, out, "cgroup", false)
}

func TestTrustRemoveLeavesExplicitEmpty(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "profile = \"happ\"\n")}
	runMenu("windows", f, steps("5", "5", "2", "1", "0")...)
	trust, set := f.lastSaved(t).TrustEntries()
	eq(t, set, true)
	eq(t, len(trust), 0)
}

func TestRepairProgramsOnWindows(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "6", "1", `C:\claude.exe`, "0")...)
	eq(t, f.lastSaved(t).Repair.Programs, &[]string{`C:\claude.exe`})
}

func TestRepairHiddenInSettingsOnDarwin(t *testing.T) {
	out := runMenu("darwin", &fakeActions{}, "4", "0", "0")
	contains(t, out, "починке", false)
}

func TestCheckTargetsAdd(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, steps("5", "7", "1", "203.0.113.1", "0")...)
	eq(t, f.lastSaved(t).Check.Targets, &[]string{"203.0.113.1"})
}

func TestCheckTargetRejectsName(t *testing.T) {
	out := runMenu("windows", &fakeActions{}, "5", "7", "1", "example.com", "0", "0", "0")
	contains(t, out, "не принято: нужен IP-адрес", true)
}

func TestTrustAddInStrictOnlyToEndpoints(t *testing.T) {
	f := &fakeActions{cfg: cfgWith(t, "trust_mode = \"strict\"\n[tunnel]\nendpoints = [\"192.0.2.1:443/tcp\"]\n")}
	runMenu("windows", f, steps("5", "5", "1", `C:\x.exe`, "0")...)
	p, err := policy.Build(policy.Layer{Interfaces: []string{"wg0"}}, f.lastSaved(t))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, p.WithMode(policy.ModeOn).Validate(policy.CapabilitiesFor("windows")), nil)
	eq(t, p.Trust, []policy.Trust{{Kind: policy.KindProgram, Value: `C:\x.exe`, Destinations: policy.DestEndpoints}})
}

// Решение владельца «Описать ограничение»: при выборе tunnel-up на Linux меню предупреждает про sing-box auto_redirect.
const autoRedirectHint = "с sing-box auto_redirect режим tunnel-up не поднимается — используйте open или свои резолверы"

func TestDNSTunnelUpOnLinuxWarnsAutoRedirect(t *testing.T) {
	out := runMenu("linux", &fakeActions{}, "4", "3", "2", "", "0", "0", "0", "0")
	contains(t, out, autoRedirectHint, true)
}

func TestDNSTunnelUpOnWindowsWithoutAutoRedirectHint(t *testing.T) {
	out := runMenu("windows", &fakeActions{}, "5", "3", "2", "", "0", "0", "0", "0")
	contains(t, out, autoRedirectHint, false)
}

func TestDNSTunnelUpOnDarwinWithoutAutoRedirectHint(t *testing.T) {
	out := runMenu("darwin", &fakeActions{}, "4", "3", "2", "", "0", "0", "0", "0")
	contains(t, out, autoRedirectHint, false)
}
