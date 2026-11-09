package darwin

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseReferencesSkipsHeader(t *testing.T) {
	got := parseReferences(refsOurs)
	want := []ref{{PID: 812, Name: "killswitchd", Token: "18446744071234567890"}, {PID: 430, Name: "pfctl", Token: "18446744071234567891"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("References: %+v", got)
	}
}

func TestParseTokenFromEnable(t *testing.T) {
	if got := parseToken("No ALTQ support in kernel\npf enabled\nToken : 18446744071234567890\n"); got != "18446744071234567890" {
		t.Errorf("токен из pfctl -E: %q", got)
	}
}

func TestPfEnabledReadsStatusLine(t *testing.T) {
	if !pfEnabled(infoEnabled) || pfEnabled(infoDisabled) {
		t.Error("Status: Enabled / Disabled")
	}
}

func TestMainFilterSkipsScrub(t *testing.T) {
	rules := mainFilter(mainDefault)
	if len(rules) != 1 || !isAnchorPoint(rules[0]) {
		t.Errorf("первое правило фильтра штатного набора — anchor com.apple/*, получено %q", rules)
	}
}

func TestLabelPacketsByRule(t *testing.T) {
	got := labelPackets(canaryCounters("7"))
	if got[canaryLabel] != 7 || got[probeLabel("tcp", 30000)] != 7 || len(got) != 2 {
		t.Errorf("счётчики по label: %v", got)
	}
}

func TestAnchorChildrenNames(t *testing.T) {
	got := anchorChildren("  com.apple/000.killswitch\n  com.apple/250.ApplicationFirewall\n")
	if !reflect.DeepEqual(got, []string{"000.killswitch", "250.ApplicationFirewall"}) {
		t.Errorf("дети com.apple: %q", got)
	}
}

func TestHardwarePortsDevices(t *testing.T) {
	out := "\nHardware Port: Ethernet\nDevice: en0\nEthernet Address: 00:11\n\nHardware Port: Wi-Fi\nDevice: en1\nEthernet Address: 00:12\n"
	if got := hardwarePorts(out); !reflect.DeepEqual(got, map[string]string{"en0": "Ethernet", "en1": "Wi-Fi"}) {
		t.Errorf("аппаратные порты: %v", got)
	}
}

func TestRouteInterface(t *testing.T) {
	out := "   route to: 1.1.1.1\ndestination: default\n    gateway: 192.168.1.1\n  interface: utun4\n      flags: <UP,GATEWAY,DONE>\n"
	if got := routeInterface(out); got != "utun4" {
		t.Errorf("интерфейс маршрута: %q", got)
	}
}

func TestScopedResolversOnlyPhysical(t *testing.T) {
	out := `DNS configuration

resolver #1
  nameserver[0] : 100.64.0.1
  if_index : 21 (utun4)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 6 (en0)

resolver #2
  nameserver[0] : 100.64.0.1
  if_index : 21 (utun4)
`
	got := scopedResolvers(out, map[string]bool{"en0": true})
	want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("резолверы физики: %v", got)
	}
}

func TestPlistGolden(t *testing.T) {
	golden(t, "launchd.plist", Plist("/Library/Application Support/killswitch/killswitch", "/var/log/killswitch.log"))
}
