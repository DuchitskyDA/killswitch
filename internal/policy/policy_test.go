package policy

import (
	"net/netip"
	"testing"
)

func base() Policy {
	p, _ := Build(Layer{Interfaces: []string{"wg0"}}, Config{})
	return p.WithMode(ModeOn)
}

func build(t *testing.T, toml string, l Layer) Policy {
	t.Helper()
	c, err := ParseConfig([]byte(toml))
	noErr(t, err)
	p, err := Build(l, c)
	noErr(t, err)
	return p.WithMode(ModeOn)
}

var linux = CapabilitiesFor("linux")
var windows = CapabilitiesFor("windows")
var darwin = CapabilitiesFor("darwin")

func TestBuildDefaults(t *testing.T) {
	p := base()
	eq(t, p.LAN, true)
	eq(t, p.DNS, DNSOpen)
	eq(t, p.TrustMode, TrustCompat)
	noErr(t, p.Validate(linux))
}

func TestBuildConfigReplacesProfileLists(t *testing.T) {
	l := Layer{Interfaces: []string{"happ-*"}, Trust: []Trust{{Kind: KindUser, Value: "root"}}}
	p := build(t, "[tunnel]\ninterfaces = [\"wg0\"]\n[[trust]]\nkind = \"user\"\nvalue = \"tunnel\"\n", l)
	eq(t, p.Tunnel.Interfaces, []string{"wg0"})
	eq(t, p.Trust, []Trust{{Kind: KindUser, Value: "tunnel", Destinations: DestAny}})
}

func TestBuildProfileTrustDestinationsFollowStrict(t *testing.T) {
	l := Layer{Interfaces: []string{"wg0"}, Trust: []Trust{{Kind: KindUser, Value: "root"}}}
	p := build(t, "trust_mode = \"strict\"\n[tunnel]\nendpoints = [\"tunnel.example.org:51820/udp\"]\n", l)
	eq(t, p.Trust[0].Destinations, DestEndpoints)
	eq(t, p.Tunnel.Endpoints, []Endpoint{{Host: "tunnel.example.org", Port: 51820, Proto: ProtoUDP}})
	noErr(t, p.Validate(linux))
}

func TestParseConfigUnknownKey(t *testing.T) {
	_, err := ParseConfig([]byte("lan = true\nlna = false\n"))
	hasErr(t, err)
}

func TestBuildBadEndpoint(t *testing.T) {
	c, err := ParseConfig([]byte("[tunnel]\nendpoints = [\"1.2.3.4:51820\"]\n"))
	noErr(t, err)
	_, err = Build(Layer{}, c)
	hasErr(t, err)
}

func TestParseEndpointIPv6(t *testing.T) {
	e, err := ParseEndpoint("[2001:db8::1]:443/tcp")
	noErr(t, err)
	a, ok := e.Addr()
	eq(t, ok, true)
	eq(t, a, netip.MustParseAddr("2001:db8::1"))
	eq(t, e.String(), "[2001:db8::1]:443/tcp")
}

func TestParseHealthURL(t *testing.T) {
	h, err := ParseHealthURL("http://198.18.0.1:8080/generate_204")
	noErr(t, err)
	eq(t, h.Addr, netip.MustParseAddrPort("198.18.0.1:8080"))
	eq(t, h.Path, "/generate_204")
	_, err = ParseHealthURL("http://health.example.org:80/")
	hasErr(t, err)
}

func TestValidateTunnelUpNeedsHealth(t *testing.T) {
	p := base()
	p.DNS = DNSTunnelUp
	hasErr(t, p.Validate(linux))
}

func TestValidateResolversNeedList(t *testing.T) {
	p := base()
	p.DNS = DNSResolvers
	hasErr(t, p.Validate(linux))
}

func TestValidateResolversListWithOtherMode(t *testing.T) {
	p := base()
	p.Resolvers = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}
	hasErr(t, p.Validate(linux))
}

func TestValidateStrictWithoutEndpoints(t *testing.T) {
	p := base()
	p.TrustMode = TrustStrict
	hasErr(t, p.Validate(linux))
}

func TestValidateStrictWithAnyDestinations(t *testing.T) {
	p := build(t, "trust_mode = \"strict\"\n[tunnel]\nendpoints = [\"203.0.113.2:443/udp\"]\n"+
		"[[trust]]\nkind = \"user\"\nvalue = \"root\"\ndestinations = \"any\"\n", Layer{Interfaces: []string{"wg0"}})
	hasErr(t, p.Validate(linux))
}

func TestValidateUserTrustOnWindows(t *testing.T) {
	p := base()
	p.Trust = []Trust{{Kind: KindUser, Value: "root", Destinations: DestAny}}
	hasErr(t, p.Validate(windows))
}

func TestValidateProgramTrustOnLinux(t *testing.T) {
	p := base()
	p.Trust = []Trust{{Kind: KindProgram, Value: "/usr/bin/sing-box", Destinations: DestAny}}
	hasErr(t, p.Validate(linux))
}

func TestValidateRepairUnsupportedOnLinuxAndDarwin(t *testing.T) {
	p := base().WithMode(ModeRepair)
	p.Repair.Programs = []string{"/usr/bin/curl"}
	hasErr(t, p.Validate(linux))
	hasErr(t, p.Validate(darwin))
}

func TestValidateRepairWindowsNeedsPrograms(t *testing.T) {
	p := base().WithMode(ModeRepair)
	hasErr(t, p.Validate(windows))
	p.Repair.Programs = []string{`C:\Program Files\Happ\*.exe`}
	noErr(t, p.Validate(windows))
}

func TestValidateRepairWindowsAcceptsNamesAlone(t *testing.T) {
	p := base().WithMode(ModeRepair)
	p.Repair.Names = []string{"node"}
	noErr(t, p.Validate(windows))
}

func TestBuildReadsRepairNames(t *testing.T) {
	p := build(t, "[repair]\nnames = ['node', 'python3.12']\n", Layer{Interfaces: []string{"wg0"}})
	eq(t, p.Repair.Names, []string{"node", "python3.12"})
	noErr(t, p.Validate(windows))
}

// Имя — без пути, расширения и знаков шаблона: по нему утилита сама строит шаблоны мест установки.
func TestValidateRejectsBadProgramNames(t *testing.T) {
	for _, name := range []string{"", " node", `bin\node`, "bin/node", "C:node", "node*", "no?e", "node[1]", "node.exe", "Node.EXE"} {
		p := base()
		p.Repair.Names = []string{name}
		if p.Validate(windows) == nil {
			t.Errorf("имя %q принято", name)
		}
	}
}

func TestValidateNoTunnelInterfaces(t *testing.T) {
	p := base()
	p.Tunnel.Interfaces = nil
	hasErr(t, p.Validate(linux))
}

func TestDNSPermitsOpen(t *testing.T) {
	p := base()
	eq(t, p.DNSPermits(true), DNSPermits{LAN: true, DHCP: true})
}

func TestDNSPermitsTunnelUpWhenDown(t *testing.T) {
	p := base()
	p.DNS = DNSTunnelUp
	eq(t, p.DNSPermits(false), DNSPermits{LAN: true, DHCP: true})
}

func TestDNSPermitsTunnelUpWhenUp(t *testing.T) {
	p := base()
	p.DNS = DNSTunnelUp
	eq(t, p.DNSPermits(true), DNSPermits{})
}

func TestDNSPermitsResolversIgnoreLANFlag(t *testing.T) {
	p := base()
	p.DNS, p.LAN = DNSResolvers, false
	p.Resolvers = []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}
	eq(t, p.DNSPermits(false), DNSPermits{Listed: p.Resolvers})
}
