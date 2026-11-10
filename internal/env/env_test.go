package env

import (
	"net/netip"
	"testing"
)

func names(ifs []Iface) []string {
	out := []string{}
	for _, i := range ifs {
		out = append(out, i.Name)
	}
	return out
}

func TestMatchIfacesByDescriptionCaseInsensitiveOnWindows(t *testing.T) {
	e := Env{OS: "windows", Ifaces: []Iface{
		{Name: "Ethernet", Description: "Intel(R) Ethernet"},
		{Name: "Local Area Connection 2", Description: "Happ Tunnel"},
	}}
	eq(t, names(e.MatchIfaces([]string{"happ tunnel*"})), []string{"Local Area Connection 2"})
}

func TestMatchIfacesCaseSensitiveOnLinux(t *testing.T) {
	e := Env{OS: "linux", Ifaces: []Iface{{Name: "wg0"}, {Name: "WG1"}, {Name: "eth0"}}}
	eq(t, names(e.MatchIfaces([]string{"wg*"})), []string{"wg0"})
}

func TestMatchIfacesEmptyAliasDoesNotMatchStar(t *testing.T) {
	e := Env{OS: "linux", Ifaces: []Iface{{Name: "eth0"}}}
	eq(t, names(e.MatchIfaces([]string{"wg*"})), []string{})
}

func TestWithLastKnownFallsBackToStored(t *testing.T) {
	last := map[string][]netip.Addr{"tunnel.example.org": {netip.MustParseAddr("203.0.113.2")}}
	e := Env{ResolveErr: map[string]string{"tunnel.example.org": "timeout"}}
	got, warns := WithLastKnown(e, last)
	eq(t, got.Resolved["tunnel.example.org"], last["tunnel.example.org"])
	eq(t, len(warns), 1)
}

func TestWithLastKnownNoStoredAllowsNothing(t *testing.T) {
	e := Env{Resolved: map[string][]netip.Addr{}, ResolveErr: map[string]string{"tunnel.example.org": "nxdomain"}}
	got, warns := WithLastKnown(e, nil)
	eq(t, len(got.Resolved["tunnel.example.org"]), 0)
	eq(t, len(warns), 1)
}

func TestSourceAddrIgnoresLinkLocalV6(t *testing.T) {
	i := Iface{Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.5/24"), netip.MustParsePrefix("fe80::1/64")}}
	v4, ok4 := i.SourceAddr(true)
	_, ok6 := i.SourceAddr(false)
	eq(t, v4, netip.MustParseAddr("192.0.2.5"))
	eq(t, ok4, true)
	eq(t, ok6, false)
}
