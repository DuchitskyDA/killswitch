package policy

import "testing"

func roundTrip(t *testing.T, c Config) Config {
	t.Helper()
	data, err := Encode(c)
	noErr(t, err)
	got, err := ParseConfig(data)
	noErr(t, err)
	return got
}

func ptr[T any](v T) *T { return &v }

func TestEncodeEmptyConfigRoundTrips(t *testing.T) {
	eq(t, roundTrip(t, Config{}), Config{})
}

func TestEncodeFullConfigRoundTrips(t *testing.T) {
	c := Config{
		Profile:   "happ",
		LAN:       ptr(false),
		TrustMode: ptr("strict"),
		Tunnel: configTunnel{Interfaces: ptr([]string{"happ-xray", "wg*"}),
			Endpoints: ptr([]string{"[2001:db8::1]:443/tcp", "tunnel.example.org:51820/udp"})},
		DNS: configDNS{Mode: ptr("resolvers"), Resolvers: ptr([]string{"192.0.2.53", "198.51.100.0/24"}),
			Health: ptr("http://198.18.0.1:80/health")},
		Repair: configRepair{Programs: ptr([]string{`C:\Users\user\AppData\Local\app\app.exe`})},
		Check:  configCheck{Targets: ptr([]string{"203.0.113.130"})},
	}
	c.SetTrust([]Trust{{Kind: KindProgram, Value: `C:\Program Files\Happ\Happ.exe`, Destinations: DestEndpoints},
		{Kind: KindProgram, Value: `C:\Program Files\Happ\core\xray.exe`}})
	eq(t, roundTrip(t, c), c)
}

func TestEncodeEmptyListsStayExplicit(t *testing.T) {
	c := Config{Tunnel: configTunnel{Interfaces: ptr([]string{})}, Repair: configRepair{Programs: ptr([]string{})}}
	c.SetTrust([]Trust{})
	got := roundTrip(t, c)
	entries, ok := got.TrustEntries()
	eq(t, ok, true)
	eq(t, len(entries), 0)
	eq(t, got, c)
}

func TestSetTrustNilRemovesKey(t *testing.T) {
	c := Config{}
	c.SetTrust([]Trust{{Kind: KindUser, Value: "root"}})
	c.SetTrust(nil)
	_, ok := roundTrip(t, c).TrustEntries()
	eq(t, ok, false)
}

func TestEncodeSkipsEmptyTables(t *testing.T) {
	data, err := Encode(Config{Profile: "happ", LAN: ptr(true)})
	noErr(t, err)
	eq(t, string(data), "profile = \"happ\"\nlan = true\n")
}
