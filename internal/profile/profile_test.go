package profile

import (
	"testing"
	"testing/fstest"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/profiles"
)

func TestEmbeddedProfilesLoad(t *testing.T) {
	m, err := Load(profiles.FS)
	noErr(t, err)
	_, ok := m["wireguard"].Section("linux")
	eq(t, ok, true)
}

func TestParseVerifiedOn(t *testing.T) {
	p, err := Parse("wg", []byte("name = \"wg\"\n[[verified_on]]\nos = \"linux\"\nbackend = \"nft\"\nclient_version = \"1.0.0\"\ndate = \"2026-11-09\"\n"))
	noErr(t, err)
	eq(t, p.VerifiedOn, []Verification{{OS: "linux", Backend: "nft", ClientVersion: "1.0.0", Date: "2026-11-09"}})
}

func TestParseBadVerifiedDate(t *testing.T) {
	_, err := Parse("wg", []byte("name = \"wg\"\n[[verified_on]]\nos = \"linux\"\nbackend = \"nft\"\nclient_version = \"1\"\ndate = \"09.11.2026\"\n"))
	hasErr(t, err)
}

func TestParseUnknownKey(t *testing.T) {
	_, err := Parse("wg", []byte("name = \"wg\"\n[linux]\nprogramz = [\"x\"]\n"))
	hasErr(t, err)
}

func TestParseNameMismatch(t *testing.T) {
	_, err := Parse("wg", []byte("name = \"happ\"\n"))
	hasErr(t, err)
}

func TestLoadReportsBrokenFile(t *testing.T) {
	_, err := Load(fstest.MapFS{"bad.toml": {Data: []byte("name = ")}})
	hasErr(t, err)
}

func TestSectionLayerMapsSelectors(t *testing.T) {
	s := Section{Interfaces: []string{"wg0"}, Users: []string{"root"}, Marks: []string{"0xca6c"}, RepairPrograms: []string{"x"}}
	eq(t, s.Layer(), policy.Layer{Interfaces: []string{"wg0"}, RepairPrograms: []string{"x"},
		Trust: []policy.Trust{{Kind: policy.KindUser, Value: "root"}, {Kind: policy.KindMark, Value: "0xca6c"}}})
}
