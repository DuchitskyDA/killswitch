package windows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/probe"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func probeID() probe.ProbeID {
	return probe.ProbeID{Proto: "tcp", Src: netip.MustParseAddrPort("10.1.0.4:61000"),
		Dst: netip.MustParseAddrPort("1.1.1.1:80"), Iface: "Ethernet", At: t0}
}

func dropFor(id probe.ProbeID) Drop {
	return Drop{At: t0.Add(200 * time.Millisecond), Proto: ProtoTCP, Local: id.Src, Remote: id.Dst, FilterID: 7}
}

func TestMatchDropOurFilter(t *testing.T) {
	id := probeID()
	if !MatchDrop(dropFor(id), id, t0, map[uint64]bool{7: true}) {
		t.Error("отброс пробы нашим фильтром должен совпасть")
	}
}

func TestMatchDropForeignFilter(t *testing.T) {
	id := probeID()
	if MatchDrop(dropFor(id), id, t0, map[uint64]bool{8: true}) {
		t.Error("отброс чужим фильтром — не наше свидетельство")
	}
}

func TestMatchDropOtherSourcePort(t *testing.T) {
	id := probeID()
	d := dropFor(id)
	d.Local = netip.MustParseAddrPort("10.1.0.4:61001")
	if MatchDrop(d, id, t0, map[uint64]bool{7: true}) {
		t.Error("другой порт-источник — другая проба")
	}
}

func TestMatchDropBeforeSince(t *testing.T) {
	id := probeID()
	d := dropFor(id)
	d.At = t0.Add(-5 * time.Second)
	if MatchDrop(d, id, t0, map[uint64]bool{7: true}) {
		t.Error("событие раньше пробы — не её свидетельство")
	}
}
