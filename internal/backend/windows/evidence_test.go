package windows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/probe"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func probeID() probe.ProbeID {
	return probe.ProbeID{Proto: "tcp", Src: netip.MustParseAddrPort("10.1.0.4:30000"),
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
	d.Local = netip.MustParseAddrPort("10.1.0.4:30001")
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

func TestMatchDropOtherSourceAddr(t *testing.T) {
	id := probeID()
	d := dropFor(id)
	d.Local = netip.MustParseAddrPort("10.1.0.5:30000")
	if MatchDrop(d, id, t0, map[uint64]bool{7: true}) {
		t.Error("другой адрес-источник — проба другого интерфейса")
	}
}

// fakeCollector — опция сбора событий WFP в памяти.
type fakeCollector struct {
	on   bool
	sets int
}

func (f *fakeCollector) CollectNetEvents() (bool, error) { return f.on, nil }
func (f *fakeCollector) SetCollectNetEvents(on bool) error {
	f.on = on
	f.sets++
	return nil
}

func TestCollectionRestoredWhenWeEnabledIt(t *testing.T) {
	c := &fakeCollector{}
	var st evidenceState
	if err := prepareCollection(c, &st); err != nil {
		t.Fatal(err)
	}
	finishCollection(c, &st)
	if c.on || c.sets != 2 {
		t.Errorf("сбор должен вернуться в выключенный: on=%v sets=%d", c.on, c.sets)
	}
}

func TestCollectionLeftOnWhenAlreadyOn(t *testing.T) {
	c := &fakeCollector{on: true}
	var st evidenceState
	if err := prepareCollection(c, &st); err != nil {
		t.Fatal(err)
	}
	finishCollection(c, &st)
	if !c.on || c.sets != 0 {
		t.Errorf("чужой включённый сбор не трогаем: on=%v sets=%d", c.on, c.sets)
	}
}
