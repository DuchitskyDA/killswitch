package windows

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// Drop — событие отброса WFP (classify drop).
type Drop struct {
	At            time.Time
	Proto         uint8
	Local, Remote netip.AddrPort
	FilterID      uint64
}

// clockSlack — допуск на расхождение метки события и времени пробы.
const clockSlack = time.Second

// MatchDrop: событие — отброс пробы id нашим block-фильтром (ours — рабочие id наших block) не раньше since.
func MatchDrop(d Drop, id probe.ProbeID, since time.Time, ours map[uint64]bool) bool {
	proto := ProtoUDP
	if id.Proto == "tcp" {
		proto = ProtoTCP
	}
	remote := netip.AddrPortFrom(d.Remote.Addr().Unmap(), d.Remote.Port())
	dst := netip.AddrPortFrom(id.Dst.Addr().Unmap(), id.Dst.Port())
	src := id.Src.Addr().Unmap()
	sameSrc := !src.IsValid() || src.IsUnspecified() || d.Local.Addr().Unmap() == src
	return ours[d.FilterID] && !d.At.Before(since.Add(-clockSlack)) && d.Proto == proto &&
		remote == dst && d.Local.Port() == id.Src.Port() && sameSrc
}

// collector — опция движка WFP «сбор событий отброса».
type collector interface {
	CollectNetEvents() (bool, error)
	SetCollectNetEvents(on bool) error
}

// evidenceState — включали ли мы сбор событий сами (тогда выключаем после пробы).
type evidenceState struct {
	enabledByUs bool
}

// prepareCollection включает сбор событий на время пробы, запоминая, что включили сами.
func prepareCollection(c collector, st *evidenceState) error {
	on, err := c.CollectNetEvents()
	if err != nil {
		return fmt.Errorf("опция сбора событий WFP: %w", err)
	}
	if on {
		return nil
	}
	if err := c.SetCollectNetEvents(true); err != nil {
		return fmt.Errorf("включить сбор событий WFP: %w", err)
	}
	st.enabledByUs = true
	return nil
}

// finishCollection возвращает сбор в исходное состояние: выключает, только если включил prepareCollection.
func finishCollection(c collector, st *evidenceState) {
	if st.enabledByUs && c.SetCollectNetEvents(false) == nil {
		st.enabledByUs = false
	}
}
