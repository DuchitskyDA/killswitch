package windows

import (
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
	return ours[d.FilterID] && !d.At.Before(since.Add(-clockSlack)) && d.Proto == proto &&
		remote == dst && d.Local.Port() == id.Src.Port()
}
