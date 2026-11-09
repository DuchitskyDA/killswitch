package windows

import (
	"encoding/binary"
	"strings"
	"syscall"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	xwin "golang.org/x/sys/windows"
)

// IP_UNICAST_IF и IPV6_UNICAST_IF (ws2ipdef.h).
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// BindControl привязывает сокет к интерфейсу: IP_UNICAST_IF (индекс в сетевом порядке) или IPV6_UNICAST_IF.
func (b *Backend) BindControl(iface env.Iface) backend.ControlFunc {
	idx := uint32(iface.Index)
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			h := xwin.Handle(fd)
			if strings.HasSuffix(network, "6") {
				serr = xwin.SetsockoptInt(h, xwin.IPPROTO_IPV6, ipv6UnicastIf, int(idx))
				return
			}
			var be [4]byte
			binary.BigEndian.PutUint32(be[:], idx)
			serr = xwin.SetsockoptInt(h, xwin.IPPROTO_IP, ipUnicastIf, int(binary.LittleEndian.Uint32(be[:])))
		})
		if err != nil {
			return err
		}
		return serr
	}
}
