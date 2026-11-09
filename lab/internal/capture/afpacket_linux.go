//go:build linux

package capture

import (
	"context"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Run захватывает все кадры интерфейса iface в текущем namespace (AF_PACKET), пока ctx жив.
// ready вызывается после bind: с этого момента ни один кадр интерфейса не теряется мимо сокета.
func Run(ctx context.Context, iface string, ready func(), emit func(Flow)) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return err
	}
	tv := unix.Timeval{Usec: 200000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	ready()
	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Ifindex != ifi.Index {
			continue
		}
		f, ok := ParseEthernet(buf[:n])
		if !ok {
			continue
		}
		f.Out = ll.Pkttype == unix.PACKET_OUTGOING
		emit(f)
	}
	return nil
}
