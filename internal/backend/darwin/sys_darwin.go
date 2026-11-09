package darwin

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/DuchitskyDA/killswitch/internal/backend"
)

// bindControl привязывает сокет к интерфейсу: IP_BOUND_IF для v4, IPV6_BOUND_IF для v6.
func bindControl(index int) backend.ControlFunc {
	return func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
				return
			}
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
		})
		if err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("привязка к интерфейсу %d: %w", index, serr)
		}
		return nil
	}
}

// bootID — kern.boottime: время загрузки меняется только с новой загрузкой.
func bootID() (string, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return "", fmt.Errorf("kern.boottime: %w", err)
	}
	return fmt.Sprintf("%d.%06d", tv.Sec, tv.Usec), nil
}
