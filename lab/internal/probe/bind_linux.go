//go:build linux

package probe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindControl привязывает сокет к интерфейсу: так проба идёт строго через физику, мимо маршрута в туннель.
func bindControl(iface string) func(string, string, syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}
}
