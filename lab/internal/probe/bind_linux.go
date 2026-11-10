//go:build linux

package probe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// control привязывает сокет к интерфейсу (проба строго через физику, мимо маршрута в туннель) и ставит fwmark
// (проба от имени доверенной метки). Пустой iface и mark = 0 — без настройки.
func control(iface string, mark uint32) func(string, string, syscall.RawConn) error {
	if iface == "" && mark == 0 {
		return nil
	}
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			if iface != "" {
				serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}
			if serr == nil && mark != 0 {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
		}); err != nil {
			return err
		}
		return serr
	}
}
