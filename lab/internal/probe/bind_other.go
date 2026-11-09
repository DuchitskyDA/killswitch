//go:build !linux

package probe

import (
	"errors"
	"syscall"
)

func bindControl(iface string) func(string, string, syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("SO_BINDTODEVICE есть только в Linux")
	}
}
