//go:build !linux

package probe

import (
	"errors"
	"syscall"
)

func control(iface string, mark uint32) func(string, string, syscall.RawConn) error {
	if iface == "" && mark == 0 {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("SO_BINDTODEVICE и SO_MARK есть только в Linux")
	}
}
