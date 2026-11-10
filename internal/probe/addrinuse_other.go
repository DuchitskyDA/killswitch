//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

// addrInUse — адрес и порт сокета заняты.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
