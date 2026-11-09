//go:build !linux

package linux

import (
	"errors"
	"syscall"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
)

var errNotLinux = errors.New("backend linux работает только на linux")

// BindControl: вне linux привязки нет.
func (b *Backend) BindControl(env.Iface) backend.ControlFunc {
	return func(string, string, syscall.RawConn) error { return errNotLinux }
}

// Changes: вне linux событий нет.
func (b *Backend) Changes() <-chan struct{} { return nil }
