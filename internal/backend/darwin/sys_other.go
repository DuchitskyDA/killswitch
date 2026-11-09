//go:build !darwin

package darwin

import (
	"errors"
	"syscall"

	"github.com/DuchitskyDA/killswitch/internal/backend"
)

// Вне macOS пакет собирается ради эталонных тестов; системных вызовов нет.
var errNotDarwin = errors.New("pf-backend работает только на macOS")

func bindControl(int) backend.ControlFunc {
	return func(string, string, syscall.RawConn) error { return errNotDarwin }
}

func bootID() (string, error) { return "", errNotDarwin }
