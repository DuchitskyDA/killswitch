//go:build unix

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LockName — отдельный файл замка: state.json заменяется rename, и flock на нём терялся бы.
func LockName(dir string) string { return filepath.Join(dir, "state.lock") }

// Acquire берёт flock на файле name. Замок снимается ядром при смерти процесса.
func Acquire(name string, wait bool) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("flock %s: %w", name, err)
	}
	return &Lock{release: func() error {
		uerr := unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return errors.Join(uerr, f.Close())
	}}, nil
}
