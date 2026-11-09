//go:build linux || darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// elevateFunc: повышения нет — меню просит запустить через sudo.
var elevateFunc func() error

// isAdmin — процесс работает от root.
func isAdmin() bool { return os.Geteuid() == 0 }

// isTerminal — stdin и stdout — терминал (конвейер, файл и /dev/null — нет).
func isTerminal() bool { return isTTY(os.Stdin) && isTTY(os.Stdout) }

func isTTY(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), termiosRequest)
	return err == nil
}
