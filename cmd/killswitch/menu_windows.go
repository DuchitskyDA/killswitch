package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// elevateFunc — перезапуск с повышением (UAC).
var elevateFunc = elevate

// isAdmin — процесс запущен с повышенными правами.
func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// elevate перезапускает killswitch без аргументов через ShellExecute «runas»: меню откроется в новом окне.
func elevate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// isTerminal — stdin и stdout — консоль (конвейер, файл и NUL — нет).
func isTerminal() bool { return isConsole(os.Stdin) && isConsole(os.Stdout) }

func isConsole(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}
