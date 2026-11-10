package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// elevateFunc — перезапуск с повышением (UAC).
var elevateFunc = elevate

// isAdmin — процесс запущен с повышенными правами.
func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// elevate перезапускает killswitch через ShellExecute «runas»: без команды — меню (команда menu) в новом окне консоли;
// с командой (window) консоль свёрнута — она только держит сервер окна.
func elevate(command string) error {
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
	show := int32(windows.SW_SHOWMINNOACTIVE)
	if command == "" {
		// Меню — явной командой: новая консоль без аргументов выглядит как двойной клик, то есть установка.
		command, show = "menu", windows.SW_SHOWNORMAL
	}
	args, err := windows.UTF16PtrFromString(command)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, args, nil, show)
}

// isTerminal — stdin и stdout — консоль (конвейер, файл и NUL — нет).
func isTerminal() bool { return isConsole(os.Stdin) && isConsole(os.Stdout) }

func isConsole(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}
