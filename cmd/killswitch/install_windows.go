package main

import (
	"golang.org/x/sys/windows"

	install "github.com/DuchitskyDA/killswitch/internal/install/windows"
	"github.com/DuchitskyDA/killswitch/internal/state"
)

// installSelf — установка в %ProgramFiles%\killswitch: каталоги, служба, ярлык, запись в «Приложения».
func installSelf(enable func() error) error {
	l, err := install.System(state.DefaultDir("windows"))
	if err != nil {
		return err
	}
	return l.Install(enable)
}

// uninstallSelf — полное снятие: служба, правила (removeRules), ярлык, запись в «Приложения», файлы установки.
func uninstallSelf(removeRules func() error) error {
	l, err := install.System(state.DefaultDir("windows"))
	if err != nil {
		return err
	}
	return l.Uninstall(removeRules)
}

// alert — сообщение об ошибке окном: консоль установки свёрнута или уже закрылась.
func alert(msg string) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, _ := windows.UTF16PtrFromString("killswitch")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
}
