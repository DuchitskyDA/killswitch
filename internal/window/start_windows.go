package window

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// start запускает браузер. Сервер окна работает с правами администратора, браузеру они не нужны:
// дочерний процесс создаётся от имени оболочки рабочего стола и получает её обычные права.
// Оболочки нет, она принадлежит другому пользователю или процесс от неё не создался — запуск напрямую.
func start(c Command) error {
	if c.Unelevated {
		if shell, err := shellProcess(); err == nil {
			defer windows.CloseHandle(shell)
			cmd := exec.Command(c.Path, c.Args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{ParentProcess: syscall.Handle(shell)}
			if cmd.Start() == nil {
				return settle(cmd)
			}
		}
	}
	return run(exec.Command(c.Path, c.Args...))
}

// shellProcess — процесс оболочки рабочего стола того же пользователя, с правом создавать от него процессы.
func shellProcess() (windows.Handle, error) {
	hwnd := windows.GetShellWindow()
	if hwnd == 0 {
		return 0, errors.New("оболочка рабочего стола не запущена")
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil {
		return 0, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS|windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	if !ownedByCurrentUser(h) {
		windows.CloseHandle(h)
		return 0, errors.New("оболочка рабочего стола принадлежит другому пользователю")
	}
	return h, nil
}

func ownedByCurrentUser(process windows.Handle) bool {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	shell, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	own, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return windows.EqualSid(shell.User.Sid, own.User.Sid)
}
