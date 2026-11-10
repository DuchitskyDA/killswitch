package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// elevateFunc — перезапуск команды от root после пароля в системном окне macOS.
var elevateFunc = elevate

// invoker — пользователь, открывший программу: окно откроет вкладку от его имени (SUDO_* в internal/window).
type invoker struct {
	UID, GID int
	Name     string
}

// osascriptRun выполняет строку sh от root через osascript и возвращает его вывод.
type osascriptRun func(shellCommand string) ([]byte, error)

// elevate перезапускает свой исполняемый файл с командой от root: пароль спрашивает системное окно.
func elevate(command string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	return elevateWith(runOsascript, exe, invoker{UID: os.Getuid(), GID: os.Getgid(), Name: u.Username}, command)
}

// elevateWith — строка sh в фоне (Apple TN2065: вывод перенаправлен и «&» — osascript вернётся сразу после
// пароля, команда живёт дальше). Без команды — меню: от root без терминала его не открыть, нужен sudo.
func elevateWith(run osascriptRun, exe string, u invoker, command string) error {
	if command == "" {
		return errors.New("меню работает в терминале: запустите sudo killswitch")
	}
	line := fmt.Sprintf("SUDO_UID=%d SUDO_GID=%d SUDO_USER=%s %s %s </dev/null >/dev/null 2>&1 &",
		u.UID, u.GID, shellQuote(u.Name), shellQuote(exe), shellQuote(command))
	out, err := run(line)
	if err == nil {
		return nil
	}
	reason := strings.TrimSpace(string(out))
	switch {
	case strings.Contains(reason, "(-128)"): // userCanceledErr: пользователь нажал «Отменить»
		reason = "ввод пароля отменён"
	case reason == "":
		reason = "osascript: " + err.Error()
	default:
		reason = "osascript: " + reason
	}
	return fmt.Errorf("%s; в терминале: sudo killswitch %s", reason, command)
}

// shellQuote — слово sh в одинарных кавычках: внутри них особых символов нет, кроме самой кавычки.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runOsascript передаёт строку sh аргументом скрипта: экранировать её для AppleScript не нужно.
func runOsascript(shellCommand string) ([]byte, error) {
	return exec.Command("/usr/bin/osascript",
		"-e", "on run argv",
		"-e", "do shell script (item 1 of argv) with administrator privileges",
		"-e", "end run",
		shellCommand).CombinedOutput()
}
