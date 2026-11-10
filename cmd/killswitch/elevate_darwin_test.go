package main

import (
	"errors"
	"strings"
	"testing"
)

// Тесты elevate macOS — на подменённом osascript: пароль и подпроцессы не нужны.

func TestElevateRunsQuotedCommandInBackgroundAsInvoker(t *testing.T) {
	var got string
	run := func(cmd string) ([]byte, error) { got = cmd; return nil, nil }
	exe := `/Users/o'neil/My "apps"/$HOME\x/Кс.app/Contents/MacOS/killswitch`
	err := elevateWith(run, exe, invoker{UID: 501, GID: 20, Name: "o'neil"}, "setup")
	noErr(t, err)
	eq(t, got, `SUDO_UID=501 SUDO_GID=20 SUDO_USER='o'\''neil' `+
		`'/Users/o'\''neil/My "apps"/$HOME\x/Кс.app/Contents/MacOS/killswitch' 'setup' </dev/null >/dev/null 2>&1 &`)
}

func TestElevateMenuAsksForSudoWithoutPasswordWindow(t *testing.T) {
	calls := 0
	run := func(string) ([]byte, error) { calls++; return nil, nil }
	err := elevateWith(run, "/x/killswitch", invoker{UID: 501, GID: 20, Name: "u"}, "")
	eq(t, calls, 0)
	eq(t, strings.Contains(err.Error(), "sudo killswitch"), true)
}

func TestElevateCancelledPasswordIsClearError(t *testing.T) {
	run := func(string) ([]byte, error) {
		return []byte("0:85: execution error: User canceled. (-128)\n"), errors.New("exit status 1")
	}
	err := elevateWith(run, "/x/killswitch", invoker{UID: 501, GID: 20, Name: "u"}, "window")
	eq(t, err.Error(), "ввод пароля отменён; в терминале: sudo killswitch window")
}

func TestElevateFailureKeepsOsascriptReasonAndSudoHint(t *testing.T) {
	run := func(string) ([]byte, error) {
		return []byte("execution error: No user interaction allowed. (-1713)\n"), errors.New("exit status 1")
	}
	err := elevateWith(run, "/x/killswitch", invoker{UID: 501, GID: 20, Name: "u"}, "window")
	eq(t, err.Error(), "osascript: execution error: No user interaction allowed. (-1713); в терминале: sudo killswitch window")
}

func TestElevateFuncIsSetOnDarwin(t *testing.T) {
	eq(t, elevateFunc != nil, true)
}
