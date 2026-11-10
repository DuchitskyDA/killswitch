package window

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Запуск окна проверяется на подставной функции запуска процесса: браузер в тестах не стартует.

const testURL = "http://127.0.0.1:49152/open?key=abc"

type fakeHost struct {
	env      map[string]string
	files    []string
	homes    map[uint32]string
	started  []Command
	startErr error
}

func (f *fakeHost) host(goos string) Host {
	return Host{
		GOOS:   goos,
		Getenv: func(k string) string { return f.env[k] },
		Exists: func(p string) bool { return slices.Contains(f.files, p) },
		Home:   func(uid uint32) string { return f.homes[uid] },
		Start: func(c Command) error {
			f.started = append(f.started, c)
			return f.startErr
		},
	}
}

var windowsEnv = map[string]string{
	"ProgramFiles(x86)": `C:\Program Files (x86)`,
	"ProgramFiles":      `C:\Program Files`,
	"LOCALAPPDATA":      `C:\Users\user\AppData\Local`,
	"SystemRoot":        `C:\Windows`,
}

func edgeArgs(url string) []string {
	return []string{"--app=" + url, `--user-data-dir=C:\Users\user\AppData\Local\killswitch\window`,
		"--window-size=460,700", "--no-first-run", "--no-default-browser-check"}
}

func TestWindowsOpensEdgeAppWindow(t *testing.T) {
	for _, edge := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Users\user\AppData\Local\Microsoft\Edge\Application\msedge.exe`,
	} {
		f := &fakeHost{env: windowsEnv, files: []string{edge}}
		noErr(t, f.host("windows").Open(testURL))
		eq(t, f.started, []Command{{Path: edge, Args: edgeArgs(testURL), Unelevated: true}})
	}
}

func TestWindowsWithoutEdgeOpensDefaultBrowser(t *testing.T) {
	f := &fakeHost{env: windowsEnv}
	noErr(t, f.host("windows").Open(testURL))
	eq(t, f.started, []Command{{Path: `C:\Windows\System32\rundll32.exe`,
		Args: []string{"url.dll,FileProtocolHandler", testURL}, Unelevated: true}})
}

func TestWindowSizeIsOneConstant(t *testing.T) {
	eq(t, WindowWidth, 460)
	eq(t, WindowHeight, 700)
}

func TestLinuxOpensBrowserAsSudoUser(t *testing.T) {
	f := &fakeHost{
		env: map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1001", "SUDO_USER": "user", "DISPLAY": ":0",
			"PATH": "/usr/sbin:/usr/bin", "HOME": "/root", "XAUTHORITY": "/home/user/.Xauthority"},
		files: []string{"/run/user/1000", "/run/user/1000/bus", "/run/user/1000/wayland-0"},
		homes: map[uint32]string{1000: "/home/user"},
	}
	noErr(t, f.host("linux").Graphical())
	noErr(t, f.host("linux").Open(testURL))
	eq(t, len(f.started), 1)
	c := f.started[0]
	eq(t, c.Path, "xdg-open")
	eq(t, c.Args, []string{testURL})
	eq(t, c.User, &User{UID: 1000, GID: 1001})
	eq(t, c.Unelevated, false)
	for _, want := range []string{"HOME=/home/user", "USER=user", "LOGNAME=user", "PATH=/usr/sbin:/usr/bin", "DISPLAY=:0",
		"XAUTHORITY=/home/user/.Xauthority", "XDG_RUNTIME_DIR=/run/user/1000",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "WAYLAND_DISPLAY=wayland-0"} {
		if !slices.Contains(c.Env, want) {
			t.Errorf("в окружении нет %q: %q", want, c.Env)
		}
	}
	for _, v := range c.Env {
		if strings.HasPrefix(v, "SUDO_") || v == "HOME=/root" {
			t.Errorf("в окружении браузера лишнее: %q", v)
		}
	}
}

func TestLinuxWithoutSudoOpensAsCurrentUser(t *testing.T) {
	for _, env := range []map[string]string{
		{"DISPLAY": ":0"},
		{"DISPLAY": ":0", "SUDO_UID": "0", "SUDO_GID": "0", "SUDO_USER": "root"},
		{"DISPLAY": ":0", "SUDO_UID": "не число", "SUDO_GID": "1000"},
		{"DISPLAY": ":0", "SUDO_UID": "1000"},
	} {
		f := &fakeHost{env: env}
		noErr(t, f.host("linux").Open(testURL))
		eq(t, f.started, []Command{{Path: "xdg-open", Args: []string{testURL}}})
	}
}

func TestLinuxWithoutGraphicsRefuses(t *testing.T) {
	f := &fakeHost{env: map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1000"}}
	eq(t, errors.Is(f.host("linux").Graphical(), ErrNoDisplay), true)

	// sudo не передаёт WAYLAND_DISPLAY: сеанс виден по сокету пользователя
	f.files = []string{"/run/user/1000/wayland-0"}
	noErr(t, f.host("linux").Graphical())
	f.files, f.env = nil, map[string]string{"WAYLAND_DISPLAY": "wayland-1"}
	noErr(t, f.host("linux").Graphical())

	noErr(t, (&fakeHost{}).host("windows").Graphical())
	noErr(t, (&fakeHost{}).host("darwin").Graphical())
}

func TestDarwinOpensBrowserAsSudoUser(t *testing.T) {
	f := &fakeHost{env: map[string]string{"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "user", "PATH": "/usr/bin:/bin"}}
	noErr(t, f.host("darwin").Open(testURL))
	eq(t, f.started, []Command{{Path: "/usr/bin/open", Args: []string{testURL}, User: &User{UID: 501, GID: 20},
		Env: []string{"HOME=/Users/user", "USER=user", "LOGNAME=user", "PATH=/usr/bin:/bin"}}})
}

func TestOpenReportsStartFailure(t *testing.T) {
	f := &fakeHost{env: map[string]string{"DISPLAY": ":0"}, startErr: errors.New("xdg-open: не найден")}
	eq(t, f.host("linux").Open(testURL), f.startErr)
}

func TestUnknownSystemCannotOpen(t *testing.T) {
	f := &fakeHost{}
	if err := f.host("plan9").Open(testURL); err == nil {
		t.Error("ожидалась ошибка")
	}
	eq(t, len(f.started), 0)
}
