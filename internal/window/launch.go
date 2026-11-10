package window

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"time"
)

// Размер окна на Windows.
const (
	WindowWidth  = 460
	WindowHeight = 700
)

// ErrNoDisplay — графического сеанса нет: окно открыть негде.
var ErrNoDisplay = errors.New("нет графического сеанса")

// Command — процесс, который открывает окно.
type Command struct {
	Path string
	Args []string
	Env  []string // nil — окружение текущего процесса
	User *User    // nil — от имени текущего пользователя
	// Unelevated — Windows: запустить без прав администратора, если получится.
	Unelevated bool
}

// User — пользователь, от имени которого запускается браузер (Linux и macOS).
type User struct{ UID, GID uint32 }

// Host — машина, на которой открывается окно; в тестах подменяется.
type Host struct {
	GOOS   string
	Getenv func(string) string
	Exists func(path string) bool
	Home   func(uid uint32) string // домашний каталог; пусто — неизвестен
	Start  func(Command) error
}

// SystemHost — эта машина.
func SystemHost() Host {
	return Host{
		GOOS:   runtime.GOOS,
		Getenv: os.Getenv,
		Exists: func(path string) bool { _, err := os.Stat(path); return err == nil },
		Home: func(uid uint32) string {
			u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
			if err != nil {
				return ""
			}
			return u.HomeDir
		},
		Start: start,
	}
}

// Graphical — есть ли где открыть окно. Проверяется только Linux: сеанс виден по DISPLAY, WAYLAND_DISPLAY
// или сокету Wayland пользователя (sudo переменную WAYLAND_DISPLAY не передаёт).
func (h Host) Graphical() error {
	if h.GOOS != "linux" || h.Getenv("DISPLAY") != "" || h.wayland() != "" {
		return nil
	}
	return ErrNoDisplay
}

// Open открывает адрес: Windows — окно Edge без адресной строки, без Edge — браузер по умолчанию;
// Linux и macOS — браузер по умолчанию от имени пользователя, вызвавшего sudo.
func (h Host) Open(url string) error {
	var c Command
	switch h.GOOS {
	case "windows":
		c = h.windowsCommand(url)
	case "linux":
		c = h.asSudoUser(Command{Path: "xdg-open", Args: []string{url}})
	case "darwin":
		c = h.asSudoUser(Command{Path: "/usr/bin/open", Args: []string{url}})
	default:
		return fmt.Errorf("окно на %s не поддерживается", h.GOOS)
	}
	return h.Start(c)
}

func (h Host) windowsCommand(url string) Command {
	local := h.Getenv("LOCALAPPDATA")
	const edge = `\Microsoft\Edge\Application\msedge.exe`
	for _, root := range []string{h.Getenv("ProgramFiles(x86)"), h.Getenv("ProgramFiles"), local} {
		// Свой каталог профиля: окно не делит cookie и расширения с обычным браузером.
		if root == "" || local == "" || !h.Exists(root+edge) {
			continue
		}
		return Command{Path: root + edge, Unelevated: true, Args: []string{
			"--app=" + url,
			`--user-data-dir=` + local + `\killswitch\window`,
			fmt.Sprintf("--window-size=%d,%d", WindowWidth, WindowHeight),
			"--no-first-run", "--no-default-browser-check",
		}}
	}
	return Command{Path: h.Getenv("SystemRoot") + `\System32\rundll32.exe`,
		Args: []string{"url.dll,FileProtocolHandler", url}, Unelevated: true}
}

// sudoUser — пользователь, вызвавший sudo; false — sudo не было или это root.
func (h Host) sudoUser() (User, bool) {
	uid, err := strconv.ParseUint(h.Getenv("SUDO_UID"), 10, 32)
	if err != nil || uid == 0 {
		return User{}, false
	}
	gid, err := strconv.ParseUint(h.Getenv("SUDO_GID"), 10, 32)
	if err != nil {
		return User{}, false
	}
	return User{UID: uint32(uid), GID: uint32(gid)}, true
}

func (h Host) runtimeDir(u User) string { return fmt.Sprintf("/run/user/%d", u.UID) }

// wayland — имя сокета Wayland: из окружения или сокет по умолчанию у пользователя sudo.
func (h Host) wayland() string {
	if w := h.Getenv("WAYLAND_DISPLAY"); w != "" {
		return w
	}
	if u, ok := h.sudoUser(); ok && h.Exists(h.runtimeDir(u)+"/wayland-0") {
		return "wayland-0"
	}
	return ""
}

// asSudoUser: браузер запускается не от root, а от пользователя, вызвавшего sudo, с окружением его сеанса.
func (h Host) asSudoUser(c Command) Command {
	u, ok := h.sudoUser()
	if !ok {
		return c
	}
	c.User = &u
	set := func(k, v string) {
		if v != "" {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	name := h.Getenv("SUDO_USER")
	home := h.Home(u.UID)
	if home == "" && name != "" {
		home = map[string]string{"linux": "/home/", "darwin": "/Users/"}[h.GOOS] + name
	}
	path := h.Getenv("PATH")
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	set("HOME", home)
	set("USER", name)
	set("LOGNAME", name)
	set("PATH", path)
	for _, k := range []string{"LANG", "LC_ALL"} {
		set(k, h.Getenv(k))
	}
	if h.GOOS != "linux" {
		return c
	}
	for _, k := range []string{"DISPLAY", "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "DESKTOP_SESSION",
		"XDG_DATA_DIRS", "XDG_CONFIG_DIRS"} {
		set(k, h.Getenv(k))
	}
	set("WAYLAND_DISPLAY", h.wayland())
	if dir := h.runtimeDir(u); h.Exists(dir) {
		set("XDG_RUNTIME_DIR", dir)
		if h.Exists(dir + "/bus") {
			set("DBUS_SESSION_BUS_ADDRESS", "unix:path="+dir+"/bus")
		}
	}
	return c
}

// earlyExit — сколько ждать, что запускающая команда сразу сообщит о сбое (нет обработчика адресов).
const earlyExit = 2 * time.Second

// run запускает команду открытия окна.
func run(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return settle(cmd)
}

// settle недолго ждёт запущенную команду: быстрый выход с ошибкой — окно не открылось.
// Команда, которая живёт дольше (сам браузер), остаётся работать.
func settle(cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(earlyExit):
		return nil
	}
}
