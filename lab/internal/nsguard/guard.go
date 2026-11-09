// Package nsguard не даёт лаборатории выполнить сетевую операцию в корневом network namespace хоста.
// Каждая операция идёт через открытый дескриптор namespace, inode которого сверен перед запуском.
// То же для mount namespace держателя: killswitch пишет только в tmpfs своего mount ns.
package nsguard

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
)

const (
	Prefix = "ksl-"
	RunDir = "/run/netns"
)

var (
	ErrRootNS    = errors.New("nsguard: цель — корневой network namespace хоста")
	ErrRootMnt   = errors.New("nsguard: цель — mount namespace хоста")
	ErrChanged   = errors.New("nsguard: inode namespace изменился")
	ErrName      = errors.New("nsguard: имя namespace должно быть ksl-<a-z0-9->")
	ErrUnknown   = errors.New("nsguard: inode namespace не определён")
	ErrInner     = errors.New("nsguard: подкоманда внутри ns отказала по сверке inode (выход 2)")
	ErrIsolation = errors.New("nsguard: mount ns без изоляции")
)

// IsolatedDirs — каталоги, поверх которых в mount ns лаборатории обязан стоять tmpfs: killswitch пишет туда
// состояние (/var/lib/killswitch), маркеры (/run/killswitch) и юниты (/etc/systemd/system).
var IsolatedDirs = []string{"/var/lib", "/run", "/etc/systemd/system"}

var nameRe = regexp.MustCompile(`^ksl-[a-z0-9-]{1,11}$`)

// IsGuard — ошибка защиты хоста; по ней раннер выходит с кодом 2.
func IsGuard(err error) bool {
	for _, e := range []error{ErrRootNS, ErrRootMnt, ErrChanged, ErrName, ErrUnknown, ErrInner, ErrIsolation} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// CheckName пропускает только имена лаборатории.
func CheckName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	return nil
}

// CheckTarget сверяет inode цели с корневым и с записанным при создании (expected = 0 — не сверять).
func CheckTarget(target, root, expected uint64) error {
	if target == 0 || root == 0 {
		return ErrUnknown
	}
	if target == root {
		return fmt.Errorf("%w (inode %d)", ErrRootNS, target)
	}
	if expected != 0 && target != expected {
		return fmt.Errorf("%w: ждали %d, есть %d", ErrChanged, expected, target)
	}
	return nil
}

// CheckMountTarget — CheckTarget для mount namespace: совпадение с mount ns хоста — ErrRootMnt.
func CheckMountTarget(target, root, expected uint64) error {
	err := CheckTarget(target, root, expected)
	if errors.Is(err, ErrRootNS) {
		return fmt.Errorf("%w (inode %d)", ErrRootMnt, target)
	}
	return err
}

// CheckIsolation: каждый из IsolatedDirs — tmpfs, а systemctl в PATH — заглушка из stubDir.
func CheckIsolation(isTmpfs func(dir string) (bool, error), lookPath func(string) (string, error), stubDir string) error {
	for _, d := range IsolatedDirs {
		ok, err := isTmpfs(d)
		if err != nil || !ok {
			return fmt.Errorf("%w: %s не tmpfs (%v)", ErrIsolation, d, err)
		}
	}
	p, err := lookPath("systemctl")
	if err != nil || filepath.ToSlash(filepath.Dir(p)) != stubDir {
		return fmt.Errorf("%w: systemctl = %q, ждали заглушку в %s", ErrIsolation, p, stubDir)
	}
	return nil
}

// Exec — проверки kslab ksexec перед exec killswitch; функции подменяются в тестах.
type Exec struct {
	Ino, Mnt uint64
	Stub     string
	SelfNet  func(expected uint64) error
	SelfMnt  func(expected uint64) error
	IsTmpfs  func(dir string) (bool, error)
	LookPath func(string) (string, error)
}

// CheckExec: процесс в ожидаемом network ns и в mount ns держателя (оба — не хоста), IsolatedDirs — tmpfs,
// systemctl — заглушка. Любой отказ — ошибка защиты, exec не выполняется.
func CheckExec(e Exec) error {
	if err := e.SelfNet(e.Ino); err != nil {
		return err
	}
	if err := e.SelfMnt(e.Mnt); err != nil {
		return err
	}
	return CheckIsolation(e.IsTmpfs, e.LookPath, e.Stub)
}
