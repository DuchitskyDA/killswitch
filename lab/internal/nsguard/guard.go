// Package nsguard не даёт лаборатории выполнить сетевую операцию в корневом network namespace хоста.
// Каждая операция идёт через открытый дескриптор namespace, inode которого сверен перед запуском.
package nsguard

import (
	"errors"
	"fmt"
	"regexp"
)

const (
	Prefix = "ksl-"
	RunDir = "/run/netns"
)

var (
	ErrRootNS  = errors.New("nsguard: цель — корневой network namespace хоста")
	ErrChanged = errors.New("nsguard: inode namespace изменился")
	ErrName    = errors.New("nsguard: имя namespace должно быть ksl-<a-z0-9->")
	ErrUnknown = errors.New("nsguard: inode namespace не определён")
	ErrInner   = errors.New("nsguard: подкоманда внутри ns отказала по сверке inode (выход 2)")
)

var nameRe = regexp.MustCompile(`^ksl-[a-z0-9-]{1,11}$`)

// IsGuard — ошибка защиты хоста; по ней раннер выходит с кодом 2.
func IsGuard(err error) bool {
	return errors.Is(err, ErrRootNS) || errors.Is(err, ErrChanged) ||
		errors.Is(err, ErrName) || errors.Is(err, ErrUnknown) || errors.Is(err, ErrInner)
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
