package state

import "errors"

// ErrBusy — замок занят другим процессом (только при wait=false).
var ErrBusy = errors.New("другая команда killswitch уже работает")

// Lock — захваченный системный замок. Release вызывает та же горутина, что Acquire (Windows: владение mutex — у потока ОС).
type Lock struct{ release func() error }

// Release отпускает замок.
func (l *Lock) Release() error { return l.release() }
