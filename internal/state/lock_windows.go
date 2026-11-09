package state

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// LockName — имя именованного mutex в Global\ (dir не нужен).
func LockName(string) string { return `Global\killswitch` }

// Acquire захватывает именованный mutex. WAIT_ABANDONED (прежний владелец умер) — захват: сбой разберёт журнал намерения.
// Горутина остаётся на своём потоке ОС до Release.
func Acquire(name string, wait bool) (*Lock, error) {
	runtime.LockOSThread()
	h, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(name))
	if h == 0 {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("mutex %s: %w", name, err)
	}
	timeout := uint32(windows.INFINITE)
	if !wait {
		timeout = 0
	}
	ev, err := windows.WaitForSingleObject(h, timeout)
	if ev != windows.WAIT_OBJECT_0 && ev != windows.WAIT_ABANDONED {
		_ = windows.CloseHandle(h)
		runtime.UnlockOSThread()
		if ev == uint32(windows.WAIT_TIMEOUT) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("mutex %s: %w", name, err)
	}
	return &Lock{release: func() error {
		defer runtime.UnlockOSThread()
		rerr := windows.ReleaseMutex(h)
		cerr := windows.CloseHandle(h)
		if rerr != nil {
			return rerr
		}
		return cerr
	}}, nil
}
