package state

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockSDDL — доступ к mutex только SYSTEM и Администраторам. Без явного дескриптора mutex,
// созданный службой (SYSTEM), получает DACL по умолчанию её токена: Администраторам — только
// чтение, и CLI администратора получает Access is denied, пока служба держит объект.
const lockSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// LockName — имя именованного mutex в Global\ (dir не нужен).
func LockName(string) string { return `Global\killswitch` }

// Acquire захватывает именованный mutex. WAIT_ABANDONED (прежний владелец умер) — захват: сбой разберёт журнал намерения.
// Горутина остаётся на своём потоке ОС до Release.
func Acquire(name string, wait bool) (*Lock, error) {
	sd, err := windows.SecurityDescriptorFromString(lockSDDL)
	if err != nil {
		return nil, fmt.Errorf("mutex %s: дескриптор: %w", name, err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	runtime.LockOSThread()
	h, err := windows.CreateMutex(sa, false, windows.StringToUTF16Ptr(name))
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
