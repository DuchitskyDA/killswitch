package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var getConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// isDesktop — запуск с рабочего стола (двойной клик в Проводнике): консоль создана для этого процесса и в ней
// больше никого нет. Из терминала в консоли есть и сам терминал; у службы консоли нет.
func isDesktop() bool {
	pids := make([]uint32, 4)
	n, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
