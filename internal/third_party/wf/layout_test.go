//go:build windows && amd64

package wf

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// killswitch: раскладка FWPM_FILTER0 на amd64 по fwpmtypes.h — FilterID на смещении 176, размер 200.
func TestFilter0LayoutAMD64(t *testing.T) {
	var f fwpmFilter0
	got := [3]uintptr{unsafe.Offsetof(f.ProviderContext), unsafe.Offsetof(f.FilterID), unsafe.Sizeof(f)}
	if got != [3]uintptr{152, 176, 200} {
		t.Errorf("смещения providerContext, filterId и размер: %v, ожидалось [152 176 200]", got)
	}
}

var procLocalSize = windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalSize")

// killswitch: массив условий больше слаба (100+ app-id) не должен ронять процесс, а блок — вмещать весь запрос.
func TestArenaAllocLargerThanSlab(t *testing.T) {
	var a arena
	defer a.Dispose()
	const want = slabSize + 24
	p := a.Alloc(want)
	size, _, _ := procLocalSize.Call(a.slabs[len(a.slabs)-1])
	if uintptr(p) != a.slabs[len(a.slabs)-1] || size < want {
		t.Errorf("большое выделение: блок %d байт, нужно не меньше %d", size, want)
	}
}
