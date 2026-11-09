//go:build windows && amd64

package wf

import (
	"testing"
	"unsafe"
)

// killswitch: раскладка FWPM_FILTER0 на amd64 по fwpmtypes.h — FilterID на смещении 176, размер 200.
func TestFilter0LayoutAMD64(t *testing.T) {
	var f fwpmFilter0
	got := [3]uintptr{unsafe.Offsetof(f.ProviderContext), unsafe.Offsetof(f.FilterID), unsafe.Sizeof(f)}
	if got != [3]uintptr{152, 176, 200} {
		t.Errorf("смещения providerContext, filterId и размер: %v, ожидалось [152 176 200]", got)
	}
}

// killswitch: массив условий больше слаба (100+ app-id) не должен ронять процесс.
func TestArenaAllocLargerThanSlab(t *testing.T) {
	var a arena
	defer a.Dispose()
	p := a.Alloc(slabSize + 24)
	if p == nil || uintptr(p)%8 != 0 {
		t.Errorf("большое выделение: %v", p)
	}
}
