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
