package state

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockGrantees — SID-ы, которым DACL mutex даёт полный доступ.
func lockGrantees(t *testing.T) map[string]bool {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(lockSDDL)
	noErr(t, err)
	dacl, _, err := sd.DACL()
	noErr(t, err)
	got := map[string]bool{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		noErr(t, windows.GetAce(dacl, uint32(i), &ace))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&windows.GENERIC_ALL == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		got[sid.String()] = true
	}
	return got
}

// Служба (SYSTEM) создаёт mutex, CLI администратора открывает его: оба должны иметь полный доступ,
// владелец — для повторного захвата тем же пользователем без повышения.
func TestLockDACLGrantsSystemAdminsAndOwner(t *testing.T) {
	eq(t, lockGrantees(t), map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, "S-1-3-4": true})
}
