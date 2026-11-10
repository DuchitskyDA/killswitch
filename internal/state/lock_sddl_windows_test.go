package state

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mutantAllAccess — полный доступ к mutex после отображения GENERIC_ALL ядром.
const mutantAllAccess = 0x001F0001

// grantees — все ACE DACL как «SID → полный доступ разрешён». Любой другой ACE (запрет, частичный
// доступ, иной тип) попадает в набор с false, и сверка с ожидаемым набором его ловит.
func grantees(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) map[string]bool {
	t.Helper()
	dacl, _, err := sd.DACL()
	noErr(t, err)
	got := map[string]bool{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		noErr(t, windows.GetAce(dacl, uint32(i), &ace))
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		full := ace.Mask&windows.GENERIC_ALL != 0 || ace.Mask&mutantAllAccess == mutantAllAccess
		allowed := ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && full
		if prev, seen := got[sid]; seen && !prev {
			continue
		}
		got[sid] = allowed
	}
	return got
}

// Служба (SYSTEM) создаёт mutex, CLI администратора открывает его: оба должны иметь полный доступ,
// владелец — для повторного захвата тем же пользователем без повышения.
func TestLockDACLGrantsSystemAdminsAndOwner(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(lockSDDL)
	noErr(t, err)
	eq(t, grantees(t, sd), wantGrantees)
}

// Созданный объект действительно несёт этот DACL, а не DACL по умолчанию токена.
func TestCreatedMutexCarriesLockDACL(t *testing.T) {
	h, err := createLockMutex(testLockName(t))
	noErr(t, err)
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	noErr(t, err)
	eq(t, grantees(t, sd), wantGrantees)
}

var wantGrantees = map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, "S-1-3-4": true}
