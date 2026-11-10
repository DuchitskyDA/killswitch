package windows

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Решение о доверии — по дескрипторам из SDDL, без системы; проверка каталога — во временном каталоге.

const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func TestTrustedSD(t *testing.T) {
	cases := []struct {
		name, sddl string
		want       bool
	}{
		{"точные права", exactSDDL, true},
		{"пользователи создают файлы (ProgramData)", "O:BAD:(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)", false},
		{"создатель-владелец не мешает", "O:BAD:P(A;OICIIO;GA;;;CO)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", true},
		{"NULL DACL", "O:BAD:NO_ACCESS_CONTROL", false},
		{"владелец — пользователи", "O:BUD:P(A;OICI;FA;;;BA)", false},
		{"владелец — TrustedInstaller", "O:" + trustedInstaller + "D:P(A;;FA;;;" + trustedInstaller + ")(A;;0x1200a9;;;BU)", true},
		{"запрет записи пользователям", "O:BAD:P(A;OICI;FA;;;BA)(D;;FA;;;BU)", true},
		{"наследуемая GENERIC_WRITE пользователям", "O:BAD:P(A;OICI;FA;;;BA)(A;OICIIO;GW;;;BU)", false},
		{"смена прав пользователям", "O:BAD:P(A;OICI;FA;;;BA)(A;;WD;;;BU)", false},
		{"смена владельца пользователям", "O:BAD:P(A;OICI;FA;;;BA)(A;;WO;;;BU)", false},
		{"удаление пользователям", "O:BAD:P(A;OICI;FA;;;BA)(A;;SD;;;BU)", false},
		{"условная запись — недоверенно", "O:BAD:P(A;OICI;FA;;;BA)(XA;;0x1200a9;;;BU;(Member_of {SID(BA)}))", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(c.sddl)
			if err != nil {
				t.Fatal(err)
			}
			got, err := trustedSD(sd)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("trustedSD(%s) = %v, ожидалось %v", c.sddl, got, c.want)
			}
		})
	}
}

// Точные права — те, что проверяет CI (install.ps1, Acl-Exact): владелец BA, наследование снято, SID ровно SY, BA, BU.
func TestExactSDDL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(exactSDDL)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	if owner.String() != "S-1-5-32-544" {
		t.Errorf("владелец %s", owner)
	}
	control, _, _ := sd.Control()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("наследование от родителя не снято")
	}
	dacl, _, _ := sd.DACL()
	var sids []string
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	slices.Sort(sids)
	if strings.Join(sids, ",") != "S-1-5-18,S-1-5-32-544,S-1-5-32-545" {
		t.Errorf("записи %v", sids)
	}
}

func TestEmptyDACLIsNotNull(t *testing.T) {
	dacl, err := emptyDACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 0 {
		t.Fatalf("dacl = %+v", dacl)
	}
}

func TestAssertTrustedDirMissingIsFine(t *testing.T) {
	if err := AssertTrustedDir(filepath.Join(t.TempDir(), "нет")); err != nil {
		t.Fatal(err)
	}
}

// Временный каталог принадлежит пользователю — недоверенный.
func TestAssertTrustedDirRefusesUserDir(t *testing.T) {
	err := AssertTrustedDir(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "небезопасный каталог") || !strings.Contains(err.Error(), "не администраторам") {
		t.Fatalf("ошибка %v", err)
	}
}

func TestAssertTrustedDirRefusesLink(t *testing.T) {
	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("ссылку не создать без права: %v", err)
	}
	err := AssertTrustedDir(link)
	if err == nil || !strings.Contains(err.Error(), "ссылка") {
		t.Fatalf("ошибка %v", err)
	}
}

// Каталог с точными правами создаёт только администратор (владелец BA): без повышения тесты пропускаются,
// на раннере CI они идут. Всё — во временном каталоге.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("нужны права администратора: владелец каталога — BA")
	}
}

func setSD(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func protectedRootWithChild(t *testing.T) (root, child string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "killswitch")
	if err := ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	child = filepath.Join(root, "config.toml")
	if err := os.WriteFile(child, []byte("profile = 'x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, child
}

func TestAssertTrustedDirRefusesUntrustedChild(t *testing.T) {
	requireElevated(t)
	root, child := protectedRootWithChild(t)
	if err := AssertTrustedDir(root); err != nil {
		t.Fatalf("свой каталог отвергнут: %v", err)
	}
	setSD(t, child, "O:BAD:P(A;;FA;;;BA)(A;;FA;;;BU)")
	err := AssertTrustedDir(root)
	if err == nil || !strings.Contains(err.Error(), child) {
		t.Fatalf("вложенный файл с записью пользователям принят: %v", err)
	}
	if err := ProtectDir(root); err == nil {
		t.Fatal("ProtectDir принял каталог с недоверенным вложенным")
	}
}

// Повторная установка: явные права вложенного сбрасываются до унаследованных от точных прав каталога.
func TestProtectDirResetsChildren(t *testing.T) {
	requireElevated(t)
	root, child := protectedRootWithChild(t)
	setSD(t, child, "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)")
	if err := ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	h, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := h.Owner()
	control, _, _ := h.Control()
	dacl, _, _ := h.DACL()
	var sids []string
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			t.Errorf("явная запись осталась: %+v", ace.Header)
		}
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	slices.Sort(sids)
	if owner.String() != "S-1-5-32-544" || control&windows.SE_DACL_PROTECTED != 0 ||
		strings.Join(sids, ",") != "S-1-5-18,S-1-5-32-544,S-1-5-32-545" {
		t.Errorf("вложенное: владелец %s, protected %v, записи %v", owner, control&windows.SE_DACL_PROTECTED != 0, sids)
	}
}
