// Package windows — установка killswitch в систему Windows: каталоги только для администраторов, копия
// программы, служба enforce, ярлык окна и запись в «Параметры → Приложения»; и полное удаление.
package windows

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Доверенные владельцы и получатели прав записи: администраторы, SYSTEM, TrustedInstaller.
var trustedSIDs = []string{"S-1-5-32-544", "S-1-5-18",
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}

// «Создатель-владелец» даёт права только на созданное самим: создать может лишь тот, у кого уже есть запись.
const creatorOwner = "S-1-3-0"

// writeMask — запись, удаление, смена прав и владельца; GENERIC_ALL и GENERIC_WRITE — в наследуемых записях.
const writeMask = 0x0002 | 0x0004 | 0x0010 | 0x0100 | // запись данных, дозапись, атрибуты (Write)
	0x0040 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | // удаление вложенного и своё, права, владелец
	windows.GENERIC_ALL | windows.GENERIC_WRITE

// exactSDDL — точные права каталога: владелец — администраторы; полный доступ — администраторам и SYSTEM, чтение —
// пользователям; наследование от родителя снято, прежние записи не сохраняются.
const exactSDDL = "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"

// trustedSD — путь доверенный: владелец из trustedSIDs и никто другой не может писать в него или менять права.
// Разрешающие записи иных типов (объектные, условные) не разбираются — недоверенно.
func trustedSD(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil || !slices.Contains(trustedSIDs, owner.String()) {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil { // NULL DACL — полный доступ всем
		return false, nil
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, 0x6, 0xA, 0xC: // запрещающие записи прав не дают
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid == creatorOwner || slices.Contains(trustedSIDs, sid) {
			continue
		}
		if ace.Mask&writeMask != 0 {
			return false, nil
		}
	}
	return true, nil
}

// inspect читает сам путь, не следуя ссылке: признак ссылки, каталог ли это и права — с одного хэндла.
func inspect(path string) (reparse, dir bool, sd *windows.SECURITY_DESCRIPTOR, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, false, nil, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, false, nil, err
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return false, false, nil, err
	}
	reparse = fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	dir = fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if reparse {
		return true, dir, nil, nil
	}
	sd, err = windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return false, dir, sd, err
}

// AssertTrustedDir: каталог, который уже есть, принимается только доверенным вместе со всем вложенным: иначе его
// содержимое (config.toml, state.json, копию программы) мог подложить обычный пользователь, и служба с правами SYSTEM
// исполнила бы чужое. Ссылка (junction, symlink) увела бы запись настроек и прав в чужой каталог. Нет каталога — nil.
func AssertTrustedDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return assertTrusted(dir, dir)
}

func assertTrusted(root, path string) error {
	reparse, dir, sd, err := inspect(path)
	if err != nil {
		return fmt.Errorf("небезопасный каталог: %s не проверен: %w", path, err)
	}
	if reparse {
		return fmt.Errorf("небезопасный каталог: %s — ссылка, а не каталог или файл. Удалите её и повторите установку", path)
	}
	ok, err := trustedSD(sd)
	if err != nil {
		return fmt.Errorf("небезопасный каталог: права %s не прочитаны: %w", path, err)
	}
	if !ok {
		return fmt.Errorf("небезопасный каталог: %s принадлежит не администраторам или открыт на запись другим. "+
			"Проверьте содержимое %s, удалите каталог и повторите установку", path, root)
	}
	if !dir {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("небезопасный каталог: %s не прочитан: %w", path, err)
	}
	for _, e := range entries {
		if err := assertTrusted(root, filepath.Join(path, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// ProtectDir — каталог только для администраторов. Нового каталога с открытыми правами не бывает ни на миг: он
// создаётся сразу с точными правами. Существующий принимается только доверенным — и до создания, и после: каталог,
// который кто-то успел подложить между проверкой и созданием, отвергается до смены владельца и чтения содержимого.
// Вложенное (прежняя установка): владелец — администраторы, права — только унаследованные.
func ProtectDir(dir string) error {
	if err := AssertTrustedDir(dir); err != nil {
		return err
	}
	exact, err := windows.SecurityDescriptorFromString(exactSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: exact}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreateDirectory(p, &sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("каталог %s не создан: %w", dir, err)
	}
	if err := AssertTrustedDir(dir); err != nil {
		return err
	}
	owner, _, err := exact.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := exact.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("права каталога %s не заданы: %w", dir, err)
	}
	if err := resetChildren(dir, owner); err != nil {
		return err
	}
	if err := AssertTrustedDir(dir); err != nil {
		return fmt.Errorf("права каталога %s не установились: %w", dir, err)
	}
	return nil
}

// emptyDACL — пустой (не NULL) список прав: с unprotected остаются только унаследованные записи.
// NULL на его месте дал бы полный доступ всем.
func emptyDACL() (*windows.ACL, error) {
	sd, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return nil, errors.New("пустой список прав не построен")
	}
	return dacl, nil
}

// resetChildren — владелец вложенного — администраторы, права — только унаследованные (icacls /setowner, /reset).
// Ссылок в дереве нет и писать в него может только администратор: AssertTrustedDir прошёл.
func resetChildren(dir string, owner *windows.SID) error {
	dacl, err := emptyDACL()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
			return fmt.Errorf("права %s не заданы: %w", path, err)
		}
		if e.IsDir() {
			if err := resetChildren(path, owner); err != nil {
				return err
			}
		}
	}
	return nil
}
