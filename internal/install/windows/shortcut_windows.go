package windows

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ярлык — файл .lnk по [MS-SHLLINK]: цель — список ID оболочки (как у IShellLink::SetPath), аргументы, рабочий
// каталог, значок, свёрнутое окно и флаг «Запуск от имени администратора».

var (
	shell32           = windows.NewLazySystemDLL("shell32.dll")
	ilCreateFromPathW = shell32.NewProc("ILCreateFromPathW")
	ilGetSize         = shell32.NewProc("ILGetSize")
	ilFree            = shell32.NewProc("ILFree")
	rtlMoveMemory     = windows.NewLazySystemDLL("kernel32.dll").NewProc("RtlMoveMemory")
)

const (
	linkHasTargetIDList = 0x1
	linkHasWorkingDir   = 0x10
	linkHasArguments    = 0x20
	linkHasIconLocation = 0x40
	linkIsUnicode       = 0x80
	linkRunAsUser       = 0x2000 // SLDF_RUNAS_USER: байт 0x15, бит 0x20
	showMinNoActive     = 7      // свёрнутое окно консоли
)

// shortcut — что открывает ярлык.
type shortcut struct {
	target, args, workDir, icon string
}

// lnk — содержимое .lnk; idList — цель в виде списка ID оболочки.
func (s shortcut) lnk(idList []byte) []byte {
	var b bytes.Buffer
	le := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	le(uint32(0x4C))                                                                              // HeaderSize
	b.Write([]byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}) // LinkCLSID
	le(uint32(linkHasTargetIDList | linkHasWorkingDir | linkHasArguments | linkHasIconLocation | linkIsUnicode | linkRunAsUser))
	le(uint32(0))   // FileAttributes
	le([3]uint64{}) // CreationTime, AccessTime, WriteTime
	le(uint32(0))   // FileSize
	le(int32(0))    // IconIndex
	le(uint32(showMinNoActive))
	le(uint16(0))  // HotKey
	le([10]byte{}) // Reserved1..3
	le(uint16(len(idList)))
	b.Write(idList)
	for _, str := range []string{s.workDir, s.args, s.icon} { // порядок StringData: WORKING_DIR, ARGUMENTS, ICON
		u := utf16.Encode([]rune(str))
		le(uint16(len(u)))
		le(u)
	}
	le(uint32(0)) // TerminalBlock
	return b.Bytes()
}

// idList — список ID оболочки для существующего пути (с завершающим нулевым ID).
func idList(path string) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	pidl, _, _ := ilCreateFromPathW.Call(uintptr(unsafe.Pointer(p)))
	if pidl == 0 {
		return nil, errors.New("оболочка не разобрала путь " + path)
	}
	defer ilFree.Call(pidl)
	size, _, _ := ilGetSize.Call(pidl)
	if size < 2 {
		return nil, errors.New("пустой список ID оболочки для " + path)
	}
	out := make([]byte, size)
	rtlMoveMemory.Call(uintptr(unsafe.Pointer(&out[0])), pidl, size)
	return out, nil
}

// writeShortcut пишет ярлык атомарно: временный файл рядом, затем замена.
func writeShortcut(path string, s shortcut) error {
	ids, err := idList(s.target)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "killswitch-*.lnk.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(s.lnk(ids))
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
