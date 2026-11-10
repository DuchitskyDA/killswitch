package windows

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// uninstallKey — запись killswitch в «Параметры → Приложения».
const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\killswitch`

// appEntry — значения записи «Приложений»: удаление — установленный exe с командой uninstall.
type appEntry struct {
	strings map[string]string
	dwords  map[string]uint32
}

func newAppEntry(exe, dir, version string) appEntry {
	return appEntry{
		strings: map[string]string{
			"DisplayName":     "killswitch",
			"DisplayIcon":     exe,
			"Publisher":       "DuchitskyDA",
			"DisplayVersion":  version,
			"InstallLocation": dir,
			"UninstallString": syscall.EscapeArg(exe) + " uninstall",
		},
		dwords: map[string]uint32{"NoModify": 1, "NoRepair": 1},
	}
}

func register(e appEntry) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("запись в «Приложения» не создана: %w", err)
	}
	defer k.Close()
	for name, v := range e.strings {
		if err := k.SetStringValue(name, v); err != nil {
			return fmt.Errorf("запись в «Приложения», %s: %w", name, err)
		}
	}
	for name, v := range e.dwords {
		if err := k.SetDWordValue(name, v); err != nil {
			return fmt.Errorf("запись в «Приложения», %s: %w", name, err)
		}
	}
	return nil
}

// unregister удаляет запись; её нет — nil.
func unregister() error {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("запись в «Приложения» не удалена: %w", err)
	}
	return nil
}
