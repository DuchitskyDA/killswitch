package windows

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Layout — где лежит установка.
type Layout struct {
	Running    string // запущенный killswitch.exe
	InstallDir string // %ProgramFiles%\killswitch
	StateDir   string // %ProgramData%\killswitch: config.toml, state.json
	Shortcut   string // ярлык окна на общем рабочем столе
	Version    string // DisplayVersion в «Приложениях»
}

// System — установка этой машины; stateDir — каталог состояния программы.
func System(stateDir string) (Layout, error) {
	running, err := os.Executable()
	if err != nil {
		return Layout{}, err
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return Layout{}, fmt.Errorf("Program Files: %w", err)
	}
	desktop, err := windows.KnownFolderPath(windows.FOLDERID_PublicDesktop, 0)
	if err != nil {
		return Layout{}, fmt.Errorf("общий рабочий стол: %w", err)
	}
	return Layout{
		Running:    running,
		InstallDir: filepath.Join(programFiles, "killswitch"),
		StateDir:   stateDir,
		Shortcut:   filepath.Join(desktop, "killswitch.lnk"),
		Version:    buildVersion(),
	}, nil
}

// Exe — установленная копия: её запускают служба, ярлык и удаление из «Приложений».
func (l Layout) Exe() string { return filepath.Join(l.InstallDir, "killswitch.exe") }

// buildVersion — версия из сборки (тег или псевдоверсия Go), без «v».
func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}

// Install ставит программу: каталоги только для администраторов (до копирования и до чтения настроек), копия себя
// (обновление, если запущен другой файл), enable — включение защиты по уже имеющимся настройкам, служба enforce,
// ярлык окна и запись в «Приложения». Повторный запуск приводит к тому же.
func (l Layout) Install(enable func() error) error {
	for _, dir := range []string{l.InstallDir, l.StateDir} {
		if err := ProtectDir(dir); err != nil {
			return err
		}
	}
	if err := stopService(); err != nil {
		return err
	}
	removeLeftovers(l.InstallDir)
	if err := copySelf(l.Running, l.Exe()); err != nil {
		return fmt.Errorf("копия в %s: %w", l.Exe(), err)
	}
	if err := enable(); err != nil {
		return err
	}
	if err := ensureService(l.Exe()); err != nil {
		return err
	}
	if err := writeShortcut(l.Shortcut, shortcut{target: l.Exe(), args: "window", workDir: l.InstallDir, icon: l.Exe()}); err != nil {
		return fmt.Errorf("ярлык %s: %w", l.Shortcut, err)
	}
	return register(newAppEntry(l.Exe(), l.InstallDir, l.Version))
}

// Uninstall снимает всё: служба — до снятия правил (иначе вернёт их; останавливать её под общим замком нельзя —
// её обработчик ждёт тот же замок), removeRules, и только если правила сняты — ярлык, запись в «Приложения» и файлы.
// Чего нет — пропускается: снятие можно повторять.
func (l Layout) Uninstall(removeRules func() error) error {
	if err := deleteService(); err != nil {
		return err
	}
	if err := removeRules(); err != nil {
		return err
	}
	var errs []error
	if err := os.Remove(l.Shortcut); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("ярлык %s: %w", l.Shortcut, err))
	}
	errs = append(errs, unregister(), l.removeFiles())
	return errors.Join(errs...)
}

// copySelf копирует запущенный файл на место установленного; это он и есть — ничего. Установленная копия может быть
// занята (открыто окно): занятый exe не перезаписать, но можно переименовать — он уходит в сторону и удаляется.
func copySelf(src, dst string) error {
	if same(src, dst) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "killswitch.exe.*.new")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, cerr := io.Copy(tmp, in)
	serr := tmp.Sync()
	clerr := tmp.Close()
	if err := errors.Join(cerr, serr, clerr); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err == nil {
		return nil
	}
	old, err := moveAside(dst)
	if err != nil {
		return err
	}
	deleteLater(old, "")
	return os.Rename(tmp.Name(), dst)
}

func same(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// moveAside переименовывает файл рядом под одноразовым именем *.old.
func moveAside(path string) (string, error) {
	old := fmt.Sprintf("%s.%d.old", path, time.Now().UnixNano())
	return old, os.Rename(path, old)
}

// removeLeftovers — остатки прошлых обновлений и снятий (*.old, *.new); занятые остаются до следующего раза.
func removeLeftovers(dir string) {
	for _, pattern := range []string{"*.old", "*.new"} {
		paths, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, p := range paths {
			_ = os.Remove(p)
		}
	}
}

// removeFiles удаляет копию программы и каталог установки. Запущенный exe (снятие из «Приложений») себя не удалит:
// он переименовывается и удаляется следом, когда процесс завершится; гарантия — удаление при перезагрузке.
func (l Layout) removeFiles() error {
	removeLeftovers(l.InstallDir)
	// menu.ps1 — копия установщика прежних версий.
	if err := os.Remove(filepath.Join(l.InstallDir, "menu.ps1")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	exe := l.Exe()
	pending := ""
	if err := os.Remove(exe); err != nil && !errors.Is(err, fs.ErrNotExist) {
		if pending, err = moveAside(exe); err != nil {
			return fmt.Errorf("копия %s не удалена: %w", exe, err)
		}
	}
	if pending == "" {
		// Чужие файлы в каталоге не трогаются: каталог тогда остаётся.
		if err := os.Remove(l.InstallDir); err != nil && !errors.Is(err, fs.ErrNotExist) &&
			!errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
			return fmt.Errorf("каталог %s не удалён: %w", l.InstallDir, err)
		}
		return nil
	}
	deleteLater(pending, l.InstallDir)
	return nil
}

// deleteLater удаляет файл (и затем каталог, если он пуст) после выхода процесса: отдельный cmd через несколько
// секунд, а на случай неудачи — при перезагрузке. Удаляется только этот файл и только пустой каталог: новая
// установка, сделанная за это время, остаётся.
func deleteLater(file, dir string) {
	for _, p := range []string{file, dir} {
		if p == "" {
			continue
		}
		if u, err := windows.UTF16PtrFromString(p); err == nil {
			_ = windows.MoveFileEx(u, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return
	}
	cmd := deleteHelper(sys, file, dir)
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}

// deleteHelper — cmd, который через несколько секунд удаляет файл и затем каталог, если он пуст. Только системные
// программы по полному пути и системный текущий каталог: помощник работает с правами администратора, а каталог
// запуска мог выбрать обычный пользователь. /s: cmd снимает только внешнюю пару кавычек, пути с пробелами остаются.
func deleteHelper(sys, file, dir string) *exec.Cmd {
	chain := fmt.Sprintf(`"%s" -n 4 127.0.0.1 >nul & del /f /q "%s"`, filepath.Join(sys, "PING.EXE"), file)
	if dir != "" {
		chain += fmt.Sprintf(` & rmdir "%s"`, dir)
	}
	cmd := exec.Command(filepath.Join(sys, "cmd.exe"))
	cmd.Dir = sys
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /q /s /c "` + chain + `"`, HideWindow: true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP}
	return cmd
}
