package windows

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
)

var _ backend.ProgramLister = (*Backend)(nil)

// RunningPrograms — запущенные программы с известным путём (backend.ProgramLister).
func (b *Backend) RunningPrograms() ([]backend.Program, error) {
	paths, err := runningPaths()
	if err != nil {
		return nil, err
	}
	return programsOf(paths), nil
}

// runningPaths — пути исполняемых файлов процессов. Процесс, путь которого не отдаётся (системный, уже
// завершился, нет доступа), пропускается.
func runningPaths() ([]string, error) {
	snap, err := xwin.CreateToolhelp32Snapshot(xwin.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("список процессов: %w", err)
	}
	defer xwin.CloseHandle(snap)
	entry := xwin.ProcessEntry32{Size: uint32(unsafe.Sizeof(xwin.ProcessEntry32{}))}
	buf := make([]uint16, xwin.MAX_LONG_PATH)
	var out []string
	for err = xwin.Process32First(snap, &entry); err == nil; err = xwin.Process32Next(snap, &entry) {
		h, err := xwin.OpenProcess(xwin.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if err != nil {
			continue
		}
		size := uint32(len(buf))
		if xwin.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
			out = append(out, xwin.UTF16ToString(buf[:size]))
		}
		xwin.CloseHandle(h)
	}
	if err != xwin.ERROR_NO_MORE_FILES {
		return nil, fmt.Errorf("список процессов: %w", err)
	}
	return out, nil
}

// installed — файлы программы name в обычных местах установки (installDirs). Имя файла сравнивается без учёта
// регистра, как у запущенных процессов: filepath.Glob регистр различает. Каталог, который не читается, пропускается.
func installed(name string, getenv func(string) string) ([]string, error) {
	exe := name + ".exe"
	var out []string
	for _, g := range installDirs {
		dirs, err := filepath.Glob(ExpandProgramGlob(g, getenv))
		if err != nil {
			return nil, fmt.Errorf("места установки: %w", err)
		}
		for _, dir := range dirs {
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if !e.IsDir() && strings.EqualFold(e.Name(), exe) {
					out = append(out, filepath.Join(dir, e.Name()))
				}
			}
		}
	}
	return out, nil
}

// addNamed дописывает в programs найденное по именам repair.names: пути (backend.NameFilesKey) и app-id
// (backend.NameKey) — запущенные процессы с таким именем и места установки. Файл, для которого app-id не
// получить (исчез, недоступен), не попадает ни в правило, ни в показ.
func addNamed(programs map[string][]string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	paths, err := runningPaths()
	if err != nil {
		return err
	}
	running := programsOf(paths)
	for _, n := range names {
		found, err := installed(n, os.Getenv)
		if err != nil {
			return err
		}
		var files, ids []string
		for _, path := range mergePaths(found, named(n, running)) {
			if id, err := wf.AppID(path); err == nil {
				files, ids = append(files, path), append(ids, id)
			}
		}
		programs[backend.NameFilesKey(n)], programs[backend.NameKey(n)] = files, ids
	}
	return nil
}
