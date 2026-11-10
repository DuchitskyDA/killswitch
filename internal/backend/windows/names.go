package windows

import (
	"sort"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/backend"
)

// installDirs — обычные места установки программ: Program Files на глубину 2, Programs в профиле пользователя
// на глубину 3 и .local\bin. Переменные раскрывает ExpandProgramGlob (пользовательские — во всех профилях).
// Глубже не ищем: снимок берётся часто; программу из другого места находит список запущенных процессов.
var installDirs = []string{
	`%ProgramFiles%\*`,
	`%ProgramFiles%\*\*`,
	`%ProgramFiles(x86)%\*`,
	`%ProgramFiles(x86)%\*\*`,
	`%LOCALAPPDATA%\Programs\*`,
	`%LOCALAPPDATA%\Programs\*\*`,
	`%LOCALAPPDATA%\Programs\*\*\*`,
	`%USERPROFILE%\.local\bin`,
}

// programName — имя программы по пути: имя файла без .exe.
func programName(path string) string {
	base := path[strings.LastIndexAny(path, `\/`)+1:]
	if len(base) > 4 && strings.EqualFold(base[len(base)-4:], ".exe") {
		return base[:len(base)-4]
	}
	return base
}

// mergePaths — пути без дублей (без учёта регистра: файловая система Windows его не различает), по порядку.
func mergePaths(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, p := range l {
			if key := strings.ToLower(p); !seen[key] {
				seen[key] = true
				out = append(out, p)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

// programsOf — программы по путям исполняемых файлов: без дублей пути, по имени и пути.
func programsOf(paths []string) []backend.Program {
	var out []backend.Program
	for _, p := range mergePaths(paths) {
		out = append(out, backend.Program{Name: programName(p), Path: p})
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// named — пути программ с именем name (без учёта регистра).
func named(name string, progs []backend.Program) []string {
	var out []string
	for _, p := range progs {
		if strings.EqualFold(p.Name, name) {
			out = append(out, p.Path)
		}
	}
	return out
}
