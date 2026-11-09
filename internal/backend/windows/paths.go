package windows

import (
	"regexp"
	"strings"
)

var envRef = regexp.MustCompile(`%([A-Za-z0-9_()]+)%`)

// userDirs — пользовательские переменные: под SYSTEM (служба) они указывают в systemprofile, поэтому раскрываются
// в шаблон по всем профилям — одинаково под любой учётной записью (план on и enforce совпадают).
var userDirs = map[string]string{
	"USERPROFILE":  `\Users\*`,
	"APPDATA":      `\Users\*\AppData\Roaming`,
	"LOCALAPPDATA": `\Users\*\AppData\Local`,
}

// ExpandProgramGlob раскрывает %VAR% в шаблоне пути программы. Системные переменные (ProgramFiles, SystemRoot,
// ProgramData) берутся из окружения; неизвестная остаётся как есть (glob ничего не найдёт — fail-closed).
func ExpandProgramGlob(glob string, getenv func(string) string) string {
	return envRef.ReplaceAllStringFunc(glob, func(ref string) string {
		name := strings.ToUpper(strings.Trim(ref, "%"))
		if dir, ok := userDirs[name]; ok {
			drive := getenv("SystemDrive")
			if drive == "" {
				drive = "C:"
			}
			return drive + dir
		}
		if v := getenv(name); v != "" {
			return v
		}
		return ref
	})
}
