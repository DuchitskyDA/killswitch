package windows

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Места установки: Program Files на глубину 2, Programs в профиле каждого пользователя на глубину 3, .local\bin.
func TestInstalledFindsUsualPlacesForAllUsers(t *testing.T) {
	root := t.TempDir()
	found := []string{
		`pf\nodejs\node.exe`,
		`pf\Vendor\App\node.exe`,
		`pf86\Tool\node.exe`,
		`pf86\Other\Node.EXE`,
		`Users\one\AppData\Local\Programs\App\node.exe`,
		`Users\two\AppData\Local\Programs\Vendor\App\bin\node.exe`,
		`Users\two\.local\bin\node.exe`,
	}
	missed := []string{
		`pf\a\b\c\node.exe`,
		`pf\nodejs\nodejs.exe`,
		`Users\one\Downloads\node.exe`,
	}
	for _, rel := range append(append([]string{}, found...), missed...) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	getenv := func(name string) string {
		return map[string]string{"SystemDrive": root, "PROGRAMFILES": root + `\pf`, "PROGRAMFILES(X86)": root + `\pf86`}[name]
	}
	got, err := installed("node", getenv)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, rel := range found {
		want = append(want, filepath.Join(root, rel))
	}
	if !reflect.DeepEqual(mergePaths(got), mergePaths(want)) {
		t.Errorf("найдено:\n%s\nждали:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Список запущенных программ: процесс теста в нём есть, путь — его исполняемый файл, дублей пути нет.
func TestRunningProgramsListsThisProcessOnce(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	progs, err := (&Backend{}).RunningPrograms()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, p := range progs {
		if strings.EqualFold(p.Path, self) {
			seen++
			if want := programName(self); p.Name != want {
				t.Errorf("имя %q, ждали %q", p.Name, want)
			}
		}
	}
	if seen != 1 {
		t.Errorf("процесс теста %s встречен %d раз", self, seen)
	}
}
