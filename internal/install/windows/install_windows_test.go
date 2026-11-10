package windows

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Помощник отложенного удаления — настоящий cmd на временных путях с пробелами: файл и пустой каталог удалены.
func TestDeleteHelperRemovesFileThenEmptyDir(t *testing.T) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "Program Files", "killswitch")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "killswitch.exe.1.old")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := deleteHelper(sys, file, dir).CombinedOutput(); err != nil {
		t.Fatalf("cmd: %v: %s", err, out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("каталог остался: %v", err)
	}
}

// Каталог с чужим файлом не удаляется: помощник удаляет только свой файл и только пустой каталог.
func TestDeleteHelperKeepsNonEmptyDir(t *testing.T) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "kill switch")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "killswitch.exe.1.old")
	keep := filepath.Join(dir, "killswitch.exe")
	for _, p := range []string{file, keep} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = deleteHelper(sys, file, dir).Run()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("свой файл остался: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("новая установка удалена: %v", err)
	}
}
