package windows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Ярлык пишется во временный каталог и читается обратно оболочкой (WScript.Shell) — как его увидит Проводник.
func TestShortcutReadsBackThroughShell(t *testing.T) {
	target, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lnk := filepath.Join(dir, "killswitch.lnk")
	s := shortcut{target: target, args: "window", workDir: filepath.Dir(target), icon: target}
	if err := writeShortcut(lnk, s); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(lnk)
	if err != nil {
		t.Fatal(err)
	}
	if data[0x15]&0x20 == 0 {
		t.Error("нет флага «Запуск от имени администратора» (байт 0x15, бит 0x20)")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("нет powershell.exe: ярлык не прочитать оболочкой")
	}
	script := `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:KS_TEST_LNK); ` +
		`[Console]::Out.Write(($s.TargetPath, $s.Arguments, $s.WindowStyle, $s.WorkingDirectory, $s.IconLocation) -join '|')`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "KS_TEST_LNK="+lnk)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("WScript.Shell: %v: %s", err, out)
	}
	// Оболочка возвращает длинные имена, временный каталог может быть коротким (8.3) — пути сверяются как файлы.
	got := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(got) != 5 {
		t.Fatalf("ответ оболочки %q", out)
	}
	sameFile := func(a, b string) bool {
		fa, errA := os.Stat(a)
		fb, errB := os.Stat(b)
		return errA == nil && errB == nil && os.SameFile(fa, fb)
	}
	icon, index, _ := strings.Cut(got[4], ",")
	if !sameFile(got[0], target) || got[1] != "window" || got[2] != "7" || !sameFile(got[3], filepath.Dir(target)) ||
		!sameFile(icon, target) || index != "0" {
		t.Errorf("ярлык %q, ожидалась цель %s, window, 7, каталог цели, значок цели", got, target)
	}
}

func TestAppEntryUninstallsWithInstalledExe(t *testing.T) {
	e := newAppEntry(`C:\Program Files\killswitch\killswitch.exe`, `C:\Program Files\killswitch`, "0.2.0")
	if got := e.strings["UninstallString"]; got != `"C:\Program Files\killswitch\killswitch.exe" uninstall` {
		t.Errorf("UninstallString %s", got)
	}
	for _, name := range []string{"DisplayName", "DisplayIcon", "Publisher", "DisplayVersion", "InstallLocation"} {
		if e.strings[name] == "" {
			t.Errorf("нет %s", name)
		}
	}
	if e.dwords["NoModify"] != 1 || e.dwords["NoRepair"] != 1 {
		t.Errorf("NoModify/NoRepair %v", e.dwords)
	}
}
