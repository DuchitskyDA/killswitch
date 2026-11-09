package windows

import "testing"

func sysEnv(name string) string {
	return map[string]string{"SystemDrive": "D:", "PROGRAMFILES": `D:\Program Files`, "LOCALAPPDATA": `C:\Windows\system32\config\systemprofile\AppData\Local`}[name]
}

func TestExpandUserDirIsAccountIndependent(t *testing.T) {
	got := ExpandProgramGlob(`%LocalAppData%\Happ\happ.exe`, sysEnv)
	if got != `D:\Users\*\AppData\Local\Happ\happ.exe` {
		t.Errorf("получено %q", got)
	}
}

func TestExpandSystemVar(t *testing.T) {
	got := ExpandProgramGlob(`%ProgramFiles%\Happ\happ.exe`, sysEnv)
	if got != `D:\Program Files\Happ\happ.exe` {
		t.Errorf("получено %q", got)
	}
}

func TestExpandUnknownVarStays(t *testing.T) {
	got := ExpandProgramGlob(`%NOPE%\x.exe`, sysEnv)
	if got != `%NOPE%\x.exe` {
		t.Errorf("получено %q", got)
	}
}
