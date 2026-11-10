package windows

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

const nodeApp = `\device\harddiskvolume3\program files\nodejs\node.exe`

func namedPolicy(mode policy.Mode) policy.Policy {
	p := basePolicy(mode)
	p.Repair = policy.Repair{Names: []string{"node"}}
	return p
}

func TestPlanRepairBlocksProgramsFoundByName(t *testing.T) {
	e := baseEnv()
	e.Programs[backend.NameKey("node")] = []string{nodeApp}
	block := "block w=30 hard app-id==" + strconv.Quote(nodeApp)
	got := plan(t, namedPolicy(policy.ModeRepair), e).Render()
	if !strings.Contains(got, block) {
		t.Errorf("в плане repair нет блока программы, найденной по имени:\n%s", got)
	}
	if on := plan(t, namedPolicy(policy.ModeOn), e).Render(); strings.Contains(on, strconv.Quote(nodeApp)) {
		t.Errorf("программа починки попала в план on:\n%s", on)
	}
}

func TestProgramsOfDropsDuplicatesAndSorts(t *testing.T) {
	got := programsOf([]string{`C:\Tools\zed.exe`, `C:\Program Files\nodejs\node.exe`, `c:\program files\NODEJS\Node.exe`,
		`D:\portable\Node.EXE`, `C:\Windows\System32\wsl.com`})
	want := []backend.Program{
		{Name: "node", Path: `C:\Program Files\nodejs\node.exe`},
		{Name: "Node", Path: `D:\portable\Node.EXE`},
		{Name: "wsl.com", Path: `C:\Windows\System32\wsl.com`},
		{Name: "zed", Path: `C:\Tools\zed.exe`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("получено %+v", got)
	}
}

func TestNamedMatchesIgnoringCase(t *testing.T) {
	progs := programsOf([]string{`C:\a\Node.exe`, `C:\b\node.exe`, `C:\c\nodejs.exe`})
	got := named("NODE", progs)
	if !reflect.DeepEqual(got, []string{`C:\a\Node.exe`, `C:\b\node.exe`}) {
		t.Errorf("получено %v", got)
	}
}

func TestMergePathsIgnoresCase(t *testing.T) {
	got := mergePaths([]string{`C:\Program Files\nodejs\node.exe`}, []string{`c:\program files\nodejs\NODE.exe`, `C:\b\node.exe`})
	if !reflect.DeepEqual(got, []string{`C:\b\node.exe`, `C:\Program Files\nodejs\node.exe`}) {
		t.Errorf("получено %v", got)
	}
}
