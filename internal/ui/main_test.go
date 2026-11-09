package ui

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Главное меню Windows: 1 вкл, 2 починка, 3 выкл, 4 проверка, 5 настройки, 0 выход.
// Linux и macOS — без починки: 1 вкл, 2 выкл, 3 проверка, 4 настройки.

func TestOnCallsTransitionOn(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, "1", "0")
	eq(t, f.transitions, []policy.Mode{policy.ModeOn})
}

func TestRepairOnWindows(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, "2", "0")
	eq(t, f.transitions, []policy.Mode{policy.ModeRepair})
}

func TestRepairHiddenOnLinux(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("linux", f, "2", "0")
	eq(t, f.transitions, []policy.Mode{policy.ModeOff})
	contains(t, out, "Починка", false)
}

func TestCheckRunsCheck(t *testing.T) {
	f := &fakeActions{}
	runMenu("windows", f, "4", "0")
	eq(t, f.checks, 1)
}

func TestUnknownItemAsksAgain(t *testing.T) {
	f := &fakeActions{}
	out := runMenu("windows", f, "9", "1", "0")
	contains(t, out, "нет такого пункта", true)
	eq(t, f.transitions, []policy.Mode{policy.ModeOn})
}

func TestEndOfInputExits(t *testing.T) {
	f := &fakeActions{}
	var out bytes.Buffer
	Run(context.Background(), policy.CapabilitiesFor("windows"), f, &bytes.Buffer{}, &out)
	eq(t, len(f.transitions), 0)
}

func TestCancelledContextExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, w := io.Pipe() // ввод не кончается: выйти можно только по отмене
	defer w.Close()
	f := &fakeActions{}
	Run(ctx, policy.CapabilitiesFor("windows"), f, r, io.Discard)
	eq(t, len(f.transitions), 0)
}

func TestHeaderShowsModeTunnelAndLeak(t *testing.T) {
	f := &fakeActions{header: Header{Mode: policy.ModeOn, Active: true,
		Tunnels: []Tunnel{{Name: "happ-xray", Up: true}}, Notes: []string{"LEAK wfp-tie: чужой permit"}}}
	out := runMenu("windows", f, "0")
	contains(t, out, "killswitch — защита: ВКЛ (on), туннель: happ-xray ▲", true)
	contains(t, out, "LEAK wfp-tie: чужой permit", true)
}

func TestHeaderOffMode(t *testing.T) {
	f := &fakeActions{header: Header{Mode: policy.ModeOff, Active: true}}
	out := runMenu("linux", f, "0")
	contains(t, out, "защита: ВЫКЛ до перезагрузки (off), туннель: не найден", true)
}
