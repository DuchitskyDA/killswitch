package ui

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

const happExe = `C:\Happ\Happ.exe`

// fakeActions записывает вызовы меню.
type fakeActions struct {
	header      Header
	cfg         policy.Config
	detected    []string
	saveErr     error
	savedMsg    string // итог при saveErr: файл записан, применение не удалось
	transitions []policy.Mode
	checks      int
	saved       [][]byte
}

func (f *fakeActions) Header() Header { return f.header }

func (f *fakeActions) Transition(m policy.Mode) error {
	f.transitions = append(f.transitions, m)
	return nil
}

func (f *fakeActions) Check(context.Context) error { f.checks++; return nil }
func (f *fakeActions) Detect() []string            { return f.detected }

func (f *fakeActions) Profiles() []Profile {
	return []Profile{
		{Name: "happ", Description: "Happ", Layer: policy.Layer{Interfaces: []string{"happ-xray"},
			Trust: []policy.Trust{{Kind: policy.KindProgram, Value: happExe}}}},
		{Name: "wireguard", Description: "WireGuard", Layer: policy.Layer{Interfaces: []string{"wg*"}}},
	}
}

func (f *fakeActions) LoadConfig() (policy.Config, error) { return f.cfg, nil }

func (f *fakeActions) Save(data []byte) (string, error) {
	if f.saveErr != nil {
		return f.savedMsg, f.saveErr
	}
	f.saved = append(f.saved, data)
	return "сохранено", nil
}

// lastSaved — последний сохранённый конфиг, разобранный тем же ParseConfig.
func (f *fakeActions) lastSaved(t *testing.T) policy.Config {
	t.Helper()
	if len(f.saved) == 0 {
		t.Fatal("конфиг не сохранялся")
	}
	c, err := policy.ParseConfig(f.saved[len(f.saved)-1])
	if err != nil {
		t.Fatalf("сохранён неразбираемый конфиг: %v", err)
	}
	return c
}

// runMenu прогоняет меню на ОС goos с вводом-строками.
func runMenu(goos string, f *fakeActions, input ...string) string {
	var out bytes.Buffer
	Run(context.Background(), policy.CapabilitiesFor(goos), f, strings.NewReader(strings.Join(input, "\n")+"\n"), &out)
	return out.String()
}

func cfgWith(t *testing.T, toml string) policy.Config {
	t.Helper()
	c, err := policy.ParseConfig([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var errInvalid = errors.New("не сохранено: trust_mode = strict: нужен хотя бы один tunnel.endpoints")

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("получено %#v, ожидалось %#v", got, want)
	}
}

func contains(t *testing.T, s, sub string, want bool) {
	t.Helper()
	if strings.Contains(s, sub) != want {
		t.Errorf("вхождение %q = %t, ожидалось %t; вывод:\n%s", sub, !want, want, s)
	}
}

func ptrTo[T any](v T) *T { return &v }
