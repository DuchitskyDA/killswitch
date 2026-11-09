package main

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/backend/fake"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/state"
	"github.com/DuchitskyDA/killswitch/profiles"
)

const wireguardExe = `C:\Program Files\WireGuard\wireguard.exe`

const baseConfig = `profile = "example"
[check]
targets = ["203.0.113.130"]
`

const tunnelUpConfig = baseConfig + `[dns]
mode = "tunnel-up"
health = "http://198.18.0.1:80/"
`

type harness struct {
	t      *testing.T
	dir    string
	fb     *fake.Backend
	prober *fakeProber
	out    bytes.Buffer
	err    bytes.Buffer
	locks  int // захваты общего замка
}

type fakeProber struct{ answered bool }

func (f *fakeProber) Tunnel(context.Context, probe.Service, netip.Addr, env.Iface) error { return nil }

func (f *fakeProber) Direct(context.Context, probe.Service, probe.ProbeID, env.Iface) (bool, error) {
	return f.answered, nil
}

func newHarness(t *testing.T, config string) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), prober: &fakeProber{}}
	h.fb = &fake.Backend{Caps: policy.CapabilitiesFor("windows"), Env: env.Env{
		OS: "windows", BootID: "boot-1",
		Ifaces: []env.Iface{
			{Name: "wg-example", Index: 7, Up: true},
			{Name: "Ethernet", Index: 2, Up: true, Physical: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}},
		},
		Programs: map[string][]string{wireguardExe: {wireguardExe}},
	}}
	noErr(t, os.WriteFile(filepath.Join(h.dir, "config.toml"), []byte(config), 0o600))
	return h
}

func (h *harness) deps() deps {
	return deps{
		goos:     "windows",
		dir:      h.dir,
		backend:  func() (backend.Backend, error) { return h.fb, nil },
		lock:     func(string) (func(), error) { h.locks++; return func() {}, nil },
		now:      func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) },
		out:      &h.out,
		err:      &h.err,
		profiles: profiles.FS,
		glob: func(p string) ([]string, error) {
			if p == wireguardExe {
				return []string{p}, nil
			}
			return nil, nil
		},
		prober: func(backend.Backend) probe.Prober { return h.prober },
	}
}

func (h *harness) run(args ...string) int {
	return run(context.Background(), args, h.deps())
}

// reconcile — один шаг enforce.
func (h *harness) reconcile(hs env.HealthState) error {
	a := &app{d: h.deps(), b: h.fb, configPath: filepath.Join(h.dir, "config.toml")}
	_, err := a.reconcile(hs)
	return err
}

func (h *harness) state() state.State {
	h.t.Helper()
	st, err := state.Load(filepath.Join(h.dir, state.FileName))
	noErr(h.t, err)
	return st
}

func (h *harness) writeState(data string) {
	noErr(h.t, os.WriteFile(filepath.Join(h.dir, state.FileName), []byte(data), 0o600))
}

func (h *harness) installedMode() policy.Mode {
	if h.fb.Installed == nil {
		return ""
	}
	return h.fb.Installed.Mode
}

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("получено %#v, ожидалось %#v", got, want)
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
}
