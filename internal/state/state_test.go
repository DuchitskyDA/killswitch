package state

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	want := State{Gen: 3, Mode: policy.ModeOff, BootID: "b1", PlanHash: "p", AppliedHash: "p",
		Intent:    &Intent{Gen: 4, Target: policy.ModeOn, PlanHash: "q"},
		LastKnown: map[string][]netip.Addr{"tunnel.example.org": {netip.MustParseAddr("203.0.113.2")}},
		UpdatedAt: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	noErr(t, Save(path, want))
	got, err := Load(path)
	noErr(t, err)
	eq(t, got, want)
}

func TestLoadMissingIsNotExist(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), FileName))
	eq(t, errors.Is(err, fs.ErrNotExist), true)
}

func TestLoadGarbageIsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	noErr(t, os.WriteFile(path, []byte(`{"gen": 1, "mode": "on"`), 0o600))
	_, err := Load(path)
	eq(t, errors.Is(err, ErrCorrupt), true)
}

func TestLoadUnknownModeIsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	noErr(t, os.WriteFile(path, []byte(`{"gen": 1, "mode": "maybe"}`), 0o600))
	_, err := Load(path)
	eq(t, errors.Is(err, ErrCorrupt), true)
}

func TestRemoveMissingIsNotError(t *testing.T) {
	noErr(t, Remove(filepath.Join(t.TempDir(), FileName)))
}

func TestAcquireBusyWhileHeldAndFreeAfterRelease(t *testing.T) {
	name := testLockName(t)
	held, release, released := make(chan error), make(chan struct{}), make(chan error)
	go func() {
		l, err := Acquire(name, false)
		held <- err
		<-release
		released <- l.Release()
	}()
	noErr(t, <-held)
	_, busy := Acquire(name, false)
	close(release)
	noErr(t, <-released)
	again, err := Acquire(name, false)
	noErr(t, err)
	eq(t, errors.Is(busy, ErrBusy), true)
	noErr(t, again.Release())
}

func TestLoadTrailingGarbageIsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	noErr(t, os.WriteFile(path, []byte(`{"gen": 1, "mode": "off", "boot_id": "b1"}BROKEN`), 0o600))
	_, err := Load(path)
	eq(t, errors.Is(err, ErrCorrupt), true)
}

func TestLoadFirstInstallIntentIsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	noErr(t, os.WriteFile(path, []byte(`{"gen": 0, "mode": "", "intent": {"gen": 1, "target": "on", "plan_hash": "h"}}`), 0o600))
	st, err := Load(path)
	noErr(t, err)
	eq(t, st.Intent.Target, policy.ModeOn)
}

func TestLoadExtraClosingBraceIsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	noErr(t, os.WriteFile(path, []byte(`{"gen": 2, "mode": "off", "boot_id": "b1"}}`), 0o600))
	_, err := Load(path)
	eq(t, errors.Is(err, ErrCorrupt), true)
}
