package darwin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRunner отвечает готовым выводом по командной строке; очередь ответов, последний повторяется.
type fakeRunner struct {
	replies map[string][]Result
	fails   map[string]bool
	calls   []string
}

func (f *fakeRunner) Run(_ string, name string, args ...string) (Result, error) {
	key := strings.TrimSpace(filepath.Base(name) + " " + strings.Join(args, " "))
	f.calls = append(f.calls, key)
	if f.fails[key] {
		return Result{}, errors.New("сбой " + key)
	}
	q := f.replies[key]
	if len(q) == 0 {
		return Result{}, nil
	}
	if len(q) > 1 {
		f.replies[key] = q[1:]
	}
	return q[0], nil
}

func (f *fakeRunner) on(key string, outs ...string) {
	for _, o := range outs {
		f.replies[key] = append(f.replies[key], Result{Out: o})
	}
}

func (f *fakeRunner) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

const (
	mainDefault = `scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
`
	infoEnabled  = "Status: Enabled for 0 days 00:00:05           Debug: Urgent\n"
	infoDisabled = "Status: Disabled for 0 days 00:00:00          Debug: Urgent\n"
	refsOurs     = `TOKENS:
PID      Process Name                TOKEN                     TIMESTAMP
812      killswitchd                 18446744071234567890      12 secs ago
430      pfctl                       18446744071234567891      40 secs ago
`
	refsForeign = `TOKENS:
PID      Process Name                TOKEN                     TIMESTAMP
430      pfctl                       18446744071234567891      40 secs ago
`
	anchorReadback = `pass out quick on lo0 proto udp from any to 127.0.0.1 port = 9 no state label "killswitch-canary"
pass out quick on lo0 all no state
block return out quick all
`
)

func canaryCounters(packets string) string {
	return `pass out quick on lo0 proto udp from any to 127.0.0.1 port = 9 no state label "killswitch-canary"
  [ Evaluations: 12        Packets: ` + packets + `         Bytes: 87          States: 0     ]
  [ Inserted: uid 0 pid 812 State Creations: 0     ]
block return out quick proto tcp from any port = 61000 to any label "killswitch-probe-tcp-61000"
  [ Evaluations: 40        Packets: ` + packets + `         Bytes: 0           States: 0     ]
block return out quick all
  [ Evaluations: 40        Packets: 9         Bytes: 0           States: 0     ]
`
}

// fixture — backend на фейковом исполнителе и временном каталоге.
type fixture struct {
	t     *testing.T
	b     *Backend
	run   *fakeRunner
	paths Paths
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	p := Paths{Dir: filepath.Join(dir, "ks"), Plist: filepath.Join(dir, Label+".plist"),
		PfctlSrc: filepath.Join(dir, "pfctl"), Log: filepath.Join(dir, "ks.log")}
	exe := filepath.Join(dir, "killswitch-build")
	for _, f := range []string{p.PfctlSrc, exe} {
		if err := os.WriteFile(f, []byte("binary "+f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := &fakeRunner{replies: map[string][]Result{}, fails: map[string]bool{}}
	b := newBackend(r, p)
	b.exe = func() (string, error) { return exe, nil }
	b.canary = func() error { return nil }
	b.wait = func(time.Duration) {}
	return &fixture{t: t, b: b, run: r, paths: p}
}

// healthy — pf включён нашим токеном, штатный основной набор, якорь читается как anchorReadback, канарейка доходит.
func (f *fixture) healthy() {
	f.run.on("pfctl -sr", mainDefault)
	f.run.on("pfctl -a "+Anchor+" -sr", anchorReadback)
	f.run.on("pfctl -s info", infoEnabled)
	f.run.on("pfctl -s References", refsOurs)
	f.run.on("pfctl -a "+Anchor+" -vsr", canaryCounters("3"))
	// Счётчик канарейки растёт только от отправленного пакета.
	f.b.canary = func() error { f.run.on("pfctl -a "+Anchor+" -vsr", canaryCounters("4")); return nil }
}

func (f *fixture) apply(r Rules) {
	f.t.Helper()
	if err := f.b.Apply(r); err != nil {
		f.t.Fatalf("Apply: %v", err)
	}
}

func onRules() Rules {
	return Rules{Mode: "on", Text: headerMode + "on\n" + anchorReadback}
}
