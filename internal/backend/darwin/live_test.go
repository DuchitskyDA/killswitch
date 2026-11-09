//go:build darwin && darwinlive

// Живые тесты: только на одноразовом раннере macOS под root, после `killswitch on` (smoke-darwin.yml).
// Политика дыма: доверены root, пользователь раннера и _mdnsresponder; пробы — от KS_PROBE_USER.
package darwin

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

const liveTarget = "1.1.1.1"

func livePhysical(t *testing.T, b *Backend) env.Iface {
	t.Helper()
	e, err := b.Snapshot(policy.Policy{})
	if err != nil || e.BootID == "" {
		t.Fatalf("Snapshot: %v, boot id %q", err, e.BootID)
	}
	for _, i := range e.Ifaces {
		if _, ok := i.SourceAddr(true); ok && i.Physical && i.Up {
			return i
		}
	}
	t.Fatalf("нет поднятого физического интерфейса с v4: %+v", e.Ifaces)
	return env.Iface{}
}

// probeAs шлёт пакет от пробного пользователя с заданного порта-источника; true — ответ получен.
func probeAs(t *testing.T, proto string, port uint16, dst string, dport int) bool {
	t.Helper()
	user := os.Getenv("KS_PROBE_USER")
	if user == "" {
		t.Fatal("KS_PROBE_USER не задан")
	}
	args := []string{"-u", user, "/usr/bin/nc", "-w", "2", "-p", strconv.Itoa(int(port))}
	if proto == "udp" {
		args = append(args, "-u")
	} else {
		args = append(args, "-z", "-G", "2")
	}
	cmd := exec.Command("/usr/bin/sudo", append(args, dst, strconv.Itoa(dport))...)
	if proto == "udp" {
		cmd.Stdin = strings.NewReader("x")
	}
	out, err := cmd.CombinedOutput()
	t.Logf("проба %s :%d → %s:%d: err=%v %s", proto, port, dst, dport, err, out)
	return err == nil && proto == "tcp" // UDP-ответ nc не различает: судим только по свидетельству
}

func TestLiveDirectProbeDroppedWithEvidence(t *testing.T) {
	b := New()
	phys := livePhysical(t, b)
	src, _ := phys.SourceAddr(true)
	for _, c := range []struct {
		proto string
		port  uint16
		dport int
	}{{"tcp", probe.SrcPortFirst + 10, 80}, {"udp", probe.SrcPortFirst + 11, 53}} {
		id := probe.ProbeID{Proto: c.proto, Src: netip.AddrPortFrom(src, c.port),
			Dst: netip.AddrPortFrom(netip.MustParseAddr(liveTarget), uint16(c.dport)), Iface: phys.Name, At: time.Now()}
		if err := b.BeforeProbe(id); err != nil {
			t.Fatalf("BeforeProbe: %v", err)
		}
		if probeAs(t, c.proto, c.port, liveTarget, c.dport) {
			t.Errorf("%s: прямая проба получила ответ мимо туннеля", c.proto)
		}
		dropped, err := b.Evidence(id, id.At)
		if err != nil || !dropped {
			t.Errorf("%s: нет свидетельства отброса нашим правилом: %t %v", c.proto, dropped, err)
		}
	}
}

func TestLiveBindControlChoosesInterface(t *testing.T) {
	b := New()
	phys := livePhysical(t, b)
	addr := netip.MustParseAddrPort(liveTarget + ":80")
	get := func(i env.Iface) error {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return health.HTTPGet(ctx, &net.Dialer{Control: b.BindControl(i)}, addr, "/")
	}
	if err := get(phys); err != nil {
		t.Errorf("root доверен: HTTP через %s должен пройти: %v", phys.Name, err)
	}
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	if err := get(env.Iface{Name: "lo0", Index: lo.Index}); err == nil {
		t.Error("сокет, привязанный к lo0, не должен дойти до внешнего адреса")
	}
}

func TestLiveStatusHealthy(t *testing.T) {
	s, err := New().Status()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Active || s.Mode != policy.ModeOn || len(s.Structural) != 0 || !s.AnchorOK || s.Token == "" {
		t.Errorf("после on: активна, on, без находок, канарейка дошла, токен есть: %+v", s)
	}
}
