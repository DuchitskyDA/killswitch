//go:build linux

package lab

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/capture"
	"github.com/DuchitskyDA/killswitch/lab/internal/classify"
	"github.com/DuchitskyDA/killswitch/lab/internal/nsguard"
	"github.com/DuchitskyDA/killswitch/lab/internal/probe"
	"github.com/DuchitskyDA/killswitch/lab/internal/services"
	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
	"github.com/DuchitskyDA/killswitch/lab/internal/wgset"
)

// ErrCriteria — прогон закончился, но критерий спайка не выполнен.
var ErrCriteria = errors.New("критерий спайка не выполнен")

type proc struct {
	name string
	cmd  *exec.Cmd
	done chan struct{}
}

type Row struct {
	Tunnel, Stage, Probe, Path string
	Verdict                    classify.Verdict
	Detail                     string
}

type Lab struct {
	ctx   context.Context
	dir   string // /opt/killswitch-lab
	run   string // каталог прогона
	self  string // путь к kslab
	out   io.Writer
	ns    map[string]*nsguard.NS
	mu    sync.Mutex
	flows []capture.Flow
	recv  []services.Entry
	procs []*proc
	mark  int
	rows  []Row
	fatal error
}

type tunnel struct {
	name, iface string
	endpoints   []Endpoint
	up          func() error
	down        func()
	version     string
}

type ignoreErrWriter struct{ w io.Writer }

func (i ignoreErrWriter) Write(p []byte) (int, error) { i.w.Write(p); return len(p), nil }

// Main — подкоманда run.
func Main(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := fs.String("dir", "/opt/killswitch-lab", "каталог лаборатории (bin/, run/)")
	only := fs.String("tunnels", "wireguard,sing-box,xray", "какие туннели проверять")
	timeout := fs.Duration("timeout", 13*time.Minute, "предел прогона")
	if err := fs.Parse(args); err != nil {
		return err
	}
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; cancel() }()

	self, err := os.Executable()
	if err != nil {
		return err
	}
	runDir := filepath.Join(*dir, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	rep, err := os.Create(filepath.Join(runDir, "report.txt"))
	if err != nil {
		return err
	}
	defer rep.Close()
	l := &Lab{ctx: ctx, dir: *dir, run: runDir, self: self, out: io.MultiWriter(rep, ignoreErrWriter{stdout}), ns: map[string]*nsguard.NS{}}
	start := time.Now()
	if err := l.guardDemo(); err != nil {
		return err
	}
	defer l.teardown()
	if err := l.setup(); err != nil {
		return err
	}
	if err := l.startServices(); err != nil {
		return err
	}
	for _, name := range strings.Split(*only, ",") {
		t, err := l.tunnel(strings.TrimSpace(name))
		if err != nil {
			return err
		}
		l.scenario(t)
		if l.fatal != nil {
			return l.fatal
		}
	}
	l.printf("\n== итог (%s)\n", time.Since(start).Round(time.Second))
	ok := l.summary()
	l.printf("память scope: %s\n", memoryPeak())
	if !ok {
		return ErrCriteria
	}
	return nil
}

func (l *Lab) printf(f string, a ...any) { fmt.Fprintf(l.out, f, a...) }

// guardDemo — до любой сетевой операции: защита обязана отказать для корневого ns и чужого имени.
func (l *Lab) guardDemo() error {
	root, err := nsguard.RootIno()
	if err != nil {
		return err
	}
	l.printf("== защита хоста: корневой ns inode %d\n", root)
	for _, p := range []string{"/proc/1/ns/net", "/proc/self/ns/net"} {
		_, err := nsguard.OpenPath(p, 0)
		if !errors.Is(err, nsguard.ErrRootNS) {
			return fmt.Errorf("защита не отказала для %s: %v", p, err)
		}
		l.printf("цель %s → отказ: %v\n", p, err)
	}
	if err := nsguard.CheckName("client"); !errors.Is(err, nsguard.ErrName) {
		return fmt.Errorf("защита пропустила имя без префикса: %v", err)
	}
	l.printf("имя \"client\" → отказ: %v\n", nsguard.CheckName("client"))
	return nil
}

func (l *Lab) do(n *nsguard.NS, argv ...string) error {
	_, err := n.Run(l.ctx, argv...)
	return err
}

func (l *Lab) seq(n *nsguard.NS, cmds ...[]string) error {
	for _, c := range cmds {
		if err := l.do(n, c...); err != nil {
			return err
		}
	}
	return nil
}

func ipAddr(dev, cidr string) []string {
	a := []string{"ip", "addr", "add", cidr, "dev", dev}
	if strings.Contains(cidr, ":") {
		a = append(a, "nodad")
	}
	return a
}

func (l *Lab) setup() error {
	l.printf("\n== топология\n")
	for _, name := range []string{topo.ClientNS, topo.WanNS, topo.VPNNS, topo.InetNS} {
		n, err := nsguard.Create(l.ctx, name)
		if err != nil {
			return err
		}
		l.ns[name] = n
		l.printf("ns %s inode %d\n", name, n.Ino)
	}
	cl, wan, vpn, inet := l.ns[topo.ClientNS], l.ns[topo.WanNS], l.ns[topo.VPNNS], l.ns[topo.InetNS]
	for _, p := range []struct {
		wanIf, peerIf string
		peer          *nsguard.NS
	}{{topo.CaptureIf, topo.PhysIf, cl}, {"wv", "v0", vpn}, {"wi", "i0", inet}} {
		if err := l.do(wan, "ip", "link", "add", p.wanIf, "type", "veth", "peer", "name", p.peerIf); err != nil {
			return err
		}
		if _, err := wan.RunWith(l.ctx, []*nsguard.NS{p.peer}, "", "ip", "link", "set", p.peerIf, "netns", nsguard.FDPath(0)); err != nil {
			return err
		}
	}
	steps := map[*nsguard.NS][][]string{
		wan: {
			ipAddr(topo.CaptureIf, topo.WanCV4.String()+"/24"), ipAddr(topo.CaptureIf, topo.WanCV6.String()+"/64"),
			ipAddr("wv", topo.WanVV4.String()+"/25"), ipAddr("wv", topo.WanVV6.String()+"/64"),
			ipAddr("wi", topo.WanIV4.String()+"/25"), ipAddr("wi", topo.WanIV6.String()+"/64"),
			{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", topo.CaptureIf, "up"},
			{"ip", "link", "set", "wv", "up"}, {"ip", "link", "set", "wi", "up"},
			{"sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"},
			{"ip", "route", "add", topo.InnerV4.String(), "via", topo.VPNV4.String()},
			{"ip", "-6", "route", "add", topo.InnerV6.String(), "via", topo.VPNV6.String()},
		},
		cl: {
			ipAddr(topo.PhysIf, topo.ClientV4.String()+"/24"), ipAddr(topo.PhysIf, topo.ClientV6.String()+"/64"),
			{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", topo.PhysIf, "up"},
			{"ip", "route", "add", "default", "via", topo.WanCV4.String(), "dev", topo.PhysIf, "metric", topo.PhysMetric},
			{"ip", "-6", "route", "add", "default", "via", topo.WanCV6.String(), "dev", topo.PhysIf, "metric", topo.PhysMetric},
		},
		vpn: {
			ipAddr("v0", topo.VPNV4.String()+"/25"), ipAddr("v0", topo.VPNV6.String()+"/64"),
			{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "v0", "up"},
			{"sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"},
			{"ip", "route", "add", "default", "via", topo.WanVV4.String()},
			{"ip", "-6", "route", "add", "default", "via", topo.WanVV6.String()},
		},
		inet: {
			ipAddr("i0", topo.InetV4.String()+"/25"), ipAddr("i0", topo.InetV6.String()+"/64"),
			{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "i0", "up"},
			{"ip", "route", "add", "default", "via", topo.WanIV4.String()},
			{"ip", "-6", "route", "add", "default", "via", topo.WanIV6.String()},
		},
	}
	for _, n := range []*nsguard.NS{wan, cl, vpn, inet} {
		if err := l.seq(n, steps[n]...); err != nil {
			return err
		}
	}
	// link-local адреса проходят DAD: ждём, пока tentative не исчезнут, иначе v6-baseline будет плавать.
	deadline := time.Now().Add(8 * time.Second)
	for _, n := range []*nsguard.NS{wan, cl, vpn, inet} {
		for {
			out, err := n.Run(l.ctx, "ip", "-6", "addr", "show", "tentative")
			if err != nil {
				return err
			}
			if strings.TrimSpace(out) == "" {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s: адреса v6 не вышли из tentative: %s", n.Name, out)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	out, _ := cl.Run(l.ctx, "ip", "-br", "addr")
	l.printf("ksl-client:\n%s", out)
	out, _ = cl.Run(l.ctx, "nft", "list", "ruleset")
	l.printf("nft в ksl-client до проб: %q\n", strings.TrimSpace(out))
	return nil
}

// startJSON запускает подкоманду kslab внутри ns и разбирает её stdout построчно; ждёт строку готовности.
func (l *Lab) startJSON(name string, n *nsguard.NS, onLine func([]byte), argv ...string) error {
	full := append([]string{l.self}, argv...)
	full = append(full, "--expect-ino", strconv.FormatUint(n.Ino, 10))
	cmd, err := n.Cmd(l.ctx, nil, full...)
	if err != nil {
		return err
	}
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=24MiB")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	logf, err := os.Create(filepath.Join(l.run, name+".log"))
	if err != nil {
		return err
	}
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		return err
	}
	p := &proc{name: name, cmd: cmd, done: make(chan struct{})}
	l.procs = append(l.procs, p)
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		once := sync.Once{}
		for sc.Scan() {
			if sc.Text() == topo.ServeReadyMsg {
				once.Do(func() { close(ready) })
				continue
			}
			onLine(sc.Bytes())
		}
	}()
	go func() { cmd.Wait(); logf.Close(); close(p.done) }()
	select {
	case <-ready:
		return nil
	case <-p.done:
		b, _ := os.ReadFile(filepath.Join(l.run, name+".log"))
		err := fmt.Errorf("%s завершился до готовности: %s", name, strings.TrimSpace(string(b)))
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 2 {
			err = fmt.Errorf("%w: %v", nsguard.ErrInner, err)
		}
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("%s не сообщил о готовности", name)
	}
}

// startBin запускает внешний бинарник (sing-box, xray) внутри ns с журналом в файл.
func (l *Lab) startBin(name string, n *nsguard.NS, argv ...string) (*proc, error) {
	cmd, err := n.Cmd(l.ctx, nil, argv...)
	if err != nil {
		return nil, err
	}
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=48MiB")
	logf, err := os.Create(filepath.Join(l.run, name+".log"))
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	p := &proc{name: name, cmd: cmd, done: make(chan struct{})}
	l.procs = append(l.procs, p)
	go func() { cmd.Wait(); logf.Close(); close(p.done) }()
	return p, nil
}

func (l *Lab) stop(p *proc) {
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

func (l *Lab) startServices() error {
	l.printf("\n== сервисы и захват\n")
	err := l.startJSON("inet", l.ns[topo.InetNS], func(b []byte) {
		var e services.Entry
		if json.Unmarshal(b, &e) == nil {
			l.mu.Lock()
			l.recv = append(l.recv, e)
			l.mu.Unlock()
		}
	}, "serve")
	if err != nil {
		return err
	}
	l.printf("ksl-inet: HTTP/80, UDP/443, DNS/53 UDP+TCP на %s и %s; журнал получателя включён\n", topo.InetV4, topo.InetV6)
	err = l.startJSON("capture", l.ns[topo.WanNS], func(b []byte) {
		var f capture.Flow
		if json.Unmarshal(b, &f) == nil {
			l.mu.Lock()
			l.flows = append(l.flows, f)
			l.mu.Unlock()
		}
	}, "capture", "--iface", topo.CaptureIf)
	if err != nil {
		return err
	}
	ok, _ := l.sendMark()
	if !ok {
		return errors.New("захват на WAN не увидел метку положительного контроля")
	}
	l.printf("захват AF_PACKET на ksl-wan/%s: метка контроля видна\n", topo.CaptureIf)
	return nil
}

// sendMark шлёт из ksl-wan в сторону клиента метку и ждёт её в захвате; возвращает индекс конца окна.
func (l *Lab) sendMark() (bool, int) {
	l.mark++
	id := strconv.Itoa(l.mark)
	wan := l.ns[topo.WanNS]
	if _, err := wan.Run(l.ctx, l.self, "mark", "--id", id, "--dst", topo.ClientV4.String(),
		"--expect-ino", strconv.FormatUint(wan.Ino, 10)); err != nil {
		l.checkInner(err)
		return false, 0
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for i := len(l.flows) - 1; i >= 0; i-- {
			if l.flows[i].Mark == id {
				l.mu.Unlock()
				return true, i
			}
		}
		l.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return false, 0
}

type windowObs struct {
	valid bool
	flows []capture.Flow
	recv  []services.Entry
}

func (l *Lab) window(f func() probe.Result) (probe.Result, windowObs) {
	l.mu.Lock()
	fi, ri := len(l.flows), len(l.recv)
	l.mu.Unlock()
	res := f()
	valid, end := l.sendMark()
	time.Sleep(150 * time.Millisecond)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !valid {
		end = len(l.flows)
	}
	obs := windowObs{valid: valid, flows: append([]capture.Flow{}, l.flows[fi:end]...), recv: append([]services.Entry{}, l.recv[ri:]...)}
	return res, obs
}

func (l *Lab) runProbe(p Probe, bind string) probe.Result {
	cl := l.ns[topo.ClientNS]
	out, err := cl.Run(l.ctx, l.self, "probe", "--kind", string(p.Kind), "--dst", p.Dst().String(),
		"--port", strconv.Itoa(int(p.Port)), "--bind", bind, "--timeout", "1500ms",
		"--expect-ino", strconv.FormatUint(cl.Ino, 10))
	var r probe.Result
	if jerr := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); jerr != nil {
		l.checkInner(err)
		return probe.Result{Err: fmt.Sprintf("проба не выполнилась: %v", err)}
	}
	return r
}

func (l *Lab) direct(p Probe) classify.Evidence {
	res, obs := l.window(func() probe.Result { return l.runProbe(p, topo.PhysIf) })
	e := classify.Evidence{Window: obs.valid, AppOK: res.OK, Err: res.Err}
	for _, f := range obs.flows {
		if topo.IsClientPhys(f.Src) && f.Dst == p.Dst() && f.Proto == p.Proto && f.DPort == p.Port {
			e.Captured++
		}
	}
	for _, r := range obs.recv {
		if topo.IsClientPhys(r.Src) && r.Proto == p.Proto && r.Port == p.Port {
			e.Received++
		}
	}
	return e
}

func (l *Lab) viaTunnel(p Probe, t *tunnel) classify.TunnelEvidence {
	res, obs := l.window(func() probe.Result { return l.runProbe(p, "") })
	e := classify.TunnelEvidence{Window: obs.valid, AppOK: res.OK, Echo: res.Echo, Err: res.Err}
	for _, f := range obs.flows {
		if !topo.IsClientPhys(f.Src) {
			continue
		}
		if f.Dst == p.Dst() && f.Proto == p.Proto && f.DPort == p.Port {
			e.Direct++
		}
		for _, ep := range t.endpoints {
			if f.Dst == ep.Addr && f.Proto == ep.Proto && f.DPort == ep.Port {
				e.Transport++
				break
			}
		}
	}
	for _, r := range obs.recv {
		if !topo.IsClientPhys(r.Src) && r.Proto == p.Proto && r.Port == p.Port {
			e.Via++
		}
	}
	return e
}

func (l *Lab) row(t *tunnel, stage, path string, p Probe, v classify.Verdict, detail string) {
	l.rows = append(l.rows, Row{t.name, stage, p.Name, path, v, detail})
	l.printf("  %-8s %-6s %-22s %-12s %s\n", stage, path, p.Name, v, detail)
}

func (l *Lab) applyNFT(text string) error {
	cl := l.ns[topo.ClientNS]
	_, err := cl.RunWith(l.ctx, nil, text, "nft", "-f", "-")
	return err
}

func (l *Lab) scenario(t *tunnel) {
	start := time.Now()
	l.printf("\n== туннель %s\n", t.name)
	if err := t.up(); err != nil {
		if nsguard.IsGuard(err) && l.fatal == nil {
			l.fatal = err
		}
		l.printf("не поднялся: %v\n", err)
		l.rows = append(l.rows, Row{t.name, "up", "-", "-", classify.TunnelFail, err.Error()})
		t.down()
		return
	}
	l.printf("версия: %s\n", t.version)
	base := map[string]classify.Evidence{}
	for _, p := range ServiceProbes {
		v, d := classify.ClassifyTunnel(l.viaTunnel(p, t))
		l.row(t, "baseline", "tunnel", p, v, d)
	}
	for _, p := range DirectProbes() {
		e := l.direct(p)
		base[p.Name] = e
		v := classify.TunnelOK
		if !e.BaselineOK() {
			v = classify.TunnelFail
		}
		l.row(t, "baseline", "direct", p, v, e.String())
	}
	for _, st := range []struct {
		name string
		eps  []Endpoint
	}{{"P1", nil}, {"P2", t.endpoints}} {
		text := NaivePolicy(t.iface, st.eps)
		if err := l.applyNFT(text); err != nil {
			l.printf("nft %s: %v\n", st.name, err)
			l.rows = append(l.rows, Row{t.name, st.name, "-", "-", classify.TunnelFail, err.Error()})
			continue
		}
		out, _ := l.ns[topo.ClientNS].Run(l.ctx, "nft", "list", "table", "inet", "ksl_probe")
		l.printf(" %s, ksl-client:\n%s", st.name, indent(out))
		time.Sleep(300 * time.Millisecond)
		for _, p := range DirectProbes() {
			v, d := classify.Classify(base[p.Name], l.direct(p))
			l.row(t, st.name, "direct", p, v, d)
		}
		for _, p := range ServiceProbes {
			v, d := classify.ClassifyTunnel(l.viaTunnel(p, t))
			l.row(t, st.name, "tunnel", p, v, d)
		}
	}
	if err := l.do(l.ns[topo.ClientNS], "nft", "delete", "table", "inet", "ksl_probe"); err != nil {
		l.printf("снятие таблицы: %v\n", err)
	}
	l.printf(" таблица ksl_probe снята\n")
	for _, p := range DirectProbes() {
		v, d := classify.Classify(base[p.Name], l.direct(p))
		l.row(t, "снято", "direct", p, v, d)
	}
	t.down()
	l.printf("время туннеля %s: %s\n", t.name, time.Since(start).Round(time.Second))
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

// expected — какой вердикт обязан дать этап; false — этап без ожидания (P1/tunnel — находка, не критерий).
func expected(stage, path string, control bool) (classify.Verdict, bool) {
	switch stage + "/" + path {
	case "baseline/tunnel", "P2/tunnel":
		return classify.TunnelOK, true
	case "baseline/direct":
		if control {
			return classify.TunnelFail, true
		}
		return classify.TunnelOK, true
	case "P1/direct", "P2/direct":
		if control {
			return classify.Inconclusive, true
		}
		return classify.Blocked, true
	case "снято/direct":
		if control {
			return classify.Inconclusive, true
		}
		return classify.Leak, true
	case "P1/tunnel":
		return "", false
	}
	return classify.TunnelOK, true // up и прочее: любой FAIL — провал
}

// summary проверяет критерий спайка по таблице.
func (l *Lab) summary() bool {
	ok := len(l.rows) > 0
	var order []string
	counts := map[string]map[string]int{}
	for _, r := range l.rows {
		if counts[r.Tunnel] == nil {
			counts[r.Tunnel] = map[string]int{}
			order = append(order, r.Tunnel)
		}
		counts[r.Tunnel][r.Stage+"/"+r.Path+" "+string(r.Verdict)]++
		want, has := expected(r.Stage, r.Path, strings.Contains(r.Probe, "нет сервера"))
		if has && r.Verdict != want {
			ok = false
			l.printf("НЕ ВЫПОЛНЕНО: %s %s %s %s: %s, ждали %s\n", r.Tunnel, r.Stage, r.Path, r.Probe, r.Verdict, want)
		}
	}
	for _, tn := range order {
		l.printf("%s: %v\n", tn, counts[tn])
	}
	return ok
}

func memoryPeak() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "нет данных"
	}
	path := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "0::"))
	peak, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", path, "memory.peak"))
	if err != nil {
		return path + ": memory.peak недоступен"
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(peak)), 10, 64)
	return fmt.Sprintf("%s memory.peak=%d МиБ", path, n>>20)
}

func (l *Lab) teardown() {
	for i := len(l.procs) - 1; i >= 0; i-- {
		l.stop(l.procs[i])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range []string{topo.ClientNS, topo.VPNNS, topo.InetNS, topo.WanNS} {
		if n, ok := l.ns[name]; ok {
			if err := n.Delete(ctx); err != nil {
				l.printf("удаление %s: %v\n", name, err)
			}
		}
	}
	l.printf("ns лаборатории удалены, процессы остановлены\n")
}

func randomKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// tunnelRoutes — default клиента через туннель; сервер туннеля — через физику.
func (l *Lab) tunnelRoutes(iface string) error {
	return l.seq(l.ns[topo.ClientNS],
		[]string{"ip", "route", "replace", topo.VPNV4.String() + "/32", "via", topo.WanCV4.String(), "dev", topo.PhysIf},
		[]string{"ip", "route", "replace", "default", "dev", iface, "metric", topo.TunnelMetric},
		[]string{"ip", "-6", "route", "replace", "default", "dev", iface, "metric", topo.TunnelMetric},
	)
}

func (l *Lab) dropTunnelRoutes(iface string) {
	cl := l.ns[topo.ClientNS]
	cl.Run(l.ctx, "ip", "route", "del", "default", "dev", iface, "metric", topo.TunnelMetric)
	cl.Run(l.ctx, "ip", "-6", "route", "del", "default", "dev", iface, "metric", topo.TunnelMetric)
	cl.Run(l.ctx, "ip", "route", "del", topo.VPNV4.String()+"/32")
}

func (l *Lab) waitFor(what string, d time.Duration, cond func() bool) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("не дождались: %s", what)
}

func (l *Lab) tunnel(name string) (*tunnel, error) {
	switch name {
	case "wireguard":
		return l.wireguard(), nil
	case "sing-box":
		return l.proxyTunnel("sing-box", "ksb0", topo.SingBoxPort, filepath.Join(l.dir, "bin", "sing-box"), nil), nil
	case "xray":
		return l.proxyTunnel("xray", "kxr0", topo.XrayPort, filepath.Join(l.dir, "bin", "xray"),
			[]string{"198.18.2.1/30", "2001:db8:ffff:2::1/126"}), nil
	}
	return nil, fmt.Errorf("неизвестный туннель %q", name)
}

func (l *Lab) wgset(n *nsguard.NS, c wgset.Config) error {
	b, _ := json.Marshal(c)
	_, err := n.RunWith(l.ctx, nil, string(b), l.self, "wgset", "--expect-ino", strconv.FormatUint(n.Ino, 10))
	return l.checkInner(err)
}

// checkInner: подкоманда kslab внутри ns вышла с кодом 2 — её сверка inode отказала; прогон прерывается с кодом 2.
// Только для собственных подкоманд: ip и nft тоже выходят с 2 на обычных ошибках.
func (l *Lab) checkInner(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		err = fmt.Errorf("%w: %v", nsguard.ErrInner, err)
		if l.fatal == nil {
			l.fatal = err
		}
	}
	return err
}

func (l *Lab) wireguard() *tunnel {
	t := &tunnel{name: "wireguard", iface: "wg0",
		endpoints: []Endpoint{{topo.VPNV4, topo.WGServerPort, "udp"}}}
	cl, vpn := l.ns[topo.ClientNS], l.ns[topo.VPNNS]
	t.up = func() error {
		cpriv, cpub, err := wgset.GenerateKeys()
		if err != nil {
			return err
		}
		spriv, spub, err := wgset.GenerateKeys()
		if err != nil {
			return err
		}
		if err := l.do(vpn, "ip", "link", "add", "kswg-s", "type", "wireguard"); err != nil {
			return err
		}
		if err := l.wgset(vpn, wgset.Config{Iface: "kswg-s", PrivateKey: spriv, ListenPort: topo.WGServerPort,
			Peers: []wgset.Peer{{PublicKey: cpub, Allowed: []string{"198.18.0.2/32", "2001:db8:ffff::2/128"}}}}); err != nil {
			return err
		}
		if err := l.seq(vpn, ipAddr("kswg-s", "198.18.0.1/24"), ipAddr("kswg-s", "2001:db8:ffff::1/64"),
			[]string{"ip", "link", "set", "kswg-s", "up"}); err != nil {
			return err
		}
		// Интерфейс создаётся внутри ksl-client: его UDP-сокет живёт в том же ns и выходит через c0.
		if err := l.do(cl, "ip", "link", "add", "wg0", "type", "wireguard"); err != nil {
			return err
		}
		if err := l.wgset(cl, wgset.Config{Iface: "wg0", PrivateKey: cpriv, ListenPort: topo.WGClientPort,
			Peers: []wgset.Peer{{PublicKey: spub, Endpoint: fmt.Sprintf("%s:%d", topo.VPNV4, topo.WGServerPort),
				Allowed: []string{"0.0.0.0/0", "::/0"}}}}); err != nil {
			return err
		}
		if err := l.seq(cl, ipAddr("wg0", "198.18.0.2/24"), ipAddr("wg0", "2001:db8:ffff::2/64"),
			[]string{"ip", "link", "set", "wg0", "up"}); err != nil {
			return err
		}
		if err := l.tunnelRoutes("wg0"); err != nil {
			return err
		}
		mod, _ := os.ReadFile("/sys/module/wireguard/version")
		t.version = "модуль ядра wireguard " + strings.TrimSpace(string(mod))
		if v, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			t.version += ", ядро " + strings.TrimSpace(string(v))
		}
		ss, _ := cl.Run(l.ctx, "ss", "-Hlunp")
		l.printf("UDP-сокеты в ksl-client: %s\n", strings.Join(strings.Fields(ss), " "))
		return nil
	}
	t.down = func() {
		show, err := cl.Run(l.ctx, l.self, "wgset", "--show", "wg0", "--expect-ino", strconv.FormatUint(cl.Ino, 10))
		if err == nil {
			l.printf("wg0: %s", show)
		}
		l.dropTunnelRoutes("wg0")
		cl.Run(l.ctx, "ip", "link", "del", "wg0")
		vpn.Run(l.ctx, "ip", "link", "del", "kswg-s")
	}
	return t
}

// proxyTunnel — sing-box или xray: сервер в ksl-vpn, клиент с TUN в ksl-client.
func (l *Lab) proxyTunnel(name, iface string, port uint16, bin string, tunAddrs []string) *tunnel {
	t := &tunnel{name: name, iface: iface,
		endpoints: []Endpoint{{topo.VPNV4, port, "tcp"}, {topo.VPNV4, port, "udp"}}}
	cl, vpn := l.ns[topo.ClientNS], l.ns[topo.VPNNS]
	var srvP, cliP *proc
	t.up = func() error {
		if _, err := os.Stat(bin); err != nil {
			return fmt.Errorf("нет бинарника: %v", err)
		}
		gen := SingBoxConfigs
		check := func(cfg string) []string { return []string{bin, "check", "-c", cfg} }
		run := func(cfg string) []string { return []string{bin, "run", "-c", cfg, "-D", l.run} }
		verArgs := []string{bin, "version"}
		if name == "xray" {
			gen = XrayConfigs
			check = func(cfg string) []string { return []string{bin, "run", "-test", "-c", cfg} }
			run = func(cfg string) []string { return []string{bin, "run", "-c", cfg} }
		}
		ver, err := cl.Run(l.ctx, verArgs...)
		if err != nil {
			return err
		}
		t.version = strings.SplitN(strings.TrimSpace(ver), "\n", 2)[0]
		srv, cli, err := gen(randomKey())
		if err != nil {
			return err
		}
		srvCfg, cliCfg := filepath.Join(l.run, name+"-server.json"), filepath.Join(l.run, name+"-client.json")
		if err := os.WriteFile(srvCfg, srv, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(cliCfg, cli, 0o600); err != nil {
			return err
		}
		if _, err := vpn.Run(l.ctx, check(srvCfg)...); err != nil {
			return fmt.Errorf("проверка конфига сервера: %w", err)
		}
		if _, err := cl.Run(l.ctx, check(cliCfg)...); err != nil {
			return fmt.Errorf("проверка конфига клиента: %w", err)
		}
		if srvP, err = l.startBin(name+"-server", vpn, run(srvCfg)...); err != nil {
			return err
		}
		if err := l.waitFor(name+" сервер слушает", 10*time.Second, func() bool {
			out, _ := vpn.Run(l.ctx, "ss", "-Hltn", fmt.Sprintf("sport = :%d", port))
			return strings.TrimSpace(out) != ""
		}); err != nil {
			return l.withLog(err, name+"-server")
		}
		if cliP, err = l.startBin(name+"-client", cl, run(cliCfg)...); err != nil {
			return err
		}
		if err := l.waitFor(iface+" поднят", 10*time.Second, func() bool {
			out, err := cl.Run(l.ctx, "ip", "-br", "link", "show", iface)
			return err == nil && (strings.Contains(out, "UP") || strings.Contains(out, "UNKNOWN"))
		}); err != nil {
			return l.withLog(err, name+"-client")
		}
		for _, a := range tunAddrs {
			if err := l.do(cl, ipAddr(iface, a)...); err != nil {
				return err
			}
		}
		if err := l.tunnelRoutes(iface); err != nil {
			return err
		}
		out, _ := cl.Run(l.ctx, "ip", "-br", "addr", "show", iface)
		l.printf("%s в ksl-client: %s\n", iface, strings.TrimSpace(out))
		return nil
	}
	t.down = func() {
		l.dropTunnelRoutes(iface)
		for _, p := range []*proc{cliP, srvP} {
			if p != nil {
				l.stop(p)
			}
		}
		for _, n := range []string{name + "-client", name + "-server"} {
			if b, err := os.ReadFile(filepath.Join(l.run, n+".log")); err == nil && len(strings.TrimSpace(string(b))) > 0 {
				l.printf("журнал %s (хвост):\n%s", n, indent(tail(string(b), 6)))
			}
		}
	}
	return t
}

func (l *Lab) withLog(err error, name string) error {
	b, _ := os.ReadFile(filepath.Join(l.run, name+".log"))
	return fmt.Errorf("%w; журнал %s: %s", err, name, tail(string(b), 8))
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
