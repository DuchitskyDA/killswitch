//go:build linux

package lab

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

const (
	stateDir    = "/var/lib/killswitch"
	unitDir     = "/etc/systemd/system"
	earlyUnit   = unitDir + "/killswitch-early.service"
	enforceUnit = unitDir + "/killswitch.service"
)

// acc — прогон приёмки одного клиента против настоящего killswitch.
type acc struct {
	*Lab
	c       ClientDef
	ksBin   string          // бинарник killswitch
	preOn   string          // nft (без своей таблицы), маршруты и правила ksl-client до on — для сценария 6
	tunBase map[string]bool // проба через туннель прошла до on
	stub    string          // каталог заглушки systemctl
	killer  string          // каталог обёртки nft, убивающей killswitch на загрузке таблицы (сценарий 8)
	realNFT string
	mnt     *nsguard.MountNS
	checks  []Check
	base    map[string]classify.Evidence // baseline прямых проб (до on)
	pw      string
	wgKeys  [4]string // cpriv, cpub, spriv, spub
	cliP    *proc
	srvP    *proc
	enf     *proc
	iface   string // текущий интерфейс клиента
	cgAbs   string // дочерний cgroup доверенного клиента (xray)
	cgRel   string
	cgDir   *os.File
	results string
}

// Accept — подкоманда accept: все сценарии для одного клиента; итог — results.json и report.txt в каталоге прогона.
func Accept(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	dir := fs.String("dir", "/opt/killswitch-lab", "каталог лаборатории (bin/, stub/, run-<клиент>/)")
	client := fs.String("client", "wireguard", "wireguard | sing-box | sing-box-ar | xray")
	timeout := fs.Duration("timeout", 13*time.Minute, "предел прогона")
	if err := fs.Parse(args); err != nil {
		return err
	}
	def, ok := Clients[*client]
	if !ok {
		return fmt.Errorf("неизвестный клиент %q", *client)
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
	runDir := filepath.Join(*dir, "run-"+def.Name)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	rep, err := os.Create(filepath.Join(runDir, "report.txt"))
	if err != nil {
		return err
	}
	defer rep.Close()
	realNFT, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	a := &acc{
		Lab: &Lab{ctx: ctx, dir: *dir, run: runDir, self: self, out: io.MultiWriter(rep, ignoreErrWriter{stdout}), ns: map[string]*nsguard.NS{}},
		c:   def, ksBin: filepath.Join(*dir, "bin", "killswitch"), stub: filepath.Join(*dir, "stub"),
		killer: filepath.Join(*dir, "stub-kill"), realNFT: realNFT, base: map[string]classify.Evidence{}, pw: randomKey(),
		results: filepath.Join(runDir, "results.json"),
	}
	start := time.Now()
	if err := a.guardDemo(); err != nil {
		return err
	}
	defer a.teardownAll()
	aborted := a.all()
	if aborted != nil {
		a.printf("ПРЕРВАНО: %v\n", aborted)
		a.save()
		if nsguard.IsGuard(aborted) {
			return aborted
		}
	}
	a.save()
	a.printf("\n== итог %s (%s), память: %s\n", def.Name, time.Since(start).Round(time.Second), memoryPeak())
	failed := 0
	for _, c := range a.checks {
		if c.Status == Fail {
			failed++
		}
	}
	a.printf("проверок %d, FAIL %d\n%s", len(a.checks), failed, RenderTable(Summarize(a.checks)))
	if a.fatal != nil {
		return a.fatal
	}
	if aborted != nil {
		// Сценарии не дошли до конца (подготовка стенда, таймаут): это не приёмка, даже если FAIL нет.
		return fmt.Errorf("приёмка прервана: %w", aborted)
	}
	if failed > 0 {
		return fmt.Errorf("%w: FAIL %d", ErrCriteria, failed)
	}
	return nil
}

func (a *acc) save() {
	data, _ := json.MarshalIndent(a.checks, "", "  ")
	_ = os.WriteFile(a.results, data, 0o600)
}

// add записывает проверку.
func (a *acc) add(scn, fam, name string, st Status, detail string) {
	a.checks = append(a.checks, Check{Scenario: scn, Client: a.c.Name, Family: fam, Name: name, Status: st, Detail: detail,
		Log: a.c.Name + "/report.txt"})
	a.printf("  [%s] %s %s %s: %s\n", st, scn, fam, name, detail)
}

func (a *acc) expect(scn, fam, name string, ok bool, detail string) bool {
	st := Pass
	if !ok {
		st = Fail
	}
	a.add(scn, fam, name, st, detail)
	return ok
}

func famOf(p Probe) string { return "v" + strconv.Itoa(p.Family) }

// Наборы проб.
var (
	shortProbes = []Probe{ServiceProbes[0], ServiceProbes[1], ServiceProbes[2], ServiceProbes[3]}
	lanProbes   = []Probe{
		{"lan-http4", probe.HTTP, 4, topo.HTTPPort, "tcp", false},
		{"lan-http6", probe.HTTP, 6, topo.HTTPPort, "tcp", false},
		{"lan-dns-udp4", probe.DNSUDP, 4, topo.DNSPort, "udp", false},
		{"lan-dns-tcp4", probe.DNSTCP, 4, topo.DNSPort, "tcp", false},
		{"lan-dns-udp6", probe.DNSUDP, 6, topo.DNSPort, "udp", false},
		{"lan-dns-tcp6", probe.DNSTCP, 6, topo.DNSPort, "tcp", false},
	}
)

func dstOf(p Probe) netip.Addr {
	if strings.HasPrefix(p.Name, "lan-") {
		return topo.Lan(p.Family)
	}
	return p.Dst()
}

// popts — от чьего имени и как идёт проба.
type popts struct {
	bind  string // интерфейс; "" — по маршруту
	uid   int    // 0 — root
	sport uint16
	mark  uint32
	cg    *os.File // запустить в этом cgroup
}

var nobody = popts{uid: topo.NobodyUID}

// direct — прямая проба «программы» через c0. При sing-box auto_redirect — от uid, исключённого клиентом (exclude_uid):
// иначе redirect перехватывает TCP даже с привязкой к c0, и прямого пути для baseline нет.
func (a *acc) direct() popts {
	uid := a.c.DirectUID
	if uid == 0 {
		uid = topo.NobodyUID
	}
	return popts{uid: uid, bind: topo.PhysIf}
}

func (a *acc) runProbeOpts(p Probe, o popts) probe.Result {
	cl := a.ns[topo.ClientNS]
	argv := []string{a.self, "probe", "--kind", string(p.Kind), "--dst", dstOf(p).String(),
		"--port", strconv.Itoa(int(p.Port)), "--bind", o.bind, "--timeout", "1500ms",
		"--uid", strconv.Itoa(o.uid), "--sport", strconv.Itoa(int(o.sport)), "--mark", strconv.FormatUint(uint64(o.mark), 10),
		"--expect-ino", strconv.FormatUint(cl.Ino, 10)}
	cmd, err := cl.Cmd(a.ctx, nil, argv...)
	if err != nil {
		a.checkGuard(err)
		return probe.Result{Err: err.Error()}
	}
	if o.cg != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(o.cg.Fd())}
	}
	out, err := cmd.Output()
	var r probe.Result
	if jerr := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &r); jerr != nil {
		a.checkInner(err)
		return probe.Result{Err: fmt.Sprintf("проба не выполнилась: %v", err)}
	}
	return r
}

func (a *acc) checkGuard(err error) {
	if nsguard.IsGuard(err) && a.fatal == nil {
		a.fatal = err
	}
}

// evidence — проба под окном захвата: ответ, пакеты от адресов клиента на линии c0 к цели, записи получателя.
func (a *acc) evidence(p Probe, o popts) (classify.Evidence, probe.Result) {
	res, obs := a.window(func() probe.Result { return a.runProbeOpts(p, o) })
	dst := dstOf(p)
	e := classify.Evidence{Window: obs.valid, AppOK: res.OK, Err: res.Err}
	for _, f := range obs.flows {
		if (topo.IsClientPhys(f.Src) || topo.IsClientLAN(f.Src)) && f.Dst == dst && f.Proto == p.Proto && f.DPort == p.Port {
			e.Captured++
		}
	}
	for _, r := range obs.recv {
		if (topo.IsClientPhys(r.Src) || topo.IsClientLAN(r.Src)) && r.Dst == dst && r.Proto == p.Proto && r.Port == p.Port {
			e.Received++
		}
	}
	return e, res
}

func (a *acc) tunnelEvidence(p Probe) classify.TunnelEvidence {
	res, obs := a.window(func() probe.Result { return a.runProbeOpts(p, nobody) })
	e := classify.TunnelEvidence{Window: obs.valid, AppOK: res.OK, Echo: res.Echo, Err: res.Err}
	for _, f := range obs.flows {
		if topo.IsClientPhys(f.Src) && f.Dst == p.Dst() && f.Proto == p.Proto && f.DPort == p.Port {
			e.Direct++
		}
	}
	for _, r := range obs.recv {
		if !topo.IsClientPhys(r.Src) && r.Dst == p.Dst() && r.Proto == p.Proto && r.Port == p.Port {
			e.Via++
		}
	}
	return e
}

// blocked — прямая или по маршруту проба обязана дать BLOCKED против baseline той же прямой пробы.
func (a *acc) blocked(scn string, p Probe, o popts, what string) bool {
	e, _ := a.evidence(p, o)
	v, d := classify.Classify(a.base[p.Name], e)
	return a.expect(scn, famOf(p), what+" "+p.Name, v == classify.Blocked, string(v)+" "+d)
}

// open — проба обязана пройти: ответ и все свидетели.
func (a *acc) open(scn string, p Probe, o popts, what string) bool {
	e, _ := a.evidence(p, o)
	return a.expect(scn, famOf(p), what+" "+p.Name, e.BaselineOK(), e.String())
}

// viaTunnel — проба по маршруту обязана пройти через туннель. Если та же проба не прошла и до on (клиент или стенд её
// не пропускают), killswitch тут не проверить — NOT_TESTED.
func (a *acc) viaTunnel(scn string, p Probe) bool {
	v, d := classify.ClassifyTunnel(a.tunnelEvidence(p))
	if a.tunBase != nil && !a.tunBase[p.Name] {
		a.add(scn, famOf(p), "через туннель "+p.Name, NotTested, "и без killswitch не прошла: "+string(v)+" "+d)
		return false
	}
	return a.expect(scn, famOf(p), "через туннель "+p.Name, v == classify.TunnelOK, string(v)+" "+d)
}

// ---- топология

func (a *acc) all() error {
	if err := a.topology(); err != nil {
		return err
	}
	if err := a.startAll(); err != nil {
		return err
	}
	if err := a.mountNS(); err != nil {
		return err
	}
	if a.c.Cgroup {
		if err := a.makeCgroup(); err != nil {
			return err
		}
	}
	a.notTestedOpenVPN()
	if err := a.serversUp(); err != nil {
		return err
	}
	steps := []struct {
		scn, name string
		f         func() error
	}{
		{"1", "baseline", a.baseline}, {"1", "1", a.s1}, {"3", "3 LAN", a.s3open}, {"9", "9 и 10", a.s9}, {"5", "5", a.s5},
		{"6", "6", a.s6}, {"2", "2", a.s2}, {"4", "4", a.s4}, {"3", "3 tunnel-up и r6-зомби", a.s3tunnelUp}, {"7", "7", a.s7},
		{"2", "strict: 2, (а), (г), r6-маршрут", a.strict}, {"8", "8", a.s8},
	}
	for _, s := range steps {
		if a.ctx.Err() != nil {
			return a.ctx.Err()
		}
		a.printf("\n== %s: %s\n", a.c.Name, s.name)
		t := time.Now()
		if err := s.f(); err != nil {
			a.add(s.scn, "-", "этап "+s.name, Fail, err.Error())
			if a.fatal != nil || nsguard.IsGuard(err) {
				return err
			}
		}
		a.printf("  (этап %s: %s)\n", s.name, time.Since(t).Round(time.Second))
		a.save()
	}
	return nil
}

func (a *acc) topology() error {
	a.printf("== топология\n")
	for _, name := range []string{topo.WanNS, topo.PeerNS, topo.InetNS, topo.MountNS} {
		n, err := nsguard.Create(a.ctx, name)
		if err != nil {
			return err
		}
		a.ns[name] = n
		a.printf("ns %s inode %d\n", name, n.Ino)
	}
	wan, peer, inet := a.ns[topo.WanNS], a.ns[topo.PeerNS], a.ns[topo.InetNS]
	for _, p := range []struct {
		wanIf, peerIf string
		peer          *nsguard.NS
	}{{"wv", "v0", peer}, {"wi", "i0", inet}} {
		if err := a.do(wan, "ip", "link", "add", p.wanIf, "type", "veth", "peer", "name", p.peerIf); err != nil {
			return err
		}
		if _, err := wan.RunWith(a.ctx, []*nsguard.NS{p.peer}, "", "ip", "link", "set", p.peerIf, "netns", nsguard.FDPath(0)); err != nil {
			return err
		}
	}
	steps := map[*nsguard.NS][][]string{
		wan: {
			ipAddr("wv", topo.WanVV4.String()+"/25"), ipAddr("wv", topo.WanVV6.String()+"/64"),
			ipAddr("wi", topo.WanIV4.String()+"/25"), ipAddr("wi", topo.WanIV6.String()+"/64"),
			{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "wv", "up"}, {"ip", "link", "set", "wi", "up"},
			{"sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"},
			{"ip", "route", "add", topo.InnerV4.String(), "via", topo.PeerV4.String()},
			{"ip", "-6", "route", "add", topo.InnerV6.String(), "via", topo.PeerV6.String()},
		},
		peer: {
			ipAddr("v0", topo.PeerV4.String()+"/25"), ipAddr("v0", topo.PeerV6.String()+"/64"),
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
	for _, n := range []*nsguard.NS{wan, peer, inet} {
		if err := a.seq(n, steps[n]...); err != nil {
			return err
		}
	}
	return a.clientLink()
}

// clientLink создаёт ksl-client и линию c0 ↔ wc (с LAN); повторно — в сценарии 7 («перезапуск ns»).
func (a *acc) clientLink() error {
	cl, err := nsguard.Create(a.ctx, topo.ClientNS)
	if err != nil {
		return err
	}
	a.ns[topo.ClientNS] = cl
	a.printf("ns %s inode %d\n", cl.Name, cl.Ino)
	wan := a.ns[topo.WanNS]
	if err := a.do(wan, "ip", "link", "add", topo.CaptureIf, "type", "veth", "peer", "name", topo.PhysIf); err != nil {
		return err
	}
	if _, err := wan.RunWith(a.ctx, []*nsguard.NS{cl}, "", "ip", "link", "set", topo.PhysIf, "netns", nsguard.FDPath(0)); err != nil {
		return err
	}
	if err := a.seq(wan,
		ipAddr(topo.CaptureIf, topo.WanCV4.String()+"/24"), ipAddr(topo.CaptureIf, topo.WanCV6.String()+"/64"),
		ipAddr(topo.CaptureIf, topo.LanHostV4.String()+"/24"), ipAddr(topo.CaptureIf, topo.LanHostV6.String()+"/64"),
		[]string{"ip", "link", "set", topo.CaptureIf, "up"}); err != nil {
		return err
	}
	if err := a.seq(cl,
		ipAddr(topo.PhysIf, topo.ClientV4.String()+"/24"), ipAddr(topo.PhysIf, topo.ClientV6.String()+"/64"),
		ipAddr(topo.PhysIf, topo.LanClientV4.String()+"/24"), ipAddr(topo.PhysIf, topo.LanClientV6.String()+"/64"),
		// c0 опускается в сценарии 8: v6-адреса должны пережить down, как статические на машине.
		[]string{"sysctl", "-qw", "net.ipv6.conf." + topo.PhysIf + ".keep_addr_on_down=1"},
		[]string{"ip", "link", "set", "lo", "up"}, []string{"ip", "link", "set", topo.PhysIf, "up"}); err != nil {
		return err
	}
	if err := a.physRoutes(); err != nil {
		return err
	}
	return a.waitDAD()
}

func (a *acc) physRoutes() error {
	return a.seq(a.ns[topo.ClientNS],
		[]string{"ip", "route", "replace", "default", "via", topo.WanCV4.String(), "dev", topo.PhysIf, "metric", topo.PhysMetric},
		[]string{"ip", "-6", "route", "replace", "default", "via", topo.WanCV6.String(), "dev", topo.PhysIf, "metric", topo.PhysMetric})
}

func (a *acc) waitDAD() error {
	return a.waitFor("v6 вне tentative", 8*time.Second, func() bool {
		for _, n := range a.ns {
			if n.Name == topo.MountNS {
				continue
			}
			out, err := n.Run(a.ctx, "ip", "-6", "addr", "show", "tentative")
			if err != nil || strings.TrimSpace(out) != "" {
				return false
			}
		}
		return true
	})
}

func (a *acc) startAll() error {
	a.printf("\n== сервисы, LAN-хост и захват\n")
	onRecv := func(b []byte) {
		var e services.Entry
		if json.Unmarshal(b, &e) == nil {
			a.mu.Lock()
			a.recv = append(a.recv, e)
			a.mu.Unlock()
		}
	}
	if err := a.startJSON("inet", a.ns[topo.InetNS], onRecv, "serve"); err != nil {
		return err
	}
	if err := a.startJSON("lan", a.ns[topo.WanNS], onRecv, "serve", "--addrs",
		topo.LanHostV4.String()+","+topo.LanHostV6.String()); err != nil {
		return err
	}
	return a.startCapture("capture")
}

func (a *acc) startCapture(name string) error {
	err := a.startJSON(name, a.ns[topo.WanNS], func(b []byte) {
		var f capture.Flow
		if json.Unmarshal(b, &f) == nil {
			a.mu.Lock()
			a.flows = append(a.flows, f)
			a.mu.Unlock()
		}
	}, "capture", "--iface", topo.CaptureIf)
	if err != nil {
		return err
	}
	if ok, _ := a.sendMark(); !ok {
		return errors.New("захват на WAN не увидел метку положительного контроля")
	}
	a.printf("захват AF_PACKET на ksl-wan/%s: метка видна\n", topo.CaptureIf)
	return nil
}

// mountNS — держатель приватного mount ns в ksl-mnt: tmpfs поверх /var/lib, /run, /etc/systemd/system, свой resolv.conf
// для DHCPDNS (резолвер — LAN-хост) и свой boot_id (bind-mount; сценарий 7 меняет его содержимое).
func (a *acc) mountNS() error {
	script := strings.Join([]string{
		"set -e",
		"mount -t tmpfs -o size=48m,mode=755 ksl-varlib /var/lib", "mkdir -p " + stateDir,
		"mount -t tmpfs -o size=8m,mode=755 ksl-run /run", "mkdir -p /run/killswitch /run/systemd/resolve /run/ksl",
		"printf 'nameserver " + topo.LanHostV4.String() + "\\n' > /run/systemd/resolve/resolv.conf",
		"cat /proc/sys/kernel/random/boot_id > /run/ksl/boot_id",
		"mount --bind /run/ksl/boot_id /proc/sys/kernel/random/boot_id",
		"mount -t tmpfs -o size=4m,mode=755 ksl-units " + unitDir,
		"echo '" + topo.ServeReadyMsg + "'", "exec sleep 3600",
	}, "\n")
	m := a.ns[topo.MountNS]
	cmd, err := m.Cmd(a.ctx, nil, "unshare", "--mount", "--propagation", "private", "sh", "-c", script)
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	logf, err := os.Create(filepath.Join(a.run, "mnt-holder.log"))
	if err != nil {
		return err
	}
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		return err
	}
	p := &proc{name: "mnt-holder", cmd: cmd, done: make(chan struct{})}
	a.procs = append(a.procs, p)
	go func() { cmd.Wait(); logf.Close(); close(p.done) }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != topo.ServeReadyMsg {
		b, _ := os.ReadFile(filepath.Join(a.run, "mnt-holder.log"))
		return fmt.Errorf("держатель mount ns не готов: %q %v %s", line, err, b)
	}
	if a.mnt, err = nsguard.OpenMount(fmt.Sprintf("/proc/%d/ns/mnt", cmd.Process.Pid)); err != nil {
		return err
	}
	out, err := a.inMnt("", "sh", "-c", "findmnt -n -o TARGET,FSTYPE /var/lib /run /etc/systemd/system; echo boot_id $(cat /proc/sys/kernel/random/boot_id)")
	a.printf("mount ns inode %d (хост — другой):\n%s", a.mnt.Ino, indent(out))
	return err
}

// inMnt — команда в ksl-client и mount ns держателя через kslab ksexec (сверка обоих inode и tmpfs до exec).
func (a *acc) inMnt(stdin string, argv ...string) (string, error) {
	cmd, err := a.mntCmd(nil, argv...)
	if err != nil {
		return "", err
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil && strings.Contains(string(out), "kslab: nsguard") {
		err = fmt.Errorf("%w: %s", nsguard.ErrInner, strings.TrimSpace(string(out)))
		a.checkGuard(err)
	}
	return string(out), err
}

func (a *acc) mntCmd(pathPrefix []string, argv ...string) (*exec.Cmd, error) {
	cl := a.ns[topo.ClientNS]
	full := append([]string{a.self, "ksexec", "--expect-ino", strconv.FormatUint(cl.Ino, 10),
		"--expect-mnt", strconv.FormatUint(a.mnt.Ino, 10), "--stub", a.stub, "--"}, argv...)
	cmd, err := cl.CmdIn(a.ctx, a.mnt, full...)
	if err != nil {
		a.checkGuard(err)
		return nil, err
	}
	path := strings.Join(append(append(pathPrefix, a.stub), os.Getenv("PATH")), ":")
	cmd.Env = append(os.Environ(), "PATH="+path, "KSL_STUB_LOG="+filepath.Join(a.run, "systemctl.log"), "KSL_REAL_NFT="+a.realNFT)
	return cmd, nil
}

// ksCmd — killswitch с аргументами; печатает вывод, возвращает его и код выхода (-1 — убит сигналом).
func (a *acc) ksCmd(pathPrefix []string, args ...string) (string, int) {
	cmd, err := a.mntCmd(pathPrefix, append([]string{a.ksBin}, args...)...)
	if err != nil {
		return err.Error(), -2
	}
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		code = -2
	}
	if strings.Contains(string(out), "kslab: nsguard") {
		a.checkGuard(fmt.Errorf("%w: %s", nsguard.ErrInner, strings.TrimSpace(string(out))))
	}
	a.printf("  $ killswitch %s → код %d\n%s", strings.Join(args, " "), code, indent(trimLines(string(out), 40)))
	return string(out), code
}

func (a *acc) ks(args ...string) (string, int) { return a.ksCmd(nil, args...) }

func trimLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = append(lines[:n], fmt.Sprintf("… ещё %d строк", len(lines)-n))
	}
	return strings.Join(lines, "\n")
}

func (a *acc) writeConfig(o ConfigOpts) error {
	cfg := a.c.Config(o)
	a.printf("  config.toml:\n%s", indent(cfg))
	_, err := a.inMnt(cfg, "sh", "-c", "cat > "+stateDir+"/config.toml")
	return err
}

func (a *acc) startEnforce(argv0 string) error {
	a.stopEnforce()
	cmd, err := a.mntCmd(nil, argv0, "enforce")
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(a.run, "enforce.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fmt.Fprintf(logf, "== enforce %s\n", time.Now().Format(time.TimeOnly))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return err
	}
	p := &proc{name: "enforce", cmd: cmd, done: make(chan struct{})}
	a.procs = append(a.procs, p)
	go func() { cmd.Wait(); logf.Close(); close(p.done) }()
	a.enf = p
	return nil
}

func (a *acc) stopEnforce() {
	if a.enf != nil {
		a.stop(a.enf)
		a.enf = nil
	}
}

func (a *acc) clientNFT(args ...string) string {
	out, _ := a.ns[topo.ClientNS].Run(a.ctx, append([]string{"nft"}, args...)...)
	return out
}

// ---- клиенты туннеля

func (a *acc) serversUp() error {
	peer := a.ns[topo.PeerNS]
	switch a.c.Name {
	case "wireguard":
		var err error
		if a.wgKeys[0], a.wgKeys[1], err = wgset.GenerateKeys(); err != nil {
			return err
		}
		if a.wgKeys[2], a.wgKeys[3], err = wgset.GenerateKeys(); err != nil {
			return err
		}
		if err := a.do(peer, "ip", "link", "add", "kswg-s", "type", "wireguard"); err != nil {
			return err
		}
		if err := a.wgset(peer, wgset.Config{Iface: "kswg-s", PrivateKey: a.wgKeys[2], ListenPort: topo.WGServerPort,
			Peers: []wgset.Peer{{PublicKey: a.wgKeys[1], Allowed: []string{"198.18.0.2/32", "2001:db8:ffff::2/128"}}}}); err != nil {
			return err
		}
		return a.seq(peer, ipAddr("kswg-s", "198.18.0.1/24"), ipAddr("kswg-s", "2001:db8:ffff::1/64"),
			[]string{"ip", "link", "set", "kswg-s", "up"})
	case "sing-box", "sing-box-ar":
		srv, _, err := SingBoxConfigs(a.pw)
		if err != nil {
			return err
		}
		return a.proxyServer("sing-box", srv, topo.SingBoxPort)
	case "xray":
		srv, _, err := XrayConfigs(a.pw)
		if err != nil {
			return err
		}
		return a.proxyServer("xray", srv, topo.XrayPort)
	}
	return fmt.Errorf("клиент %s", a.c.Name)
}

func (a *acc) bin(name string) string { return filepath.Join(a.dir, "bin", name) }

func (a *acc) runArgs(name, cfg string) []string {
	if name == "xray" {
		return []string{a.bin("xray"), "run", "-c", cfg}
	}
	return []string{a.bin("sing-box"), "run", "-c", cfg, "-D", a.run}
}

func (a *acc) proxyServer(name string, cfg []byte, port uint16) error {
	path := filepath.Join(a.run, name+"-server.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return err
	}
	peer := a.ns[topo.PeerNS]
	var err error
	if a.srvP, err = a.startBin(name+"-server", peer, a.runArgs(name, path)...); err != nil {
		return err
	}
	return a.waitFor(name+" сервер слушает", 10*time.Second, func() bool {
		out, _ := peer.Run(a.ctx, "ss", "-Hltn", fmt.Sprintf("sport = :%d", port))
		return strings.TrimSpace(out) != ""
	})
}

// upOpts — вариант запуска клиента.
type upOpts struct {
	noMark bool // WireGuard без fwmark (вопрос (г))
	direct bool // sing-box с правилом прямого маршрута (рев. 6)
}

// up поднимает клиента туннеля с интерфейсом iface.
func (a *acc) up(iface string, o upOpts) error {
	cl := a.ns[topo.ClientNS]
	a.iface = iface
	switch a.c.Name {
	case "wireguard":
		if err := a.do(cl, "ip", "link", "add", iface, "type", "wireguard"); err != nil {
			return err
		}
		mark := topo.WGMark
		if o.noMark {
			mark = 0
		}
		if err := a.wgset(cl, wgset.Config{Iface: iface, PrivateKey: a.wgKeys[0], ListenPort: topo.WGClientPort, FwMark: mark,
			Peers: []wgset.Peer{{PublicKey: a.wgKeys[3], Endpoint: fmt.Sprintf("%s:%d", topo.PeerV4, topo.WGServerPort),
				Allowed: []string{"0.0.0.0/0", "::/0"}}}}); err != nil {
			return err
		}
		if err := a.seq(cl, ipAddr(iface, "198.18.0.2/24"), ipAddr(iface, "2001:db8:ffff::2/64"),
			[]string{"ip", "link", "set", iface, "up"}); err != nil {
			return err
		}
		return a.tunnelRoutes(iface)
	case "sing-box", "sing-box-ar", "xray":
		var cfg []byte
		var err error
		name := "sing-box"
		if a.c.Name == "xray" {
			name = "xray"
			cfg, err = XrayClient(a.pw, iface)
		} else {
			cfg, err = SingBoxClient(a.pw, iface, a.c.Redirect, o.direct)
		}
		if err != nil {
			return err
		}
		path := filepath.Join(a.run, name+"-client.json")
		if err := os.WriteFile(path, cfg, 0o600); err != nil {
			return err
		}
		argv := a.runArgs(name, path)
		var p *proc
		if a.cgDir != nil {
			p, err = a.startBinCg(name+"-client", cl, a.cgDir, argv...)
		} else {
			p, err = a.startBin(name+"-client", cl, argv...)
		}
		if err != nil {
			return err
		}
		a.cliP = p
		if err := a.waitFor(iface+" поднят", 10*time.Second, func() bool {
			out, err := cl.Run(a.ctx, "ip", "-br", "link", "show", iface)
			return err == nil && (strings.Contains(out, "UP") || strings.Contains(out, "UNKNOWN"))
		}); err != nil {
			return a.withLog(err, name+"-client")
		}
		if a.c.Name == "xray" {
			if err := a.seq(cl, ipAddr(iface, "198.18.2.1/30"), ipAddr(iface, "2001:db8:ffff:2::1/126")); err != nil {
				return err
			}
		}
		if !a.c.Redirect {
			if err := a.tunnelRoutes(iface); err != nil {
				return err
			}
		}
		time.Sleep(time.Second) // sing-box с auto_route ставит маршруты и nft после появления TUN
		if a.c.Redirect {
			rules, _ := cl.Run(a.ctx, "ip", "rule")
			tables, _ := cl.Run(a.ctx, "nft", "list", "tables")
			a.printf("  sing-box auto_route: ip rule:\n%s  nft: %s\n", indent(rules), strings.Join(strings.Fields(tables), " "))
		}
		return nil
	}
	return fmt.Errorf("клиент %s", a.c.Name)
}

// down — туннель опущен: клиент остановлен, интерфейс и маршруты сняты.
func (a *acc) down() {
	if a.iface == "" {
		return
	}
	a.dropTunnelRoutes(a.iface)
	if a.cliP != nil {
		a.stop(a.cliP)
		a.cliP = nil
	}
	if a.c.Name == "wireguard" {
		a.ns[topo.ClientNS].Run(a.ctx, "ip", "link", "del", a.iface)
	}
	a.iface = ""
}

func (a *acc) startBinCg(name string, n *nsguard.NS, cg *os.File, argv ...string) (*proc, error) {
	cmd, err := n.Cmd(a.ctx, nil, argv...)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=48MiB")
	logf, err := os.Create(filepath.Join(a.run, name+".log"))
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	p := &proc{name: name, cmd: cmd, done: make(chan struct{})}
	a.procs = append(a.procs, p)
	go func() { cmd.Wait(); logf.Close(); close(p.done) }()
	return p, nil
}

// trusted — проба от имени клиента туннеля: mark у WireGuard, root у sing-box, cgroup у xray.
func (a *acc) trusted(bind string) popts {
	switch {
	case a.c.Name == "wireguard":
		return popts{bind: bind, mark: topo.WGMark}
	case a.c.Cgroup:
		return popts{bind: bind, cg: a.cgDir}
	}
	return popts{bind: bind}
}

// makeCgroup — дочерний cgroup своего scope (Delegate=yes) для доверия по cgroup.
func (a *acc) makeCgroup() error {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	self := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "0::"))
	if !strings.Contains(self, "/ksl-lab") {
		return fmt.Errorf("свой cgroup %q не scope лаборатории — дочерний не создаю", self)
	}
	a.cgRel = strings.TrimPrefix(self, "/") + "/ksl-" + a.c.Name
	a.cgAbs = filepath.Join("/sys/fs/cgroup", a.cgRel)
	if err := os.Mkdir(a.cgAbs, 0o755); err != nil {
		return err
	}
	a.cgDir, err = os.Open(a.cgAbs)
	a.printf("доверенный cgroup: %s\n", a.cgRel)
	return err
}

func (a *acc) notTestedOpenVPN() {
	detail := "openvpn на хосте нет (через apt ставить нельзя)"
	if p, err := exec.LookPath("openvpn"); err == nil {
		detail = "openvpn есть (" + p + "), но сценарий не написан"
	}
	a.checks = append(a.checks, Check{Scenario: "(в)", Client: "openvpn", Family: "-", Name: "OpenVPN user nobody",
		Status: NotTested, Detail: detail, Log: a.c.Name + "/report.txt"})
	a.printf("  [NOT_TESTED] (в): %s\n", detail)
}

func (a *acc) teardownAll() {
	a.stopEnforce()
	for i := len(a.procs) - 1; i >= 0; i-- {
		a.stop(a.procs[i])
	}
	if a.mnt != nil {
		a.mnt.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range []string{topo.ClientNS, topo.PeerNS, topo.InetNS, topo.WanNS, topo.MountNS} {
		if n, ok := a.ns[name]; ok {
			if err := n.Delete(ctx); err != nil {
				a.printf("удаление %s: %v\n", name, err)
			}
		}
	}
	if a.cgDir != nil {
		a.cgDir.Close()
		if b, err := os.ReadFile(filepath.Join(a.cgAbs, "cgroup.procs")); err == nil {
			for _, f := range strings.Fields(string(b)) {
				if pid, err := strconv.Atoi(f); err == nil && pid > 1 {
					syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
		if err := os.Remove(a.cgAbs); err != nil {
			a.printf("cgroup %s: %v\n", a.cgAbs, err)
		} else {
			a.printf("cgroup %s удалён\n", a.cgRel)
		}
	}
	a.printf("ns лаборатории удалены, процессы остановлены\n")
}

// ---- сценарии

// baseline — до on: туннель работает, прямые пробы и LAN проходят (это и есть baseline классификатора).
func (a *acc) baseline() error {
	if err := a.up(a.c.Ifaces[0], upOpts{}); err != nil {
		return err
	}
	tunBase := map[string]bool{}
	for _, p := range ServiceProbes {
		v, d := classify.ClassifyTunnel(a.tunnelEvidence(p))
		tunBase[p.Name] = v == classify.TunnelOK
		st := Pass
		if !tunBase[p.Name] {
			st = NotTested
		}
		a.add("1", famOf(p), "baseline через туннель "+p.Name, st, string(v)+" "+d)
	}
	a.tunBase = tunBase
	for _, p := range append(DirectProbes(), lanProbes...) {
		e, _ := a.evidence(p, a.direct())
		a.base[p.Name] = e
		ok := e.BaselineOK() != p.NoServer
		a.expect("1", famOf(p), "baseline прямой "+p.Name, ok, e.String())
	}
	a.preOn = a.nsState()
	return nil
}

func (a *acc) nsState() string {
	cl := a.ns[topo.ClientNS]
	var b strings.Builder
	for _, c := range [][]string{{"nft", "-s", "list", "ruleset"}, {"ip", "route"}, {"ip", "-6", "route"}, {"ip", "rule"}, {"ip", "-6", "rule"}} {
		out, _ := cl.Run(a.ctx, c...)
		if c[0] == "nft" {
			out = StripTable(out, "inet killswitch")
		}
		fmt.Fprintf(&b, "# %s\n%s", strings.Join(c, " "), out)
	}
	return b.String()
}

func (a *acc) s1() error {
	if err := a.writeConfig(ConfigOpts{CgroupPath: a.cgRel}); err != nil {
		return err
	}
	_, code := a.ks("on")
	a.expect("1", "-", "killswitch on", code == 0, fmt.Sprintf("код %d", code))
	a.printf("  таблица:\n%s", indent(trimLines(stripProbeRules(a.clientNFT("-s", "list", "table", "inet", "killswitch")), 60)))
	time.Sleep(300 * time.Millisecond)
	for _, p := range ServiceProbes {
		a.viaTunnel("1", p)
	}
	for _, p := range DirectProbes() {
		if p.NoServer {
			e, _ := a.evidence(p, a.direct())
			v, d := classify.Classify(a.base[p.Name], e)
			a.expect("1", famOf(p), "контроль без сервера "+p.Name, v == classify.Inconclusive, string(v)+" "+d)
			continue
		}
		a.blocked("1", p, a.direct(), "прямая")
	}
	return nil
}

var probeRuleRe = regexp.MustCompile(`(?m)^\s+meta l4proto \{ tcp, udp \} th sport 300[0-6][0-9] counter .*\n`)

func stripProbeRules(s string) string { return probeRuleRe.ReplaceAllString(s, "") }

func (a *acc) s3open() error {
	for _, p := range lanProbes {
		a.open("3", p, a.direct(), "LAN (dns open)")
	}
	return nil
}

func (a *acc) s9() error {
	out, code := a.ks("check")
	ok := code == 0
	a.expect("9", "-", "check под on", ok, fmt.Sprintf("код %d", code))
	if a.c.Redirect {
		a.add("(б)", "-", "check при auto_redirect", map[bool]Status{true: Pass, false: Fail}[ok],
			fmt.Sprintf("код %d; %s", code, strings.Join(grepLines(out, "LEAK|INCONCLUSIVE|итог"), " | ")))
	}
	if _, err := a.ns[topo.ClientNS].Run(a.ctx, "nft", "delete", "table", "inet", "killswitch"); err != nil {
		return err
	}
	_, code = a.ks("check")
	a.expect("9", "-", "check после ручного снятия таблицы", code == 4, fmt.Sprintf("код %d (ждали 4)", code))
	if err := a.startEnforce(a.ksBin); err != nil {
		return err
	}
	err := a.waitFor("enforce вернул таблицу", 15*time.Second, func() bool {
		return strings.Contains(a.clientNFT("list", "tables"), "inet killswitch") &&
			strings.Contains(a.clientNFT("list", "table", "inet", "killswitch"), "chain postrouting")
	})
	a.expect("10", "-", "enforce вернул снятую таблицу", err == nil, fmt.Sprint(err))
	a.stopEnforce()
	a.blocked("10", shortProbes[0], a.direct(), "после enforce прямая")
	return nil
}

func grepLines(s, re string) []string {
	r := regexp.MustCompile(re)
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if r.MatchString(l) {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func (a *acc) tableHash() string { return a.clientNFT("-s", "list", "table", "inet", "killswitch") }

func (a *acc) s5() error {
	before := a.tableHash()
	_, code := a.ks("repair")
	after := a.tableHash()
	a.expect("5", "-", "repair на linux unsupported", code == 2, fmt.Sprintf("код %d (ждали 2 по контракту)", code))
	a.expect("5", "-", "правила on не тронуты", before == after && strings.Contains(after, "chain postrouting"),
		fmt.Sprintf("таблица совпала: %t", before == after))
	return nil
}

func (a *acc) s6() error {
	_, code := a.ks("off")
	a.expect("6", "-", "killswitch off", code == 0, fmt.Sprintf("код %d", code))
	now := a.nsState()
	a.expect("6", "-", "чужие таблицы, маршруты и правила ns как до on", now == a.preOn, diffHint(a.preOn, now))
	tbl := a.clientNFT("list", "table", "inet", "killswitch")
	a.expect("6", "-", "своя таблица пустая (B3)", !strings.Contains(tbl, "chain"), strings.Join(strings.Fields(tbl), " "))
	for _, p := range shortProbes {
		a.open("6", p, a.direct(), "прямая под off")
		a.viaTunnel("6", p)
	}
	_, code = a.ks("on")
	if code != 0 {
		return fmt.Errorf("on после off: код %d", code)
	}
	return nil
}

func diffHint(want, got string) string {
	if want == got {
		return "совпало"
	}
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("строка %d: было %q, стало %q", i+1, wl, gl)
		}
	}
	return "разошлось"
}

func (a *acc) s2() error {
	a.down()
	time.Sleep(500 * time.Millisecond)
	for _, p := range shortProbes {
		a.blocked("2", p, a.direct(), "туннель опущен, прямая")
		a.blocked("2", p, nobody, "туннель опущен, по маршруту")
	}
	for _, p := range shortProbes[:2] {
		e, _ := a.evidence(p, a.trusted(topo.PhysIf))
		a.add("2", famOf(p), "compat: доверенный к чужому адресу проходит (ожидаемо в compat) "+p.Name,
			map[bool]Status{true: Pass, false: Fail}[e.BaselineOK()], e.String())
	}
	if err := a.up(a.c.Ifaces[0], upOpts{}); err != nil {
		return err
	}
	for _, p := range shortProbes {
		a.viaTunnel("2", p)
	}
	return nil
}

// s4 — переподключение с новым именем и индексом при работающем enforce; в окне фоновые пробы по маршруту.
func (a *acc) s4() error {
	if err := a.startEnforce(a.ksBin); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	a.mu.Lock()
	fi, ri := len(a.flows), len(a.recv)
	a.mu.Unlock()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var sent atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, p := range []Probe{ServiceProbes[2], ServiceProbes[3], ServiceProbes[0]} {
				a.runProbeOpts(p, popts{uid: topo.NobodyUID})
				sent.Add(1)
			}
		}
	}()
	oldIdx := a.ifIndex(a.iface)
	a.down()
	time.Sleep(time.Second)
	err := a.up(a.c.Ifaces[1], upOpts{})
	newIdx := a.ifIndex(a.iface)
	var upErr error
	if err == nil {
		upErr = a.waitFor("туннель после переподключения", 20*time.Second, func() bool {
			return a.runProbeOpts(ServiceProbes[0], nobody).OK
		})
	}
	close(stop)
	wg.Wait()
	time.Sleep(300 * time.Millisecond)
	a.mu.Lock()
	leak4, leak6, recv := 0, 0, 0
	for _, f := range a.flows[fi:] {
		if topo.IsClientPhys(f.Src) && (f.Dst == topo.InetV4 || f.Dst == topo.InetV6) {
			if f.Dst.Is4() {
				leak4++
			} else {
				leak6++
			}
		}
	}
	for _, r := range a.recv[ri:] {
		if topo.IsClientPhys(r.Src) {
			recv++
		}
	}
	a.mu.Unlock()
	if err != nil {
		return err
	}
	detail := fmt.Sprintf("%s(index %d) → %s(index %d), фоновых проб %d, получатель от c0: %d", a.c.Ifaces[0], oldIdx,
		a.c.Ifaces[1], newIdx, sent.Load(), recv)
	a.expect("4", "v4", "в окне переподключения нет пакетов c0 → «интернет»", leak4 == 0 && recv == 0, fmt.Sprintf("пакетов %d; %s", leak4, detail))
	a.expect("4", "v6", "в окне переподключения нет пакетов c0 → «интернет»", leak6 == 0 && recv == 0, fmt.Sprintf("пакетов %d; %s", leak6, detail))
	a.expect("4", "-", "enforce открыл новый интерфейс", upErr == nil && strings.Contains(a.clientNFT("list", "table", "inet", "killswitch"),
		fmt.Sprintf("oifname %q accept", a.c.Ifaces[1])), fmt.Sprint(upErr))
	for _, p := range shortProbes {
		a.viaTunnel("4", p)
		a.blocked("4", p, a.direct(), "прямая после переподключения")
	}
	return nil
}

func (a *acc) ifIndex(name string) int {
	out, _ := a.ns[topo.ClientNS].Run(a.ctx, "ip", "-o", "link", "show", name)
	n, _ := strconv.Atoi(strings.SplitN(out, ":", 2)[0])
	return n
}

// s3tunnelUp — dns tunnel-up: до здоровья DNS к LAN открыт, после up закрыт, «зомби» (сервер недоступен) — снова открыт.
func (a *acc) s3tunnelUp() error {
	if err := a.writeConfig(ConfigOpts{TunnelUpDNS: true, CgroupPath: a.cgRel}); err != nil {
		return err
	}
	if _, code := a.ks("on"); code != 0 {
		return fmt.Errorf("on tunnel-up: код %d", code)
	}
	if err := a.startEnforce(a.ksBin); err != nil {
		return err
	}
	dns4, dns6 := lanProbes[2], lanProbes[4]
	a.open("3", dns4, a.direct(), "tunnel-up до здоровья: DNS к LAN")
	t0 := time.Now()
	errUp := a.waitFor("здоровье up: DNS к LAN закрыт", 40*time.Second, func() bool {
		e, _ := a.evidence(dns4, a.direct())
		return !e.LeakSeen()
	})
	a.expect("3", "-", "tunnel-up: здоровье up закрыло DNS к LAN", errUp == nil, fmt.Sprintf("%v за %s", errUp, time.Since(t0).Round(time.Second)))
	if errUp == nil {
		for _, p := range lanProbes[2:] {
			a.blocked("3", p, a.direct(), "tunnel-up, туннель здоров: DNS к LAN")
		}
		for _, p := range lanProbes[:2] {
			a.open("3", p, a.direct(), "tunnel-up, туннель здоров: HTTP к LAN")
		}
	}
	// «Зомби»: сервер туннеля не принимает ничего (drop на входе ksl-peer), TUN клиента жив, маршруты не трогаются.
	peer := a.ns[topo.PeerNS]
	if _, err := peer.RunWith(a.ctx, nil, zombieNFT, "nft", "-f", "-"); err != nil {
		return err
	}
	t1 := time.Now()
	errZ := a.waitFor("зомби: DNS к LAN снова открыт", 45*time.Second, func() bool {
		e, _ := a.evidence(dns4, a.direct())
		return e.BaselineOK()
	})
	if errUp != nil {
		a.add("r6-зомби", "-", "TUN жив, сервер недоступен", NotTested, "здоровье не поднялось (см. сценарий 3) — переход up→down не проверить")
	} else {
		a.expect("r6-зомби", "-", "TUN жив, сервер недоступен → DNS к LAN открыт", errZ == nil,
			fmt.Sprintf("down: %v за %s", errZ, time.Since(t1).Round(time.Second)))
	}
	if errUp == nil && errZ == nil {
		a.open("r6-зомби", dns4, a.direct(), "зомби: DNS к LAN")
		a.open("r6-зомби", dns6, a.direct(), "зомби: DNS к LAN")
		a.blocked("r6-зомби", shortProbes[0], a.direct(), "зомби: прямая к «интернету»")
		a.blocked("r6-зомби", shortProbes[1], a.direct(), "зомби: прямая к «интернету»")
	}
	if err := a.do(peer, "nft", "delete", "table", "inet", "ksl_zombie"); err != nil {
		return err
	}
	a.stopEnforce()
	if err := a.writeConfig(ConfigOpts{CgroupPath: a.cgRel}); err != nil {
		return err
	}
	if _, code := a.ks("on"); code != 0 {
		return fmt.Errorf("on после tunnel-up: код %d", code)
	}
	return nil
}

// s7 — «загрузка»: off → ksl-client пересоздан, новый boot id, ранний юнит из tmpfs, enforce из копии бинарника.
func (a *acc) s7() error {
	if _, code := a.ks("off"); code != 0 {
		return fmt.Errorf("off перед перезапуском: код %d", code)
	}
	a.stopEnforce()
	a.down()
	unit, err := a.inMnt("", "cat", earlyUnit)
	if err != nil {
		return err
	}
	enfUnit, err := a.inMnt("", "cat", enforceUnit)
	if err != nil {
		return err
	}
	_, lerr := a.inMnt("", "test", "-L", unitDir+"/sysinit.target.wants/killswitch-early.service")
	a.expect("7", "-", "ранний юнит включён (ссылка sysinit.target.wants)", lerr == nil, fmt.Sprint(lerr))
	oldBoot, _ := a.inMnt("", "cat", "/proc/sys/kernel/random/boot_id")
	if err := a.ns[topo.ClientNS].Delete(a.ctx); err != nil {
		return err
	}
	delete(a.ns, topo.ClientNS)
	if err := a.clientLink(); err != nil {
		return err
	}
	if err := a.startCapture("capture-2"); err != nil {
		return err
	}
	if _, err := a.inMnt("", "sh", "-c", "cat /proc/sys/kernel/random/uuid > /run/ksl/boot_id"); err != nil {
		return err
	}
	newBoot, _ := a.inMnt("", "cat", "/proc/sys/kernel/random/boot_id")
	a.printf("  boot id: %s → %s", strings.TrimSpace(oldBoot), newBoot)
	a.printf("  nft в новом ksl-client до раннего юнита: %q\n", strings.TrimSpace(a.clientNFT("list", "ruleset")))
	argv, err := ExecStart(unit)
	if err != nil {
		return err
	}
	out, err := a.inMnt("", argv...)
	a.expect("7", "-", "ExecStart раннего юнита", err == nil, strings.TrimSpace(out)+fmt.Sprint(" ", err))
	for _, p := range shortProbes {
		a.blocked("7", p, a.direct(), "после «загрузки» до клиента, прямая")
		a.blocked("7", p, nobody, "после «загрузки» до клиента, по маршруту")
	}
	eargv, err := ExecStart(enfUnit)
	if err != nil {
		return err
	}
	if err := a.startEnforce(eargv[0]); err != nil {
		return err
	}
	errOn := a.waitFor("enforce после загрузки вернул on", 20*time.Second, func() bool {
		st, _ := a.ks("status")
		return strings.Contains(st, "режим: on")
	})
	a.expect("7", "-", "enforce из копии бинарника: новая загрузка → on", errOn == nil, fmt.Sprintf("%v (%s)", errOn, eargv[0]))
	if err := a.up(a.c.Ifaces[0], upOpts{}); err != nil {
		return err
	}
	for _, p := range shortProbes {
		a.viaTunnel("7", p)
		a.blocked("7", p, a.direct(), "клиент поднят после «загрузки», прямая")
	}
	a.stopEnforce()
	return nil
}

// strict — сценарий 2 в strict и проверки клиента: (г) WireGuard без fwmark, (а) метка cgroup на conntrack,
// рев. 6 прямой маршрут sing-box.
func (a *acc) strict() error {
	o := ConfigOpts{Strict: true, CgroupPath: a.cgRel}
	if a.c.Cgroup {
		o.ExtraEndpoints = []string{fmt.Sprintf("%s:%d/udp", topo.InetV4, topo.UDPPort)}
	}
	if err := a.writeConfig(o); err != nil {
		return err
	}
	if _, code := a.ks("on"); code != 0 {
		return fmt.Errorf("on strict: код %d", code)
	}
	if a.c.Name == "wireguard" {
		a.down()
		if err := a.up(a.c.Ifaces[0], upOpts{noMark: true}); err != nil {
			return err
		}
		time.Sleep(3 * time.Second)
		r := a.runProbeOpts(ServiceProbes[0], nobody)
		show, _ := a.ns[topo.ClientNS].Run(a.ctx, a.self, "wgset", "--show", a.iface, "--expect-ino", strconv.FormatUint(a.ns[topo.ClientNS].Ino, 10))
		a.expect("(г)", "-", "strict, WireGuard без fwmark не подключается (решение «Оставить закрытым»)", !r.OK && strings.Contains(show, "handshake=никогда"),
			strings.TrimSpace(show))
		a.down()
	}
	a.down()
	time.Sleep(500 * time.Millisecond)
	for _, p := range shortProbes[:2] {
		a.blocked("2", p, a.trusted(topo.PhysIf), "strict: доверенный к чужому адресу")
		a.blocked("2", p, a.direct(), "strict, туннель опущен, прямая")
	}
	if err := a.up(a.c.Ifaces[0], upOpts{}); err != nil {
		return err
	}
	scn := "2"
	if a.c.Name == "wireguard" {
		scn = "(г)"
	}
	for _, p := range shortProbes {
		a.viaTunnel(scn, p)
	}
	if a.c.Name == "wireguard" {
		show, _ := a.ns[topo.ClientNS].Run(a.ctx, a.self, "wgset", "--show", a.iface, "--expect-ino", strconv.FormatUint(a.ns[topo.ClientNS].Ino, 10))
		a.printf("  %s\n", strings.TrimSpace(show))
		for _, p := range shortProbes[:2] {
			a.viaTunnel("2", p)
		}
	}
	if a.c.Cgroup {
		a.conntrackP1()
	}
	if a.c.Name == "sing-box" {
		a.directRoute(o)
	}
	return nil
}

// conntrackP1 — вопрос (а): метка cgroup живёт на записи conntrack. Доверенный cgroup шлёт UDP к endpoint (эхо 443),
// потом чужой процесс с тем же 5-кортежем. Затем — кандидат правки вставкой правил в таблицу внутри ns.
func (a *acc) conntrackP1() {
	udp4 := ServiceProbes[2]
	trusted := popts{bind: topo.PhysIf, sport: 40123, cg: a.cgDir}
	foreign := popts{bind: topo.PhysIf, sport: 40123, uid: topo.NobodyUID}
	r := a.runProbeOpts(udp4, trusted)
	a.expect("(а)", "v4", "доверенный cgroup к endpoint (strict) проходит", r.OK, fmt.Sprintf("ok=%t echo=%s err=%s", r.OK, r.Echo, r.Err))
	e, _ := a.evidence(udp4, foreign)
	a.expect("(а)", "v4", "чужой процесс с тем же 5-кортежем UDP до истечения conntrack", !e.LeakSeen(),
		"прошёл="+strconv.FormatBool(e.LeakSeen())+" "+e.String())
	a.blocked("(а)", udp4, popts{bind: topo.PhysIf, sport: 40124, uid: topo.NobodyUID}, "контроль: чужой с другим sport")
	a.printf("  цепочка output:\n%s", indent(a.clientNFT("list", "chain", "inet", "killswitch", "output")))
	// Кандидат правки (только эксперимент в ns, backend не меняется): пакет с меткой доверенного cgroup и полным сокетом
	// вне этого cgroup — drop в output; пакет без сокета (TIME_WAIT) проходит, как сейчас.
	level := strings.Count(a.cgRel, "/") + 1
	labels := regexp.MustCompile(`ct label set (\d+) ct label set (\d+)`).FindStringSubmatch(a.clientNFT("list", "chain", "inet", "killswitch", "output"))
	if labels == nil {
		a.add("(а)", "v4", "кандидат правки", NotTested, "в output нет правила ct label set")
		return
	}
	fix := fmt.Sprintf("add chain inet killswitch ksl_fix\n"+
		"add rule inet killswitch ksl_fix socket cgroupv2 level %d %q return\n"+
		"add rule inet killswitch ksl_fix meta skuid >= 0 drop\n"+
		"add rule inet killswitch output ct label %s ct label %s jump ksl_fix\n", level, a.cgRel, labels[1], labels[2])
	a.printf("  кандидат правки:\n%s", indent(fix))
	if _, err := a.ns[topo.ClientNS].RunWith(a.ctx, nil, fix, "nft", "-f", "-"); err != nil {
		a.add("(а)", "v4", "кандидат правки принят nft", Fail, err.Error())
		return
	}
	trusted.sport, foreign.sport = 40125, 40125
	r = a.runProbeOpts(udp4, trusted)
	a.expect("(а)", "v4", "с правкой: доверенный проходит", r.OK, fmt.Sprintf("ok=%t err=%s", r.OK, r.Err))
	e, _ = a.evidence(udp4, foreign)
	a.expect("(а)", "v4", "с правкой: чужой с тем же 5-кортежем отброшен", !e.LeakSeen(), e.String())
	a.printf("  %s\n", strings.Join(grepLines(a.clientNFT("list", "chain", "inet", "killswitch", "ksl_fix"), "drop|return"), " | "))
}

// directRoute — рев. 6: правило клиента «HTTP «интернета» v4 → direct». compat — проходит мимо туннеля от доверенного
// root (так устроен compat); strict — отброшено (доверенный только к endpoints), утечки нет.
func (a *acc) directRoute(strict ConfigOpts) {
	p := ServiceProbes[0]
	a.down()
	if err := a.up(a.c.Ifaces[0], upOpts{direct: true}); err != nil {
		a.add("r6-маршрут", "v4", "клиент с прямым маршрутом", Fail, err.Error())
		return
	}
	e, _ := a.evidence(p, nobody)
	a.expect("r6-маршрут", "v4", "strict: прямой маршрут клиента отброшен", !e.LeakSeen(), e.String())
	a.viaTunnel("r6-маршрут", ServiceProbes[1])
	if err := a.writeConfig(ConfigOpts{}); err == nil {
		a.ks("on")
		e, res := a.evidence(p, nobody)
		a.expect("r6-маршрут", "v4", "compat: прямой маршрут доверенного root проходит (ожидаемо в compat)", e.BaselineOK(),
			e.String()+" echo="+res.Echo)
	}
	a.down()
	if err := a.up(a.c.Ifaces[0], upOpts{}); err != nil {
		a.add("r6-маршрут", "-", "клиент без прямого маршрута", Fail, err.Error())
	}
}

// s8 — сломанное состояние: (а) killswitch убит на загрузке таблицы → enforce доводит; (б) state.json испорчен, конфиг
// удалён, c0 опущен → uninstall чистит всё.
func (a *acc) s8() error {
	if err := a.writeConfig(ConfigOpts{CgroupPath: a.cgRel}); err != nil {
		return err
	}
	if _, code := a.ks("off"); code != 0 {
		return fmt.Errorf("off перед сбоем: код %d", code)
	}
	_, code := a.ksCmd([]string{a.killer}, "on")
	st, _ := a.inMnt("", "cat", stateDir+"/state.json")
	tbl := a.clientNFT("list", "table", "inet", "killswitch")
	a.expect("8", "-", "убит посреди Apply: намерение записано, таблица прежняя (off)", code == -1 &&
		strings.Contains(st, `"intent"`) && !strings.Contains(tbl, "chain postrouting"),
		fmt.Sprintf("код %d, intent=%t, postrouting=%t", code, strings.Contains(st, `"intent"`), strings.Contains(tbl, "chain postrouting")))
	if err := a.startEnforce(a.ksBin); err != nil {
		return err
	}
	errOn := a.waitFor("enforce довёл до on", 20*time.Second, func() bool {
		s, _ := a.ks("status")
		return strings.Contains(s, "режим: on") && !strings.Contains(s, "незавершённый")
	})
	a.stopEnforce()
	a.expect("8", "-", "enforce довёл незавершённый on", errOn == nil, fmt.Sprint(errOn))
	a.blocked("8", shortProbes[0], a.direct(), "после доведения, прямая")

	a.down()
	if _, err := a.inMnt("", "sh", "-c", "printf '{не json' > "+stateDir+"/state.json && rm -f "+stateDir+"/config.toml"); err != nil {
		return err
	}
	if err := a.do(a.ns[topo.ClientNS], "ip", "link", "set", topo.PhysIf, "down"); err != nil {
		return err
	}
	_, code = a.ks("uninstall")
	a.expect("8", "-", "uninstall без сети, конфига и при битом state.json", code == 0, fmt.Sprintf("код %d", code))
	tables := a.clientNFT("list", "tables")
	files, _ := a.inMnt("", "sh", "-c", "ls -A "+stateDir+" 2>/dev/null; echo '|'; ls -A "+unitDir+" "+unitDir+"/*.wants 2>/dev/null")
	stubLog, _ := os.ReadFile(filepath.Join(a.run, "systemctl.log"))
	a.expect("8", "-", "таблицы killswitch нет", !strings.Contains(tables, "killswitch"), strings.Join(strings.Fields(tables), " "))
	a.expect("8", "-", "файлы и юниты сняты", !strings.Contains(files, "killswitch") && !strings.Contains(files, "on.nft") &&
		!strings.Contains(files, "state.json"), strings.Join(strings.Fields(files), " "))
	a.expect("8", "-", "заглушка systemctl: disable", strings.Contains(string(stubLog), "disable"), lastLines(string(stubLog), 3))
	if err := a.do(a.ns[topo.ClientNS], "ip", "link", "set", topo.PhysIf, "up"); err != nil {
		return err
	}
	if err := a.physRoutes(); err != nil {
		return err
	}
	time.Sleep(time.Second)
	for _, p := range shortProbes {
		a.open("8", p, a.direct(), "после uninstall прямая")
	}
	return nil
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " | ")
}

// zombieNFT — сервер туннеля недоступен: ksl-peer отбрасывает всё входящее для себя (транзит не задет).
const zombieNFT = "table inet ksl_zombie {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tiifname \"lo\" accept\n\t}\n}\n"
