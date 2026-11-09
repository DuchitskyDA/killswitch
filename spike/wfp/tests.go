package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

const (
	cfV4  = "1.1.1.1:80" // через TUN в T3 (route_address)
	cfV4b = "1.0.0.1:80" // всегда мимо TUN
	cfV6  = "[2606:4700:4700::1111]:80"
	dnsV4 = "8.8.8.8:53"
	loV4  = "127.0.0.1:47801"
	loV6  = "[::1]:47802"
	loV4b = "127.0.0.1:47803"
	loV6b = "[::1]:47804"
	loV4c = "127.0.0.1:47805"
	loV6c = "[::1]:47806"
)

type baseline struct {
	a4, d4, d4b, ddns, adns, d6, lo4, lo6 pr
}

func (c *ctx) baseline(tag string) baseline {
	b := baseline{
		a4:   c.probe(c.allowed, "http", cfV4),
		d4:   c.probe(c.denied, "http", cfV4),
		d4b:  c.probe(c.denied, "http", cfV4b),
		ddns: c.probe(c.denied, "dns", dnsV4),
		adns: c.probe(c.allowed, "dns", dnsV4),
		d6:   c.probe(c.denied, "http", cfV6),
		lo4:  c.pair(c.denied, c.denied, loV4),
		lo6:  c.pair(c.denied, c.denied, loV6),
	}
	for name, p := range map[string]pr{"allowed-http-v4": b.a4, "denied-http-v4": b.d4, "denied-http-v4b": b.d4b,
		"denied-dns-v4": b.ddns, "allowed-dns-v4": b.adns, "denied-http-v6": b.d6, "loopback-v4": b.lo4, "loopback-v6": b.lo6} {
		st := "PASS"
		if !p.ok {
			st = "INCONCLUSIVE"
		}
		result(tag+".baseline."+name, st, "%s", p)
	}
	return b
}

func (c *ctx) mustApply(s *wf.Session, id string, rules []*wf.Rule) bool {
	t0 := time.Now()
	if err := apply(s, rules); err != nil {
		result(id, "FAIL", "apply: %v", err)
		return false
	}
	info("%s: применено %d фильтров за %v", id, len(rules), time.Since(t0))
	return true
}

// ---- T1: матрица слоёв, loopback, app-id, LUID, soft/hard ----

func t1(c *ctx) {
	b := c.baseline("T1")
	for _, hard := range []bool{false, true} {
		tag := "T1.soft"
		if hard {
			tag = "T1.hard"
		}
		s := mustSession(true, "ks-spike-t1")
		if err := addBase(s, false); err != nil {
			result(tag+".base", "FAIL", "%v", err)
			s.Close()
			continue
		}
		plan := Plan{Tag: "t1", Block: true, HardBlock: hard, Loopback: true, Apps: c.appPermits(c.allowed)}
		rules := plan.Rules()
		fmt.Println("PLAN", tag, "\n"+Render(rules))
		if !c.mustApply(s, tag+".apply", rules) {
			s.Close()
			continue
		}
		expect(tag+".allowed-http-v4", true, b.a4, c.probe(c.allowed, "http", cfV4))
		expect(tag+".denied-http-v4", false, b.d4, c.probe(c.denied, "http", cfV4))
		expect(tag+".denied-dns-v4", false, b.ddns, c.probe(c.denied, "dns", dnsV4))
		expect(tag+".allowed-dns-v4", true, b.adns, c.probe(c.allowed, "dns", dnsV4))
		expect(tag+".denied-http-v6", false, b.d6, c.probe(c.denied, "http", cfV6))
		expect(tag+".loopback-v4", true, b.lo4, c.pair(c.denied, c.denied, loV4))
		expect(tag+".loopback-v6", true, b.lo6, c.pair(c.denied, c.denied, loV6))

		if !hard {
			t1NoLoopback(c, s, plan, b)
			t1Iface(c, s, b)
			printLayerFilters(s, nil)
		}
		s.Close()
	}
	expect("T1.after-close.denied-http-v4", true, b.d4, c.probe(c.denied, "http", cfV4))
}

// t1NoLoopback — без permit loopback: доказательство, что работают V6 и RECV_ACCEPT.
func t1NoLoopback(c *ctx, s *wf.Session, plan Plan, b baseline) {
	var lo []*wf.Rule
	for _, r := range plan.Rules() {
		if strings.Contains(r.Name, "/permit-loopback/") {
			lo = append(lo, r)
		}
	}
	deleteRules(s, lo)
	tag := "T1.noloop"
	expect(tag+".denied-to-denied-v4", false, b.lo4, c.pair(c.denied, c.denied, loV4b))
	expect(tag+".denied-to-denied-v6", false, b.lo6, c.pair(c.denied, c.denied, loV6b))
	// allowed проходит CONNECT, denied-слушатель режется на RECV_ACCEPT
	expect(tag+".recv-accept-v4", false, b.lo4, c.pair(c.denied, c.allowed, loV4c))
	expect(tag+".recv-accept-v6", false, b.lo6, c.pair(c.denied, c.allowed, loV6c))
	// denied режется на CONNECT, слушатель разрешён
	expect(tag+".connect-v4", false, b.lo4, c.pair(c.allowed, c.denied, loV4))
	expect(tag+".connect-v6", false, b.lo6, c.pair(c.allowed, c.denied, loV6))
	expect(tag+".allowed-to-allowed-v4", true, b.lo4, c.pair(c.allowed, c.allowed, loV4b))
	expect(tag+".allowed-to-allowed-v6", true, b.lo6, c.pair(c.allowed, c.allowed, loV6b))
	if err := apply(s, lo); err != nil {
		result(tag+".restore", "FAIL", "%v", err)
	}
}

// t1Iface — permit по LUID физической карты для denied-пробы.
func t1Iface(c *ctx, s *wf.Session, b baseline) {
	phys, err := bestAdapter(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		result("T1.iface", "FAIL", "bestAdapter: %v", err)
		return
	}
	info("физический интерфейс: %q %q idx=%d luid=0x%x", phys.FriendlyName, phys.Description, phys.Index, phys.LUID)
	rules := Plan{Tag: "t1", Ifaces: []IfacePermit{{Name: "phys", LUID: phys.LUID}}}.Rules()
	if !c.mustApply(s, "T1.iface.apply", rules) {
		return
	}
	expect("T1.iface-luid.denied-http-v4", true, b.d4, c.probe(c.denied, "http", cfV4))
	deleteRules(s, rules)
	expect("T1.iface-luid-removed.denied-http-v4", false, b.d4, c.probe(c.denied, "http", cfV4))
}

// ---- T2: правила Windows Defender Firewall против нашего block ----

func t2(c *ctx) {
	b := c.baseline("T2")
	prof, _ := runPS(`$p = Get-NetFirewallProfile | select Name,Enabled,DefaultOutboundAction; $p | Export-Csv -NoTypeInformation C:\ks\wdf-profiles.csv; $p | ft | Out-String`)
	info("WDF до теста:\n%s", prof)
	ps := func(id, script string) {
		out, err := runPS(script)
		if err != nil {
			result(id, "FAIL", "powershell: %v %s", err, out)
		} else if out != "" {
			info("%s: %s", id, out)
		}
	}
	rule := func(name, prog, action string) string {
		return fmt.Sprintf(`New-NetFirewallRule -Group ks-spike -DisplayName %s -Direction Outbound -Program '%s' -Action %s | Out-Null;`, name, prog, action)
	}
	ps("T2.enable", `Set-NetFirewallProfile -All -Enabled True`)

	// W0: WDF включён и работает (block-правило режет allowed без нашего набора).
	ps("T2.w0.rule", rule("ks-spike-block-allowed", c.allowed, "Block"))
	expect("T2.w0.wdf-block-rule-works", false, b.a4, c.probe(c.allowed, "http", cfV4))
	ps("T2.w0.clean", `Get-NetFirewallRule -Group ks-spike | Remove-NetFirewallRule`)

	// W1: WDF по умолчанию Block, allow-правила для раннера и denied: allow работает.
	var allow strings.Builder
	for i, p := range append(append([]string{}, c.runnerApps...), c.denied) {
		allow.WriteString(rule(fmt.Sprintf("ks-spike-allow-%02d", i), p, "Allow"))
	}
	ps("T2.w1.rules", allow.String()+`Set-NetFirewallProfile -All -DefaultOutboundAction Block`)
	w1d := c.probe(c.denied, "http", cfV4)
	expect("T2.w1.wdf-allow-rule-works", true, b.d4, w1d)
	expect("T2.w1.wdf-default-block-works", false, b.a4, c.probe(c.allowed, "http", cfV4))

	for _, hard := range []bool{false, true} {
		tag := "T2.w2.soft"
		if hard {
			tag = "T2.w2.hard"
		}
		s := mustSession(true, "ks-spike-t2")
		if err := addBase(s, false); err == nil &&
			c.mustApply(s, tag+".apply", Plan{Tag: "t2", Block: true, HardBlock: hard, Loopback: true, Apps: c.appPermits(c.allowed)}.Rules()) {
			expect(tag+".wdf-allow-does-not-punch", false, w1d, c.probe(c.denied, "http", cfV4))
			got := c.probe(c.allowed, "http", cfV4)
			result(tag+".our-permit-vs-wdf-default-block", "INFO", "allowed (наш permit, WDF default Block): %s", got)
		}
		s.Close()
	}
	ps("T2.w1.restore", `Import-Csv C:\ks\wdf-profiles.csv | % { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction $_.DefaultOutboundAction };`+
		`Get-NetFirewallRule -Group ks-spike | Remove-NetFirewallRule`)

	// W4: WDF по умолчанию как было, allow-правило для denied + наш soft block.
	ps("T2.w4.rule", rule("ks-spike-allow-denied", c.denied, "Allow"))
	s := mustSession(true, "ks-spike-t2")
	if err := addBase(s, false); err == nil &&
		c.mustApply(s, "T2.w4.apply", Plan{Tag: "t2", Block: true, Loopback: true, Apps: c.appPermits(c.allowed)}.Rules()) {
		expect("T2.w4.wdf-allow-does-not-punch-default", false, b.d4, c.probe(c.denied, "http", cfV4))
		// W5: WDF block-правило для программы, которую разрешаем мы.
		ps("T2.w5.rule", rule("ks-spike-block-allowed", c.allowed, "Block"))
		result("T2.w5.wdf-block-vs-our-permit", "INFO", "allowed (наш permit + WDF Block-правило): %s", c.probe(c.allowed, "http", cfV4))
	}
	s.Close()
	ps("T2.restore", `Get-NetFirewallRule -Group ks-spike | Remove-NetFirewallRule;`+
		`Import-Csv C:\ks\wdf-profiles.csv | % { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction $_.DefaultOutboundAction -Enabled $_.Enabled }`)
	expect("T2.after.denied-http-v4", true, b.d4, c.probe(c.denied, "http", cfV4))
}

// ---- T3: sing-box TUN + strict_route в обоих порядках ----

type singbox struct {
	cmd *exec.Cmd
	log string
}

func (c *ctx) startSingbox(tag string) (*singbox, Adapter, error) {
	exe := filepath.Join(c.dir, "singbox", "sing-box.exe")
	logp := filepath.Join(c.dir, "singbox-"+tag+".log")
	f, err := os.Create(logp)
	if err != nil {
		return nil, Adapter{}, err
	}
	cmd := exec.Command(exe, "run", "-c", filepath.Join(c.dir, "singbox.json"), "-D", filepath.Join(c.dir, "singbox"))
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, Adapter{}, err
	}
	sb := &singbox{cmd: cmd, log: logp}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if a, ok := adapterByName("ks-tun"); ok && a.Up {
			time.Sleep(3 * time.Second) // маршруты и WFP sing-box
			info("TUN %s: %q idx=%d luid=0x%x", tag, a.Description, a.Index, a.LUID)
			return sb, a, nil
		}
	}
	return sb, Adapter{}, fmt.Errorf("TUN ks-tun не поднялся за 30 с")
}

func (sb *singbox) stop() {
	if sb == nil {
		return
	}
	_ = sb.cmd.Process.Kill()
	_ = sb.cmd.Wait()
	b, _ := os.ReadFile(sb.log)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 25 {
		lines = lines[len(lines)-25:]
	}
	fmt.Println("sing-box log (хвост):\n" + strings.Join(lines, "\n"))
	time.Sleep(2 * time.Second)
}

func resolveCheck(id string) {
	out, err := runPS(`Clear-DnsClientCache; try { ([System.Net.Dns]::GetHostAddresses('www.microsoft.com') | select -First 1).IPAddressToString } catch { 'ERR ' + $_.Exception.Message }`)
	st := "PASS"
	if err != nil || strings.HasPrefix(out, "ERR") || out == "" {
		st = "FAIL"
	}
	result(id, st, "системный резолвер: %s %v", out, err)
}

// foreignWFP — provider и sublayer, появившиеся после старта клиента.
func foreignWFP(before map[wf.ProviderID]bool) {
	s, err := openSession(false, "ks-spike-t3-list")
	if err != nil {
		return
	}
	defer s.Close()
	provs, _ := s.Providers()
	subs, _ := s.Sublayers()
	for _, p := range provs {
		if before[p.ID] || p.ID == providerID {
			continue
		}
		fmt.Printf("NEW PROVIDER %s %q persistent=%t\n", p.ID, p.Name, p.Persistent)
		for _, sl := range subs {
			if sl.Provider == p.ID {
				fmt.Printf("  SUBLAYER weight=0x%04X %q\n", sl.Weight, sl.Name)
			}
		}
		pid := windows.GUID(p.ID)
		fs, _ := ourFiltersOf(s, &pid)
		for _, f := range fs {
			fmt.Printf("  FILTER layer=%s sublayer=%s action=0x%x flags=0x%x weight=%s eff=%s %q\n",
				wf.LayerID(f.Layer), wf.SublayerID(f.Sublayer), f.Action, f.Flags, f.Weight, f.EffectiveWeight, f.Name)
		}
	}
	// sublayers без provider с весом рядом с нашим
	for _, sl := range subs {
		if sl.Weight >= 0xFF00 {
			fmt.Printf("HIGH SUBLAYER weight=0x%04X %q provider=%s\n", sl.Weight, sl.Name, sl.Provider)
		}
	}
}

func ourFiltersOf(s *wf.Session, provider *windows.GUID) ([]FilterInfo, error) {
	layers, err := s.Layers()
	if err != nil {
		return nil, err
	}
	var out []FilterInfo
	for _, l := range layers {
		fs, _ := enumFilters(s, l.ID, provider, enumFlagIncludeDisabled)
		out = append(out, fs...)
	}
	return out, nil
}

func providerSet() map[wf.ProviderID]bool {
	m := map[wf.ProviderID]bool{}
	s, err := openSession(false, "ks-spike-t3-list")
	if err != nil {
		return m
	}
	defer s.Close()
	provs, _ := s.Providers()
	for _, p := range provs {
		m[p.ID] = true
	}
	return m
}

func t3(c *ctx) {
	b := c.baseline("T3")
	sbExe := filepath.Join(c.dir, "singbox", "sing-box.exe")
	before := providerSet()

	// Без нашего набора: sing-box сам по себе.
	sb, tun, err := c.startSingbox("alone")
	if err != nil {
		result("T3.alone.start", "FAIL", "%v", err)
		sb.stop()
		return
	}
	result("T3.alone.start", "PASS", "TUN luid=0x%x", tun.LUID)
	expect("T3.alone.via-tun-http", true, b.d4, c.probe(c.denied, "http", cfV4))
	expect("T3.alone.direct-http", true, b.d4b, c.probe(c.denied, "http", cfV4b))
	result("T3.alone.denied-dns-8.8.8.8", "INFO", "%s", c.probe(c.denied, "dns", dnsV4))
	resolveCheck("T3.alone.resolver")
	foreignWFP(before)
	sb.stop()
	resolveCheck("T3.alone.after-stop.resolver")

	plan := func(ifaces ...IfacePermit) []*wf.Rule {
		return Plan{Tag: "t3", Block: true, Loopback: true, Apps: c.appPermits(c.allowed, sbExe), Ifaces: ifaces}.Rules()
	}
	checks := func(tag string) {
		expect(tag+".denied-via-tun", true, b.d4, c.probe(c.denied, "http", cfV4))
		expect(tag+".denied-direct", false, b.d4b, c.probe(c.denied, "http", cfV4b))
		expect(tag+".denied-dns-direct", false, b.ddns, c.probe(c.denied, "dns", dnsV4))
		expect(tag+".allowed-direct", true, b.a4, c.probe(c.allowed, "http", cfV4b))
		resolveCheck(tag + ".resolver")
	}

	// Порядок A: наш набор → клиент → permit LUID.
	{
		s := mustSession(true, "ks-spike-t3a")
		if err := addBase(s, false); err == nil && c.mustApply(s, "T3.A.apply", plan()) {
			sb, tun, err := c.startSingbox("A")
			if err != nil {
				result("T3.A.start", "FAIL", "%v", err)
			} else {
				result("T3.A.start", "PASS", "sing-box поднял TUN под нашим набором, luid=0x%x", tun.LUID)
				expect("T3.A.tun-without-luid-permit", false, b.d4, c.probe(c.denied, "http", cfV4))
				ifr := Plan{Tag: "t3", Ifaces: []IfacePermit{{Name: "tun", LUID: tun.LUID}}}.Rules()
				if c.mustApply(s, "T3.A.luid", ifr) {
					checks("T3.A")
				}
				// Перезапуск клиента: меняется ли LUID?
				sb.stop()
				sb2, tun2, err := c.startSingbox("A2")
				if err != nil {
					result("T3.A.restart", "FAIL", "%v", err)
				} else {
					result("T3.A.restart.luid", "INFO", "LUID до 0x%x, после 0x%x, совпал=%t", tun.LUID, tun2.LUID, tun.LUID == tun2.LUID)
					expect("T3.A.restart.denied-via-tun-old-permit", tun.LUID == tun2.LUID, b.d4, c.probe(c.denied, "http", cfV4))
				}
				sb = sb2
			}
			sb.stop()
		}
		s.Close()
	}
	// Порядок B: клиент → наш набор (с LUID сразу).
	{
		sb, tun, err := c.startSingbox("B")
		if err != nil {
			result("T3.B.start", "FAIL", "%v", err)
		} else {
			s := mustSession(true, "ks-spike-t3b")
			if err := addBase(s, false); err == nil && c.mustApply(s, "T3.B.apply", plan(IfacePermit{Name: "tun", LUID: tun.LUID})) {
				checks("T3.B")
				printLayerFilters(s, nil)
			}
			s.Close()
		}
		sb.stop()
	}
	resolveCheck("T3.after.resolver")
	expect("T3.after.denied-http-v4", true, b.d4, c.probe(c.denied, "http", cfV4))
}

// ---- T4: уже открытые потоки ----

type hold struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	local  string
	remote string
}

func (c *ctx) startHold(exe, kind, addr string) (*hold, error) {
	cmd := exec.Command(exe, "probe", kind, addr)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	h := &hold{cmd: cmd, stdin: in, lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			h.lines <- sc.Text()
		}
		close(h.lines)
	}()
	l := h.next()
	if !strings.HasPrefix(l, "HOLD local=") {
		return h, fmt.Errorf("hold: %s", l)
	}
	for _, f := range strings.Fields(l)[1:] {
		k, v, _ := strings.Cut(f, "=")
		if k == "local" {
			h.local = v
		} else {
			h.remote = v
		}
	}
	return h, nil
}

func (h *hold) next() string {
	select {
	case l, ok := <-h.lines:
		if !ok {
			return "EOF"
		}
		return l
	case <-time.After(15 * time.Second):
		return "TIMEOUT"
	}
}

func (h *hold) req() string {
	fmt.Fprintln(h.stdin, "next")
	return h.next()
}

func (h *hold) close() {
	if h == nil {
		return
	}
	h.stdin.Close()
	_ = h.cmd.Process.Kill()
	_ = h.cmd.Wait()
}

func t4(c *ctx) {
	type flow struct{ name, exe, kind, addr string }
	flows := []flow{
		{"denied-tcp", c.denied, "hold", cfV4},
		{"allowed-tcp", c.allowed, "hold", cfV4},
		{"denied-udp", c.denied, "holdudp", dnsV4},
	}
	// Контроль: без правил второй запрос по тому же потоку проходит.
	ctrl := map[string]bool{}
	for _, f := range flows {
		h, err := c.startHold(f.exe, f.kind, f.addr)
		r1 := ""
		if err == nil {
			r1 = h.next()
		}
		r2 := ""
		if err == nil {
			r2 = h.req()
		}
		ctrl[f.name] = err == nil && r1 == "REQ1 ok" && r2 == "REQ2 ok"
		st := "PASS"
		if !ctrl[f.name] {
			st = "INCONCLUSIVE"
		}
		result("T4.control."+f.name, st, "%v %s %s", err, r1, r2)
		h.close()
	}

	holds := map[string]*hold{}
	for _, f := range flows {
		h, err := c.startHold(f.exe, f.kind, f.addr)
		if err != nil {
			result("T4."+f.name+".open", "FAIL", "%v", err)
			continue
		}
		r1 := h.next()
		info("T4 %s: %s %s→%s", f.name, r1, h.local, h.remote)
		holds[f.name] = h
	}
	s := mustSession(true, "ks-spike-t4")
	defer s.Close()
	if err := addBase(s, false); err != nil || !c.mustApply(s, "T4.apply", Plan{Tag: "t4", Block: true, Loopback: true, Apps: c.appPermits(c.allowed)}.Rules()) {
		return
	}
	time.Sleep(time.Second)
	for _, f := range flows {
		h := holds[f.name]
		if h == nil {
			continue
		}
		r := h.req()
		st := "INFO"
		if !ctrl[f.name] {
			st = "INCONCLUSIVE"
		}
		result("T4.after-block."+f.name, st, "запрос по открытому до блока потоку: %s", r)
		if f.name == "denied-tcp" && r == "REQ2 ok" {
			lp, e1 := netip.ParseAddrPort(h.local)
			rp, e2 := netip.ParseAddrPort(h.remote)
			if e1 == nil && e2 == nil {
				err := deleteTCB(lp, rp)
				result("T4.delete-tcb.denied-tcp", "INFO", "SetTcpEntry DELETE_TCB: %v; следующий запрос: %s", err, h.req())
			}
		}
		h.close()
	}
	// Новый поток после блока — контроль.
	expect("T4.new-flow.denied-tcp", false, pr{ok: ctrl["denied-tcp"]}, c.probe(c.denied, "http", cfV4))
}

// ---- T5: транзакции, persistent, boot-time, снятие ----

func t5tx(c *ctx) {
	// Остатки прошлых шагов.
	if s, err := openSession(false, "ks-spike-pre"); err == nil {
		removeOurs(s)
		s.Close()
	}
	s := mustSession(true, "ks-spike-t5tx")
	defer s.Close()

	// a) атомарность: битый фильтр → abort → ничего нашего нет.
	err := txBegin(s)
	if err != nil {
		result("T5.tx.begin", "FAIL", "%v (раскладка wf.Session или хендл)", err)
		return
	}
	errs := []string{}
	if err := addBase(s, false); err != nil {
		errs = append(errs, err.Error())
	}
	good := Plan{Tag: "tx", Block: true, Loopback: true, Apps: c.appPermits()}.Rules()
	for _, r := range good[:2] {
		if err := s.AddRule(r); err != nil {
			errs = append(errs, err.Error())
		}
	}
	bad := &wf.Rule{ID: ruleKey("ks-spike/tx/bad"), Name: "ks-spike/tx/bad", Layer: wf.LayerID{}, Sublayer: sublayerID, Provider: providerID, Action: wf.ActionBlock}
	badErr := s.AddRule(bad)
	abortErr := txAbort(s)
	left, enumErr := ourFilters(s)
	provs, _ := s.Providers()
	hasProv := false
	for _, p := range provs {
		hasProv = hasProv || p.ID == providerID
	}
	st := "PASS"
	if badErr == nil || len(left) != 0 || hasProv || len(errs) > 0 {
		st = "FAIL"
	}
	result("T5.tx.abort-atomic", st, "битый фильтр: %v; abort: %v; после abort наших фильтров=%d provider=%t; ошибки до битого: %v; enum: %v",
		badErr, abortErr, len(left), hasProv, errs, enumErr)

	// b) commit: provider + sublayer + набор одной транзакцией.
	t0 := time.Now()
	err = txBegin(s)
	if err == nil {
		err = addBase(s, false)
	}
	for _, r := range good {
		if err == nil {
			err = s.AddRule(r)
		}
	}
	if err == nil {
		err = txCommit(s)
	} else {
		_ = txAbort(s)
	}
	left, _ = ourFilters(s)
	st = "PASS"
	if err != nil || len(left) != len(good) {
		st = "FAIL"
	}
	result("T5.tx.commit", st, "ошибка: %v; фильтров %d из %d за %v", err, len(left), len(good), time.Since(t0))
	s.Close()

	// c) persistent-объект из dynamic-сессии.
	s2 := mustSession(true, "ks-spike-t5dyn")
	err = s2.AddProvider(&wf.Provider{ID: providerID, Name: providerName, Persistent: true})
	result("T5.dynamic-session-persistent-provider", "INFO", "AddProvider(Persistent) в dynamic-сессии: %v", err)
	s2.Close()
	if s3, err := openSession(false, "ks-spike-t5clean"); err == nil {
		removeOurs(s3)
		s3.Close()
	}
}

// bootVariants — варианты размещения boot-time-фильтров (запасные — без provider/sublayer).
func bootVariants(apps []AppPermit) []Plan {
	base := Plan{Block: true, Loopback: true, DHCP: true, Apps: apps, BootTime: true}
	v := []Plan{base, base, base, base}
	v[0].Tag = "boot0"
	v[1].Tag, v[1].NoProvider = "boot1", true
	v[2].Tag, v[2].NoSublayer = "boot2", true
	v[3].Tag, v[3].NoProvider, v[3].NoSublayer = "boot3", true, true
	return v
}

func t5setup(c *ctx) {
	b := c.baseline("T5")
	if s, err := openSession(false, "ks-spike-pre"); err == nil {
		n, err := removeOurs(s)
		info("остатки: снято %d (%v)", n, err)
		s.Close()
	}
	s := mustSession(false, "ks-spike-t5")
	if err := addBase(s, true); err != nil {
		result("T5.persistent.base", "FAIL", "%v", err)
		s.Close()
		return
	}
	apps := c.appPermits(c.allowed)

	// boot-time: первый вариант, который WFP примет.
	for _, p := range bootVariants(apps) {
		rules := p.Rules()
		err := apply(s, rules)
		result("T5.boottime.add."+p.Tag, map[bool]string{true: "PASS", false: "INFO"}[err == nil],
			"provider=%t sublayer=%t: %v", !p.NoProvider, !p.NoSublayer, err)
		if err == nil {
			fmt.Println("PLAN boot\n" + Render(rules))
			break
		}
	}
	// Действует ли boot-time при работающем BFE?
	result("T5.boottime.active-at-runtime", "INFO", "denied при одних boot-time-фильтрах: %s", c.probe(c.denied, "http", cfV4))

	// persistent-набор.
	prules := Plan{Tag: "t5", Block: true, Loopback: true, DHCP: true, Apps: apps, Persistent: true}.Rules()
	fmt.Println("PLAN persistent\n" + Render(prules))
	c.mustApply(s, "T5.persistent.apply", prules)
	// boot-time и persistent в одном фильтре.
	both := Plan{Tag: "both", Block: true, Persistent: true}.Rules()[0]
	both.BootTime = true
	result("T5.boottime+persistent-one-filter", "INFO", "AddRule с обоими флагами: %v", s.AddRule(both))
	_ = s.DeleteRule(both.ID)
	s.Close()

	// Сессия закрыта, процесс ещё жив: persistent действует сам по себе.
	expect("T5.persistent.after-session-close.denied", false, b.d4, c.probe(c.denied, "http", cfV4))
	expect("T5.persistent.after-session-close.allowed", true, b.a4, c.probe(c.allowed, "http", cfV4))
	expect("T5.persistent.loopback-v4", true, b.lo4, c.pair(c.denied, c.denied, loV4))
}
