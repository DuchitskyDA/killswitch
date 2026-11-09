//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/capture"
	"github.com/DuchitskyDA/killswitch/lab/internal/lab"
	"github.com/DuchitskyDA/killswitch/lab/internal/nsguard"
	"github.com/DuchitskyDA/killswitch/lab/internal/probe"
	"github.com/DuchitskyDA/killswitch/lab/internal/services"
	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
	"github.com/DuchitskyDA/killswitch/lab/internal/wgset"
)

func dispatch(cmd string, args []string) error {
	switch cmd {
	case "run":
		return lab.Main(args, os.Stdout)
	case "accept":
		return lab.Accept(args, os.Stdout)
	case "ksexec":
		return ksexec(args)
	case "cleanup":
		return lab.Cleanup(os.Stdout)
	case "nsexec":
		return nsexec(args)
	case "serve":
		return serve(args)
	case "capture":
		return captureCmd(args)
	case "probe":
		return probeCmd(args)
	case "mark":
		return mark(args)
	case "wgset":
		return wgsetCmd(args)
	}
	return fmt.Errorf("неизвестная подкоманда %q", cmd)
}

// inner разбирает флаги подкоманды, работающей внутри ns, и сверяет её namespace до любой работы.
func inner(name string, args []string, def func(*flag.FlagSet)) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	ino := fs.Uint64("expect-ino", 0, "inode network namespace, в котором обязана работать подкоманда")
	def(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return fs, nsguard.SelfCheck(*ino)
}

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}

func nsexec(args []string) error {
	fs := flag.NewFlagSet("nsexec", flag.ContinueOnError)
	path := fs.String("ns-path", "", "путь к namespace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	n, err := nsguard.OpenPath(*path, 0)
	if err != nil {
		return err
	}
	cmd, err := n.Cmd(context.Background(), nil, fs.Args()...)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func serve(args []string) error {
	var addrList *string
	if _, err := inner("serve", args, func(fs *flag.FlagSet) {
		addrList = fs.String("addrs", topo.InetV4.String()+","+topo.InetV6.String(), "адреса сервисов через запятую")
	}); err != nil {
		return err
	}
	var addrs []netip.Addr
	for _, s := range strings.Split(*addrList, ",") {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return err
		}
		addrs = append(addrs, a)
	}
	ctx, cancel := signalCtx()
	defer cancel()
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	errc := make(chan error, 1)
	go func() {
		errc <- services.Serve(ctx, services.Config{
			Addrs: addrs, AnswerA: topo.DNSAnswerA, AnswerAAAA: topo.DNSAnswerAAAA,
			HTTPPort: topo.HTTPPort, UDPPort: topo.UDPPort, DNSPort: topo.DNSPort,
		}, func(e services.Entry) { mu.Lock(); enc.Encode(e); mu.Unlock() })
	}()
	select {
	case err := <-errc:
		return err
	case <-time.After(300 * time.Millisecond):
	}
	mu.Lock()
	fmt.Println(topo.ServeReadyMsg)
	mu.Unlock()
	return <-errc
}

func captureCmd(args []string) error {
	var iface *string
	if _, err := inner("capture", args, func(fs *flag.FlagSet) { iface = fs.String("iface", topo.CaptureIf, "") }); err != nil {
		return err
	}
	ctx, cancel := signalCtx()
	defer cancel()
	enc := json.NewEncoder(os.Stdout)
	return capture.Run(ctx, *iface, func() { fmt.Println(topo.ServeReadyMsg) }, func(f capture.Flow) { enc.Encode(f) })
}

func probeCmd(args []string) error {
	var kind, dst, bind *string
	var port, uid, sport, mark *uint
	var timeout *time.Duration
	_, err := inner("probe", args, func(fs *flag.FlagSet) {
		kind = fs.String("kind", "http", "http|udp|dnsudp|dnstcp")
		dst = fs.String("dst", "", "адрес")
		port = fs.Uint("port", 80, "порт")
		bind = fs.String("bind", "", "интерфейс SO_BINDTODEVICE")
		timeout = fs.Duration("timeout", 1500*time.Millisecond, "")
		uid = fs.Uint("uid", 0, "понизить права до uid (и gid того же номера) после сверки ns")
		sport = fs.Uint("sport", 0, "порт-источник")
		mark = fs.Uint("mark", 0, "SO_MARK")
	})
	if err != nil {
		return err
	}
	if *uid != 0 {
		if err := dropTo(int(*uid)); err != nil {
			return err
		}
	}
	a, err := netip.ParseAddr(*dst)
	if err != nil {
		return err
	}
	r := probe.Run(probe.Spec{Kind: probe.Kind(*kind), Dst: a, Port: uint16(*port), Bind: *bind, Timeout: *timeout,
		SrcPort: uint16(*sport), Mark: uint32(*mark)})
	return json.NewEncoder(os.Stdout).Encode(r)
}

func mark(args []string) error {
	var id, dst *string
	if _, err := inner("mark", args, func(fs *flag.FlagSet) {
		id = fs.String("id", "", "")
		dst = fs.String("dst", topo.ClientV4.String(), "")
	}); err != nil {
		return err
	}
	c, err := net.Dial("udp", net.JoinHostPort(*dst, strconv.Itoa(topo.MarkPort)))
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(topo.MarkPrefix + *id + "\n"))
	return err
}

func wgsetCmd(args []string) error {
	var show *string
	if _, err := inner("wgset", args, func(fs *flag.FlagSet) { show = fs.String("show", "", "показать устройство") }); err != nil {
		return err
	}
	if *show != "" {
		s, err := wgset.Show(*show)
		if err != nil {
			return err
		}
		fmt.Println(s)
		return nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var c wgset.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	return wgset.Apply(c)
}

// dropTo понижает права пробы: сверка ns (stat /proc/1/ns/net) уже прошла от root, дальше — «обычная программа».
func dropTo(uid int) error {
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(uid); err != nil {
		return err
	}
	return syscall.Setuid(uid)
}

// ksexec — запуск killswitch (или раннего юнита) внутри ksl-client и mount ns держателя: сверка обоих inode,
// tmpfs поверх IsolatedDirs и заглушка systemctl в PATH — до exec. Иначе выход 2.
func ksexec(args []string) error {
	var mnt *uint64
	var stub *string
	var ino *uint64
	fs := flag.NewFlagSet("ksexec", flag.ContinueOnError)
	ino = fs.Uint64("expect-ino", 0, "inode network namespace ksl-client")
	mnt = fs.Uint64("expect-mnt", 0, "inode mount namespace держателя")
	stub = fs.String("stub", "", "каталог заглушки systemctl")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := nsguard.CheckExec(nsguard.Exec{Ino: *ino, Mnt: *mnt, Stub: *stub, SelfNet: nsguard.SelfCheck,
		SelfMnt: nsguard.SelfCheckMount, IsTmpfs: nsguard.IsTmpfs, LookPath: exec.LookPath}); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("ksexec: нет команды")
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, os.Environ())
}
