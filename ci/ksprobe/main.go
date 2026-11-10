// Команда ksprobe — проба стенда CI: тот же обмен, что у `killswitch check` (probe.NetProber), от процесса,
// которому политика не доверяет (своя копия exe на Windows, отдельный пользователь на macOS).
//
//	ksprobe <http|udp-echo|dns-udp|dns-tcp> <ip> [интерфейс]
//
// Код 0 — сервер ответил, 1 — ответа нет, 2 — ошибка аргументов или привязки. Интерфейс — привязка сокета к нему
// (BindControl backend ОС). Только для одноразовых раннеров CI.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

type request struct {
	service probe.Service
	dst     netip.Addr
	iface   string
}

func parseArgs(args []string) (request, error) {
	if len(args) < 2 || len(args) > 3 {
		return request{}, errors.New("использование: ksprobe <http|udp-echo|dns-udp|dns-tcp> <ip> [интерфейс]")
	}
	var r request
	found := false
	for _, s := range probe.Services {
		if s.Name == args[0] {
			r.service, found = s, true
		}
	}
	if !found {
		return request{}, fmt.Errorf("неизвестная проба %q", args[0])
	}
	dst, err := netip.ParseAddr(args[1])
	if err != nil {
		return request{}, fmt.Errorf("адрес: %w", err)
	}
	r.dst = dst
	if len(args) == 3 {
		r.iface = args[2]
	}
	return r, nil
}

func main() {
	r, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var iface env.Iface
	bind := health.Binder(func(env.Iface) health.ControlFunc { return nil })
	if r.iface != "" {
		ni, err := net.InterfaceByName(r.iface)
		if err != nil {
			fmt.Fprintln(os.Stderr, "интерфейс:", err)
			os.Exit(2)
		}
		iface = env.Iface{Name: ni.Name, Index: ni.Index}
		if bind, err = systemBinder(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	var bindErr error
	record := recordBind(bind(iface), &bindErr)
	p := probe.NetProber{Bind: func(env.Iface) health.ControlFunc { return record }, Timeout: health.Timeout}
	err = p.Tunnel(context.Background(), r.service, r.dst, iface)
	code := exitCode(err, bindErr)
	switch code {
	case 2:
		fmt.Fprintln(os.Stderr, "привязка к интерфейсу:", bindErr)
	case 1:
		fmt.Printf("нет ответа: %s %s %s: %v\n", r.service.Name, r.dst, r.iface, err)
	default:
		fmt.Printf("ответ: %s %s %s\n", r.service.Name, r.dst, r.iface)
	}
	os.Exit(code)
}

// recordBind сохраняет ошибку привязки в out: по ней ksprobe отличает «проба не ушла» (2) от «нет ответа» (1).
func recordBind(ctrl health.ControlFunc, out *error) health.ControlFunc {
	return func(network, address string, c syscall.RawConn) error {
		if ctrl == nil {
			return nil
		}
		*out = ctrl(network, address, c)
		return *out
	}
}

// exitCode: ошибка привязки — 2 (проба не ушла, по ней «закрыто» не судят), нет ответа — 1, ответ — 0.
func exitCode(probeErr, bindErr error) int {
	switch {
	case bindErr != nil:
		return 2
	case probeErr != nil:
		return 1
	}
	return 0
}
