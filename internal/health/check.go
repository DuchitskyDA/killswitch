package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// ControlFunc привязывает сокет к интерфейсу (Linux SO_BINDTODEVICE, Windows IP_UNICAST_IF,
// macOS IP_BOUND_IF). Реализация — у backend ОС (Backend.BindControl).
type ControlFunc func(network, address string, c syscall.RawConn) error

// Binder выдаёт ControlFunc для интерфейса.
type Binder func(iface env.Iface) ControlFunc

// Gate — предусловия up: интерфейс туннеля поднят и эффективный маршрут к dns.health идёт через туннель.
func Gate(e env.Env, p policy.Policy) (env.Iface, error) {
	if p.Health == nil {
		return env.Iface{}, errors.New("dns.health не задан")
	}
	route, ok := e.Routes[p.Health.Addr.Addr()]
	if !ok || !route.ViaTunnel {
		return env.Iface{}, fmt.Errorf("маршрут к %s не через туннель", p.Health.Addr)
	}
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		if i.Up && i.Index == route.IfaceIndex {
			return i, nil
		}
	}
	return env.Iface{}, errors.New("интерфейс туннеля маршрута к dns.health не поднят")
}

// Check — одна проверка: HTTP GET к dns.health по эффективному маршруту через туннель tun (Gate: маршрут через него)
// с проверкой адреса-источника; здоровье — ответ, начинающийся с "HTTP/", не позже Timeout. Без привязки к TUN:
// перенаправление клиента (sing-box auto_redirect) ломает обмен привязанного сокета. Локальный SYN-ACK от TUN без
// ответа сервера здоровьем не считается.
func Check(ctx context.Context, h policy.HealthURL, tun env.Iface) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	return HTTPGet(ctx, RouteDialer{Tun: tun}, h.Addr, h.Path)
}

// Dialer открывает соединение: *net.Dialer или RouteDialer.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// RouteDialer — соединение без привязки к интерфейсу, по эффективному маршруту. Принимается, только если его
// адрес-источник — адрес Tun: маршрут, сменившийся после снимка, даёт провал, а не обмен мимо туннеля.
type RouteDialer struct{ Tun env.Iface }

// DialContext — net.Dialer без Control и проверка адреса-источника.
func (r RouteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if !r.owns(conn.LocalAddr()) {
		conn.Close()
		return nil, fmt.Errorf("соединение ушло не через туннель %s: адрес-источник %s", r.Tun.Name, conn.LocalAddr())
	}
	return conn, nil
}

func (r RouteDialer) owns(local net.Addr) bool {
	ap, err := netip.ParseAddrPort(local.String())
	if err != nil {
		return false
	}
	src := ap.Addr().Unmap().WithZone("")
	for _, p := range r.Tun.Addrs {
		if p.Addr().Unmap().WithZone("") == src {
			return true
		}
	}
	return false
}

// HTTPGet открывает TCP через d и проверяет, что сервер ответил строкой статуса HTTP.
func HTTPGet(ctx context.Context, d Dialer, addr netip.AddrPort, path string) error {
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return Exchange(conn, addr.Addr().String(), path)
}

// Exchange пишет GET и читает начало ответа.
func Exchange(conn net.Conn, host, path string) error {
	req := "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: killswitch\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	head := make([]byte, 5)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("нет ответа сервера: %w", err)
	}
	if !strings.HasPrefix(string(head), "HTTP/") {
		return fmt.Errorf("ответ не HTTP: %q", head)
	}
	return nil
}

// Step — одна проверка и учёт её итога в машине.
func (m *Machine) Step(ctx context.Context, now time.Time, e env.Env, p policy.Policy) env.HealthState {
	tun, err := Gate(e, p)
	if err == nil {
		err = Check(ctx, *p.Health, tun)
	}
	return m.Observe(now, err == nil)
}
