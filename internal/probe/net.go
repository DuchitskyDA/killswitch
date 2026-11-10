package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
)

// NetProber — пробы настоящими сокетами, привязанными к интерфейсу через Bind (Backend.BindControl).
// Успех — по ответу сервера (HTTP-статус, эхо, ответ DNS), а не по connect: TUN-стеки отвечают SYN-ACK сами.
type NetProber struct {
	Bind    health.Binder
	Timeout time.Duration
}

// Tunnel — baseline сокетом, привязанным к туннельному интерфейсу.
func (n NetProber) Tunnel(ctx context.Context, s Service, dst netip.Addr, tun env.Iface) error {
	d := net.Dialer{Control: n.Bind(tun)}
	return n.exchange(ctx, &d, s, dst)
}

// Route — baseline по маршруту через туннель tun, без привязки; источник не из tun — провал (health.RouteDialer).
func (n NetProber) Route(ctx context.Context, s Service, dst netip.Addr, tun env.Iface) error {
	return n.exchange(ctx, health.RouteDialer{Tun: tun}, s, dst)
}

// Direct — проба через физический интерфейс с портом-источником id.Src.
func (n NetProber) Direct(ctx context.Context, s Service, id ProbeID, iface env.Iface) (bool, error) {
	var bindErr error
	ctrl := n.Bind(iface)
	d := net.Dialer{
		LocalAddr: localAddr(s.Proto, id.Src),
		Control: func(network, address string, c syscall.RawConn) error {
			bindErr = ctrl(network, address, c)
			return bindErr
		},
	}
	err := n.exchange(ctx, &d, s, id.Dst.Addr())
	if bindErr != nil {
		return false, bindErr
	}
	// Сокет не занял адрес и порт пробы (порт занят, адрес исчез): проба не уходила, и молчание ничего не значит.
	var sys *os.SyscallError
	if errors.As(err, &sys) && sys.Syscall == "bind" {
		return false, err
	}
	// Проверку прервали (отмена, а не срок одной пробы): проба не состоялась.
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return err == nil, nil
}

// Resolve — адреса имени системным резолвером.
func (n NetProber) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Plain — обмен сокетом без привязки к интерфейсу, по обычному маршруту.
func (n NetProber) Plain(ctx context.Context, s Service, dst netip.Addr) error {
	return n.exchange(ctx, &net.Dialer{}, s, dst)
}

func (n NetProber) exchange(ctx context.Context, d health.Dialer, s Service, dst netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()
	addr := netip.AddrPortFrom(dst, s.Port)
	conn, err := d.DialContext(ctx, s.Proto, addr.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	switch s.Name {
	case "http":
		host := s.Host
		if host == "" {
			host = dst.String()
		}
		return health.Exchange(conn, host, "/")
	case "dns-tcp":
		q := dnsQuery(dst.Is4())
		return writeRead(conn, append([]byte{byte(len(q) >> 8), byte(len(q))}, q...), 2)
	case "dns-udp":
		return writeRead(conn, dnsQuery(dst.Is4()), 1)
	case "udp-echo":
		return writeRead(conn, []byte("killswitch-probe"), 1)
	}
	return errors.New("неизвестный сервис " + s.Name)
}

func writeRead(conn net.Conn, req []byte, min int) error {
	if _, err := conn.Write(req); err != nil {
		return err
	}
	_, err := io.ReadAtLeast(conn, make([]byte, 512), min)
	return err
}

func localAddr(proto string, src netip.AddrPort) net.Addr {
	if proto == "udp" {
		return net.UDPAddrFromAddrPort(src)
	}
	return net.TCPAddrFromAddrPort(src)
}

// dnsQuery — запрос A (v4) или AAAA (v6) для example.com с RD.
func dnsQuery(v4 bool) []byte {
	qtype := byte(28)
	if v4 {
		qtype = 1
	}
	q := []byte{0x6b, 0x73, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	return append(q, 0, qtype, 0, 1)
}
