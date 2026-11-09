// Package services — «интернет»-хост и контрольный получатель: HTTP-эхо источника, UDP-эхо, DNS UDP и TCP.
// Каждое принятое соединение или датаграмма отдаётся в emit — это журнал получателя.
package services

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/dnsmsg"
)

// Entry — запись получателя.
type Entry struct {
	Svc   string     `json:"svc"`
	Proto string     `json:"proto"`
	Port  uint16     `json:"port"`
	Src   netip.Addr `json:"src"`
	Dst   netip.Addr `json:"dst"`
}

type Config struct {
	Addrs               []netip.Addr
	AnswerA, AnswerAAAA netip.Addr
	HTTPPort, UDPPort   uint16
	DNSPort             uint16
}

// Serve слушает все сервисы на всех адресах, пока ctx жив.
func Serve(ctx context.Context, c Config, emit func(Entry)) error {
	var lc net.ListenConfig
	var mu sync.Mutex
	log := func(e Entry) { mu.Lock(); defer mu.Unlock(); emit(e) }
	var closers []io.Closer
	defer func() {
		for _, x := range closers {
			x.Close()
		}
	}()
	for _, a := range c.Addrs {
		tl, err := lc.Listen(ctx, "tcp", netip.AddrPortFrom(a, c.HTTPPort).String())
		if err != nil {
			return err
		}
		closers = append(closers, tl)
		go acceptLoop(tl, func(conn net.Conn) { serveHTTP(conn, a, c.HTTPPort, log) })

		ul, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(a, c.UDPPort).String())
		if err != nil {
			return err
		}
		closers = append(closers, ul)
		go udpLoop(ul.(*net.UDPConn), func(p []byte, from netip.AddrPort) []byte {
			log(Entry{"udp-echo", "udp", c.UDPPort, from.Addr().Unmap(), a})
			return []byte("src=" + from.Addr().Unmap().String() + "\n")
		})

		dl, err := lc.ListenPacket(ctx, "udp", netip.AddrPortFrom(a, c.DNSPort).String())
		if err != nil {
			return err
		}
		closers = append(closers, dl)
		go udpLoop(dl.(*net.UDPConn), func(p []byte, from netip.AddrPort) []byte {
			log(Entry{"dns-udp", "udp", c.DNSPort, from.Addr().Unmap(), a})
			r, err := dnsmsg.Answer(p, c.AnswerA, c.AnswerAAAA)
			if err != nil {
				return nil
			}
			return r
		})

		dt, err := lc.Listen(ctx, "tcp", netip.AddrPortFrom(a, c.DNSPort).String())
		if err != nil {
			return err
		}
		closers = append(closers, dt)
		go acceptLoop(dt, func(conn net.Conn) { serveDNSTCP(conn, a, c, log) })
	}
	<-ctx.Done()
	return nil
}

func acceptLoop(l net.Listener, h func(net.Conn)) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go h(conn)
	}
}

func udpLoop(c *net.UDPConn, h func([]byte, netip.AddrPort) []byte) {
	buf := make([]byte, 2048)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if r := h(buf[:n], from); r != nil {
			c.WriteToUDPAddrPort(r, from)
		}
	}
}

func remote(conn net.Conn) netip.Addr {
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func serveHTTP(conn net.Conn, dst netip.Addr, port uint16, log func(Entry)) {
	defer conn.Close()
	src := remote(conn)
	log(Entry{"http", "tcp", port, src, dst})
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}
	fmt.Fprintf(conn, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsrc=%s\n", src)
}

func serveDNSTCP(conn net.Conn, dst netip.Addr, c Config, log func(Entry)) {
	defer conn.Close()
	log(Entry{"dns-tcp", "tcp", c.DNSPort, remote(conn), dst})
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return
	}
	q := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, q); err != nil {
		return
	}
	r, err := dnsmsg.Answer(q, c.AnswerA, c.AnswerAAAA)
	if err != nil {
		return
	}
	conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
}
