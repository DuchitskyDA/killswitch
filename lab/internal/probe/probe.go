// Package probe — клиентская проба: HTTP, UDP-эхо, DNS по UDP и TCP. Успех — только по содержимому ответа:
// TUN-стеки sing-box и xray отвечают SYN-ACK сами, поэтому connect ничего не доказывает.
package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/dnsmsg"
	"github.com/DuchitskyDA/killswitch/lab/internal/topo"
)

type Kind string

const (
	HTTP   Kind = "http"
	UDP    Kind = "udp"
	DNSUDP Kind = "dnsudp"
	DNSTCP Kind = "dnstcp"
)

type Spec struct {
	Kind    Kind
	Dst     netip.Addr
	Port    uint16
	Bind    string // интерфейс для SO_BINDTODEVICE; пусто — по маршрутам
	Timeout time.Duration
}

type Result struct {
	OK      bool     `json:"ok"`
	Err     string   `json:"err,omitempty"`
	Echo    string   `json:"echo,omitempty"`
	Answers []string `json:"answers,omitempty"`
	MS      int64    `json:"ms"`
}

func network(base string, dst netip.Addr) string {
	if dst.Is4() {
		return base + "4"
	}
	return base + "6"
}

// Run выполняет пробу; ошибки становятся полем Err.
func Run(s Spec) Result {
	start := time.Now()
	r, err := run(s)
	r.MS = time.Since(start).Milliseconds()
	if err != nil {
		r.OK = false
		r.Err = shortErr(err)
	}
	return r
}

func shortErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Op + ": " + op.Err.Error()
	}
	return err.Error()
}

func run(s Spec) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	d := net.Dialer{Control: bindControl(s.Bind)}
	addr := netip.AddrPortFrom(s.Dst, s.Port).String()
	deadline, _ := ctx.Deadline()
	switch s.Kind {
	case HTTP:
		c, err := d.DialContext(ctx, network("tcp", s.Dst), addr)
		if err != nil {
			return Result{}, err
		}
		defer c.Close()
		c.SetDeadline(deadline)
		if _, err := fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", s.Dst); err != nil {
			return Result{}, err
		}
		body, err := io.ReadAll(c)
		if err != nil && len(body) == 0 {
			return Result{}, err
		}
		return echoResult(string(body))
	case UDP:
		c, err := d.DialContext(ctx, network("udp", s.Dst), addr)
		if err != nil {
			return Result{}, err
		}
		defer c.Close()
		c.SetDeadline(deadline)
		if _, err := c.Write([]byte("ksl-probe\n")); err != nil {
			return Result{}, err
		}
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			return Result{}, err
		}
		return echoResult(string(buf[:n]))
	case DNSUDP, DNSTCP:
		return dns(ctx, d, s, addr, deadline)
	}
	return Result{}, fmt.Errorf("неизвестный вид пробы %q", s.Kind)
}

func echoResult(body string) (Result, error) {
	i := strings.Index(body, "src=")
	if i < 0 {
		return Result{}, fmt.Errorf("ответ без src=: %q", trim(body))
	}
	return Result{OK: true, Echo: strings.TrimSpace(strings.SplitN(body[i+4:], "\n", 2)[0])}, nil
}

func trim(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

func dns(ctx context.Context, d net.Dialer, s Spec, addr string, deadline time.Time) (Result, error) {
	id := uint16(rand.N(65535) + 1)
	q, err := dnsmsg.Query(id, topo.DNSQueryName, dnsmsg.TypeA)
	if err != nil {
		return Result{}, err
	}
	var resp []byte
	if s.Kind == DNSUDP {
		c, err := d.DialContext(ctx, network("udp", s.Dst), addr)
		if err != nil {
			return Result{}, err
		}
		defer c.Close()
		c.SetDeadline(deadline)
		if _, err := c.Write(q); err != nil {
			return Result{}, err
		}
		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		if err != nil {
			return Result{}, err
		}
		resp = buf[:n]
	} else {
		c, err := d.DialContext(ctx, network("tcp", s.Dst), addr)
		if err != nil {
			return Result{}, err
		}
		defer c.Close()
		c.SetDeadline(deadline)
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			return Result{}, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return Result{}, err
		}
		resp = make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return Result{}, err
		}
	}
	addrs, err := dnsmsg.Addrs(resp, id)
	if err != nil {
		return Result{}, err
	}
	r := Result{}
	for _, a := range addrs {
		r.Answers = append(r.Answers, a.String())
	}
	if !slices.Contains(addrs, topo.DNSAnswerA) {
		return r, fmt.Errorf("в ответе нет %s: %v", topo.DNSAnswerA, r.Answers)
	}
	r.OK = true
	return r, nil
}
