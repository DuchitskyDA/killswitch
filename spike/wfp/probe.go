package main

// Пробы запускаются отдельными процессами из копий exe в probe-allowed\
// и probe-denied\: app-id WFP зависит от пути файла.

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const probeTimeout = 4 * time.Second

// runProbe — точка входа `probe <kind> <addr>`; код выхода 0 — успех.
func runProbe(args []string) int {
	if len(args) < 2 {
		fmt.Println("PROBE fail usage: probe http|dns|listen|connect|hold|holdudp <addr>")
		return 2
	}
	kind, addr := args[0], args[1]
	var err error
	switch kind {
	case "http":
		err = probeHTTP(addr)
	case "dns":
		err = probeDNS(addr)
	case "listen":
		err = probeListen(addr)
	case "connect":
		err = probeConnect(addr)
	case "hold":
		return probeHold(addr)
	case "holdudp":
		return probeHoldUDP(addr)
	default:
		err = fmt.Errorf("неизвестная проба %q", kind)
	}
	if err != nil {
		fmt.Printf("PROBE fail %v\n", err)
		return 1
	}
	fmt.Println("PROBE ok")
	return 0
}

func httpRequest(c net.Conn, host string) error {
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: ks-spike\r\nConnection: keep-alive\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return err
	}
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return fmt.Errorf("не HTTP: %q", line)
	}
	// Дочитать заголовки и тело по Content-Length, чтобы keep-alive был чистым.
	n, chunked := 0, false
	for {
		h, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if h == "\r\n" {
			break
		}
		lh := strings.ToLower(h)
		if strings.HasPrefix(lh, "content-length:") {
			fmt.Sscanf(strings.TrimSpace(h[len("content-length:"):]), "%d", &n)
		}
		if strings.HasPrefix(lh, "transfer-encoding:") && strings.Contains(lh, "chunked") {
			chunked = true
		}
	}
	if chunked {
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if l == "0\r\n" {
				_, err = r.ReadString('\n')
				return err
			}
		}
	}
	buf := make([]byte, n)
	_, err = ioReadFull(r, buf)
	return err
}

func ioReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// probeHTTP — успех только по ответу сервера (TUN-стек сам отвечает на SYN).
func probeHTTP(addr string) error {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	host, _, _ := net.SplitHostPort(addr)
	return httpRequest(c, host)
}

func dnsQuery(id uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:], id)
	binary.BigEndian.PutUint16(q[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split("example.com", ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func dnsExchange(c net.Conn) error {
	var b [2]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint16(b[:])
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := c.Write(dnsQuery(id)); err != nil {
		return err
	}
	resp := make([]byte, 512)
	n, err := c.Read(resp)
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(resp) != id {
		return errors.New("неверный ответ DNS")
	}
	return nil
}

func probeDNS(addr string) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	return dnsExchange(c)
}

// probeListen принимает одно соединение и отвечает "pong".
func probeListen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("LISTENING")
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * probeTimeout))
	c, err := ln.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("pong"))
	return err
}

func probeConnect(addr string) error {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	b := make([]byte, 4)
	if _, err := c.Read(b); err != nil {
		return err
	}
	if string(b) != "pong" {
		return fmt.Errorf("ответ %q", b)
	}
	return nil
}

// probeHold держит одно TCP-соединение и делает HTTP-запрос по каждой
// строке "next" со stdin: проверка уже открытых потоков.
func probeHold(addr string) int {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		fmt.Printf("HOLD dial fail %v\n", err)
		return 1
	}
	defer c.Close()
	fmt.Printf("HOLD local=%s remote=%s\n", c.LocalAddr(), c.RemoteAddr())
	host, _, _ := net.SplitHostPort(addr)
	return holdLoop(func() error { return httpRequest(c, host) })
}

func probeHoldUDP(addr string) int {
	c, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Printf("HOLD dial fail %v\n", err)
		return 1
	}
	defer c.Close()
	fmt.Printf("HOLD local=%s remote=%s\n", c.LocalAddr(), c.RemoteAddr())
	return holdLoop(func() error { return dnsExchange(c) })
}

func holdLoop(req func() error) int {
	report := func(i int) {
		if err := req(); err != nil {
			fmt.Printf("REQ%d fail %v\n", i, err)
		} else {
			fmt.Printf("REQ%d ok\n", i)
		}
	}
	report(1)
	sc := bufio.NewScanner(os.Stdin)
	for i := 2; sc.Scan(); i++ {
		if sc.Text() != "next" {
			return 0
		}
		report(i)
	}
	return 0
}
