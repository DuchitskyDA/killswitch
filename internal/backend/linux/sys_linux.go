//go:build linux

package linux

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
)

// BindControl — SO_BINDTODEVICE на имя интерфейса.
func (b *Backend) BindControl(iface env.Iface) backend.ControlFunc {
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if cerr := c.Control(func(fd uintptr) { err = unix.BindToDevice(int(fd), iface.Name) }); cerr != nil {
			return cerr
		}
		return err
	}
}

// Changes — события netlink (интерфейсы, адреса, маршруты v4/v6); пачка событий склеивается в один сигнал.
// Сокет не открылся — nil: enforce остаётся на пересчёте раз в 60 с.
func (b *Backend) Changes() <-chan struct{} {
	b.watchOnce.Do(func() { b.changes = watchNetlink() })
	return b.changes
}

func watchNetlink() chan struct{} {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil
	}
	ch := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			// ENOBUFS (переполнение очереди) — тоже повод пересчитать; прочие ошибки — пауза, без холостого цикла.
			if _, _, err := unix.Recvfrom(fd, buf, 0); err != nil && err != unix.ENOBUFS && err != unix.EINTR {
				time.Sleep(time.Second)
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch
}
