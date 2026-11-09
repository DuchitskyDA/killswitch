// Команда killswitch — универсальный киллсвитч: одна политика, backend ОС (WFP, nftables, pf).
package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/health"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/state"
	"github.com/DuchitskyDA/killswitch/profiles"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], systemDeps())
	stop()
	os.Exit(code)
}

func systemDeps() deps {
	return deps{
		goos:     runtime.GOOS,
		dir:      state.DefaultDir(runtime.GOOS),
		backend:  newBackend,
		lock:     systemLock,
		now:      time.Now,
		out:      os.Stdout,
		err:      os.Stderr,
		profiles: profiles.FS,
		glob:     filepath.Glob,
		prober: func(b backend.Backend) probe.Prober {
			return probe.NetProber{Bind: health.Binder(b.BindControl), Timeout: health.Timeout}
		},
		in:       os.Stdin,
		terminal: isTerminal,
		admin:    isAdmin,
		elevate:  elevateFunc,
	}
}

// systemLock — общий системный замок; ждёт, пока другая команда закончит.
func systemLock(dir string) (func(), error) {
	l, err := state.Acquire(state.LockName(dir), true)
	if err != nil {
		return nil, err
	}
	return func() { _ = l.Release() }, nil
}
