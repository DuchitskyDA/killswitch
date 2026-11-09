//go:build linux

package lab

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DuchitskyDA/killswitch/lab/internal/nsguard"
)

// Cleanup идемпотентно убирает следы лаборатории: процессы внутри ns ksl-* и сами ns.
// Гасит только процессы, чей network namespace — namespace лаборатории; по имени программ не гасит.
func Cleanup(out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	entries, err := os.ReadDir(nsguard.RunDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	found := 0
	for _, e := range entries {
		name := e.Name()
		if nsguard.CheckName(name) != nil {
			continue
		}
		found++
		n, err := nsguard.Open(name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		pids, _ := exec.CommandContext(ctx, "ip", "netns", "pids", name).Output()
		for _, f := range strings.Fields(string(pids)) {
			pid, err := strconv.Atoi(f)
			if err != nil || pid <= 1 {
				continue
			}
			var st syscall.Stat_t
			if syscall.Stat(fmt.Sprintf("/proc/%d/ns/net", pid), &st) != nil || st.Ino != n.Ino {
				continue
			}
			syscall.Kill(pid, syscall.SIGKILL)
			fmt.Fprintf(out, "cleanup: %s: остановлен pid %d\n", name, pid)
		}
		if err := n.Delete(ctx); err != nil {
			return err
		}
		fmt.Fprintf(out, "cleanup: ns %s удалён\n", name)
	}
	fmt.Fprintf(out, "cleanup: ns лаборатории найдено %d, осталось %d\n", found, countLabNS())
	return nil
}

func countLabNS() int {
	entries, _ := os.ReadDir(nsguard.RunDir)
	c := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), nsguard.Prefix) {
			c++
		}
	}
	return c
}
