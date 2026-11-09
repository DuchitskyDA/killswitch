//go:build linux

package nsguard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// NS — открытый network namespace лаборатории. Дескриптор держится всё время работы:
// команды получают именно его, а не путь, поэтому подмена пути после сверки не сработает.
type NS struct {
	Name string
	Path string
	Ino  uint64
	f    *os.File
}

func inoPath(p string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func inoFile(f *os.File) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// RootIno — inode network namespace процесса 1, то есть хоста.
func RootIno() (uint64, error) { return inoPath("/proc/1/ns/net") }

// Create создаёт новый namespace с именем лаборатории; существующий не переиспользуется.
func Create(ctx context.Context, name string) (*NS, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	path := filepath.Join(RunDir, name)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%s уже существует — сначала kslab cleanup", path)
	}
	if out, err := exec.CommandContext(ctx, "ip", "netns", "add", name).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip netns add %s: %v: %s", name, err, out)
	}
	return Open(name)
}

// Open открывает namespace лаборатории по имени.
func Open(name string) (*NS, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	n, err := OpenPath(filepath.Join(RunDir, name), 0)
	if err != nil {
		return nil, err
	}
	n.Name = name
	return n, nil
}

// OpenPath открывает namespace по пути и отказывает, если это корневой.
func OpenPath(path string, expected uint64) (*NS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ino, err := inoFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	root, err := RootIno()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if err := CheckTarget(ino, root, expected); err != nil {
		f.Close()
		return nil, err
	}
	return &NS{Name: filepath.Base(path), Path: path, Ino: ino, f: f}, nil
}

// Verify сверяет inode дескриптора и пути с записанным и с корневым.
func (n *NS) Verify() error {
	root, err := RootIno()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	fi, err := inoFile(n.f)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if err := CheckTarget(fi, root, n.Ino); err != nil {
		return err
	}
	pi, err := inoPath(n.Path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnknown, n.Path, err)
	}
	return CheckTarget(pi, root, n.Ino)
}

// FDPath — путь, по которому команда видит i-й namespace из extra.
func FDPath(i int) string { return fmt.Sprintf("/proc/self/fd/%d", 4+i) }

// Cmd готовит команду внутри n; перед этим сверяет n и все extra.
func (n *NS) Cmd(ctx context.Context, extra []*NS, argv ...string) (*exec.Cmd, error) {
	for _, x := range append([]*NS{n}, extra...) {
		if err := x.Verify(); err != nil {
			return nil, fmt.Errorf("%s: %w", x.Name, err)
		}
	}
	args := append([]string{"--net=/proc/self/fd/3", "--"}, argv...)
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.ExtraFiles = []*os.File{n.f}
	for _, x := range extra {
		cmd.ExtraFiles = append(cmd.ExtraFiles, x.f)
	}
	return cmd, nil
}

// Run выполняет команду внутри n и возвращает её вывод.
func (n *NS) Run(ctx context.Context, argv ...string) (string, error) {
	return n.RunWith(ctx, nil, "", argv...)
}

// RunWith — Run с дополнительными namespace и stdin.
func (n *NS) RunWith(ctx context.Context, extra []*NS, stdin string, argv ...string) (string, error) {
	cmd, err := n.Cmd(ctx, extra, argv...)
	if err != nil {
		return "", err
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %s: %w: %s", n.Name, strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Close закрывает дескриптор.
func (n *NS) Close() error { return n.f.Close() }

// Delete удаляет namespace лаборатории после сверки.
func (n *NS) Delete(ctx context.Context) error {
	if err := CheckName(n.Name); err != nil {
		return err
	}
	if err := n.Verify(); err != nil {
		return err
	}
	n.f.Close()
	if out, err := exec.CommandContext(ctx, "ip", "netns", "del", n.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns del %s: %v: %s", n.Name, err, out)
	}
	return nil
}

// SelfCheck — проверка изнутри: процесс не в корневом namespace и в том, что ждали.
func SelfCheck(expected uint64) error {
	self, err := inoPath("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	root, err := RootIno()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if expected == 0 {
		return fmt.Errorf("%w: не передан --expect-ino", ErrUnknown)
	}
	return CheckTarget(self, root, expected)
}
