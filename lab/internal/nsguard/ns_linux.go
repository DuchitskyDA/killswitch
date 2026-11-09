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

// RootMountIno — inode mount namespace процесса 1, то есть хоста.
func RootMountIno() (uint64, error) { return inoPath("/proc/1/ns/mnt") }

// MountNS — приватный mount namespace держателя лаборатории (tmpfs поверх IsolatedDirs).
// Как и NS, держится дескриптором: команды входят именно в него.
type MountNS struct {
	Ino uint64
	f   *os.File
}

// OpenMount открывает mount ns по пути (/proc/<pid>/ns/mnt) и отказывает, если это mount ns хоста или свой.
func OpenMount(path string) (*MountNS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	m := &MountNS{f: f}
	if m.Ino, err = inoFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if err := m.check(0); err != nil {
		f.Close()
		return nil, err
	}
	return m, nil
}

func (m *MountNS) check(expected uint64) error {
	root, err := RootMountIno()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	self, err := inoPath("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if err := CheckMountTarget(m.Ino, root, expected); err != nil {
		return err
	}
	return CheckMountTarget(m.Ino, self, expected)
}

// Verify сверяет inode дескриптора с записанным и с mount ns хоста.
func (m *MountNS) Verify() error {
	fi, err := inoFile(m.f)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if fi != m.Ino {
		return fmt.Errorf("%w: mount ns ждали %d, есть %d", ErrChanged, m.Ino, fi)
	}
	return m.check(m.Ino)
}

// Close закрывает дескриптор.
func (m *MountNS) Close() error { return m.f.Close() }

// CmdIn готовит команду внутри network ns n и mount ns m; перед этим сверяет оба.
func (n *NS) CmdIn(ctx context.Context, m *MountNS, argv ...string) (*exec.Cmd, error) {
	if err := n.Verify(); err != nil {
		return nil, fmt.Errorf("%s: %w", n.Name, err)
	}
	if err := m.Verify(); err != nil {
		return nil, err
	}
	args := append([]string{"--net=/proc/self/fd/3", "--mount=/proc/self/fd/4", "--"}, argv...)
	cmd := exec.CommandContext(ctx, "nsenter", args...)
	cmd.ExtraFiles = []*os.File{n.f, m.f}
	return cmd, nil
}

// SelfCheckMount — проверка изнутри: процесс не в mount ns хоста и в том, что ждали.
func SelfCheckMount(expected uint64) error {
	self, err := inoPath("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	root, err := RootMountIno()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if expected == 0 {
		return fmt.Errorf("%w: не передан --expect-mnt", ErrUnknown)
	}
	return CheckMountTarget(self, root, expected)
}

// IsTmpfs — каталог — точка tmpfs (statfs).
func IsTmpfs(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, err
	}
	return st.Type == unix.TMPFS_MAGIC, nil
}
