package nsguard

import (
	"errors"
	"testing"
)

func TestCheckTarget(t *testing.T) {
	cases := []struct {
		name                   string
		target, root, expected uint64
		want                   error
	}{
		{"чужой ns", 4026532153, 4026531833, 0, nil},
		{"совпал с записанным", 4026532153, 4026531833, 4026532153, nil},
		{"корневой", 4026531833, 4026531833, 0, ErrRootNS},
		{"корневой даже если записан", 4026531833, 4026531833, 4026531833, ErrRootNS},
		{"подменён", 4026532212, 4026531833, 4026532153, ErrChanged},
		{"нет inode цели", 0, 4026531833, 0, ErrUnknown},
		{"нет inode корня", 4026532153, 0, 0, ErrUnknown},
	}
	for _, c := range cases {
		err := CheckTarget(c.target, c.root, c.expected)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: CheckTarget(%d,%d,%d) = %v, ждали %v", c.name, c.target, c.root, c.expected, err, c.want)
		}
		if c.want != nil && !IsGuard(err) {
			t.Errorf("%s: IsGuard(%v) = false", c.name, err)
		}
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"ksl-client", "ksl-wan", "ksl-t0"} {
		if err := CheckName(ok); err != nil {
			t.Errorf("CheckName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ksl-", "client", "ksl-../x", "ksl-A", "default", "ksl-very-long-name-x"} {
		if err := CheckName(bad); !errors.Is(err, ErrName) {
			t.Errorf("CheckName(%q) = %v, ждали ErrName", bad, err)
		}
	}
}

func TestCheckMountTarget(t *testing.T) {
	if err := CheckMountTarget(4026531841, 4026531841, 0); !errors.Is(err, ErrRootMnt) || !IsGuard(err) {
		t.Errorf("mount ns хоста: %v, ждали ErrRootMnt", err)
	}
	if err := CheckMountTarget(4026532400, 4026531841, 4026532401); !errors.Is(err, ErrChanged) {
		t.Errorf("подменённый mount ns: %v, ждали ErrChanged", err)
	}
	if err := CheckMountTarget(4026532400, 4026531841, 4026532400); err != nil {
		t.Errorf("свой mount ns: %v", err)
	}
}

func TestCheckIsolation(t *testing.T) {
	tmpfs := func(except string) func(string) (bool, error) {
		return func(d string) (bool, error) { return d != except, nil }
	}
	stub := func(string) (string, error) { return "/opt/killswitch-lab/stub/systemctl", nil }
	real := func(string) (string, error) { return "/usr/bin/systemctl", nil }
	if err := CheckIsolation(tmpfs(""), stub, "/opt/killswitch-lab/stub"); err != nil {
		t.Errorf("полная изоляция: %v", err)
	}
	for _, d := range []string{"/var/lib", "/run", "/etc/systemd/system"} {
		if err := CheckIsolation(tmpfs(d), stub, "/opt/killswitch-lab/stub"); !errors.Is(err, ErrIsolation) {
			t.Errorf("%s не tmpfs: %v, ждали ErrIsolation", d, err)
		}
	}
	if err := CheckIsolation(tmpfs(""), real, "/opt/killswitch-lab/stub"); !errors.Is(err, ErrIsolation) || !IsGuard(err) {
		t.Errorf("настоящий systemctl: %v, ждали ErrIsolation", err)
	}
}

// ksexec не пускает killswitch, если отказала любая из трёх проверок.
func TestCheckExec(t *testing.T) {
	ok := func(uint64) error { return nil }
	deny := func(uint64) error { return ErrRootMnt }
	good := Exec{Stub: "/s", SelfNet: ok, SelfMnt: ok,
		IsTmpfs: func(string) (bool, error) { return true, nil }, LookPath: func(string) (string, error) { return "/s/systemctl", nil }}
	if err := CheckExec(good); err != nil {
		t.Errorf("все проверки прошли: %v", err)
	}
	net, mnt, iso := good, good, good
	net.SelfNet, mnt.SelfMnt = deny, deny
	iso.IsTmpfs = func(string) (bool, error) { return false, nil }
	for name, e := range map[string]Exec{"net ns": net, "mount ns": mnt, "tmpfs": iso} {
		if err := CheckExec(e); !IsGuard(err) {
			t.Errorf("отказ %s пропущен: %v", name, err)
		}
	}
}
