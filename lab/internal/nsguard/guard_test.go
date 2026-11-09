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
