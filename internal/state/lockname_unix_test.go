//go:build unix

package state

import (
	"path/filepath"
	"testing"
)

func testLockName(t *testing.T) string { return filepath.Join(t.TempDir(), "state.lock") }
