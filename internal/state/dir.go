package state

import (
	"os"
	"path/filepath"
)

// DefaultDir — каталог администратора для state.json и config.toml.
func DefaultDir(goos string) string {
	switch goos {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "killswitch")
	case "darwin":
		return "/Library/Application Support/killswitch"
	}
	return "/var/lib/killswitch"
}
