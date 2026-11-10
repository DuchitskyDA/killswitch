package main

import (
	"os"
	"path/filepath"
	"strings"
)

// launchedFromDesktop — программу открыли из Finder: исполняемый файл лежит в *.app/Contents/MacOS/,
// а stdin не терминал (запуск того же файла из терминала — обычный CLI).
func launchedFromDesktop() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return inAppBundle(exe) && !isTTY(os.Stdin)
}

// inAppBundle — путь вида <…>.app/Contents/MacOS/<файл>.
func inAppBundle(exe string) bool {
	macOS := filepath.Dir(exe)
	contents := filepath.Dir(macOS)
	return filepath.Base(macOS) == "MacOS" && filepath.Base(contents) == "Contents" &&
		strings.HasSuffix(filepath.Dir(contents), ".app")
}
