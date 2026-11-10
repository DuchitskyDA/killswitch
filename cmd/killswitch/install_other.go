//go:build !windows

package main

// Установки в систему нет: macOS ставит копию сама при первом on, Linux — пакетом или вручную.
var (
	installSelf   func(enable func() error) error
	uninstallSelf func(removeRules func() error) error
	alert         func(msg string)
)
