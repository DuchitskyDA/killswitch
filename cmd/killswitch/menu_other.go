//go:build !linux && !darwin && !windows

package main

// На прочих ОС backend нет: меню не открывается.
var elevateFunc func() error

func isAdmin() bool    { return false }
func isTerminal() bool { return false }
