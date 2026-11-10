//go:build !windows

package main

// isDesktop: запуск с рабочего стола не распознаётся — без аргументов как раньше (меню или справка).
func isDesktop() bool { return false }
