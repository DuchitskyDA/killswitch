//go:build !windows && !darwin

package main

import (
	"errors"

	"github.com/DuchitskyDA/killswitch/internal/health"
)

// systemBinder — живой CI для этой ОС не нужен (Linux проверяет лаборатория в netns).
func systemBinder() (health.Binder, error) {
	return nil, errors.New("привязка к интерфейсу на этой ОС не поддержана")
}
