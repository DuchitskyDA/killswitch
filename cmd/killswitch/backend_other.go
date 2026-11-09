//go:build !linux && !darwin && !windows

package main

import "github.com/DuchitskyDA/killswitch/internal/backend"

// newBackend: ОС не поддерживается.
func newBackend() (backend.Backend, error) { return nil, backend.ErrNotImplemented }
