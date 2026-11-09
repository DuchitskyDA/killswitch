package main

import (
	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/backend/darwin"
)

// newBackend подключает pf-backend macOS. Файл принадлежит тикету ks-darwin.
func newBackend() (backend.Backend, error) { return darwin.New(), nil }
