package main

import (
	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/backend/darwin"
)

// newBackend подключает pf-backend macOS.
func newBackend() (backend.Backend, error) { return darwin.New(), nil }
