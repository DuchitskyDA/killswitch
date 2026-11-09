package main

import (
	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/backend/linux"
)

// newBackend подключает backend nftables. Файл принадлежит тикету ks-linux.
func newBackend() (backend.Backend, error) { return linux.New(), nil }
