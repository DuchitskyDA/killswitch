package main

import "github.com/DuchitskyDA/killswitch/internal/backend"

// newBackend подключает backend ОС. Файл принадлежит backend-тикету этой ОС.
func newBackend() (backend.Backend, error) { return nil, backend.ErrNotImplemented }
