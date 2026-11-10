package main

import (
	"github.com/DuchitskyDA/killswitch/internal/backend"
	wfp "github.com/DuchitskyDA/killswitch/internal/backend/windows"
)

// Запуск под SCM (служба killswitch, ImagePath `killswitch.exe enforce`): ответы SCM — в фоне, команда — как обычно.
func init() { wfp.ServeIfService() }

// newBackend подключает backend WFP.
func newBackend() (backend.Backend, error) { return wfp.New(), nil }
