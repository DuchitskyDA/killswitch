package main

import (
	"github.com/DuchitskyDA/killswitch/internal/backend/windows"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
)

// systemBinder — IP_UNICAST_IF / IPV6_UNICAST_IF, как у check (WFP не открывается).
func systemBinder() (health.Binder, error) {
	b := windows.New()
	return func(i env.Iface) health.ControlFunc { return health.ControlFunc(b.BindControl(i)) }, nil
}
