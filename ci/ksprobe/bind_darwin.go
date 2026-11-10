package main

import (
	"github.com/DuchitskyDA/killswitch/internal/backend/darwin"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
)

// systemBinder — IP_BOUND_IF / IPV6_BOUND_IF, как у check (pfctl не вызывается).
func systemBinder() (health.Binder, error) {
	b := darwin.New()
	return func(i env.Iface) health.ControlFunc { return health.ControlFunc(b.BindControl(i)) }, nil
}
