// Package profiles — встроенные профили клиентов (*.toml), формат — internal/profile.
package profiles

import "embed"

// FS — встроенные профили.
//
//go:embed *.toml
var FS embed.FS
