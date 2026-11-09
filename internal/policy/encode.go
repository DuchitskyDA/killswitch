package policy

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
)

// Encode записывает конфиг в TOML так, что ParseConfig(Encode(c)) даёт тот же Config.
// nil-поле (ключа нет) не пишется; пустой список пишется как [] — он заменяет список профиля.
func Encode(c Config) ([]byte, error) {
	out := encodedConfig{Profile: c.Profile, LAN: c.LAN, TrustMode: c.TrustMode, Tunnel: tableOrNil(c.Tunnel),
		DNS: tableOrNil(c.DNS), Repair: tableOrNil(c.Repair), Check: tableOrNil(c.Check)}
	if c.Trust != nil {
		trust := make([]encodedTrust, 0, len(*c.Trust))
		for _, t := range *c.Trust {
			trust = append(trust, encodedTrust(t))
		}
		out.Trust = &trust
	}
	var b bytes.Buffer
	enc := toml.NewEncoder(&b)
	enc.Indent = ""
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("запись конфига: %w", err)
	}
	return b.Bytes(), nil
}

// encodedConfig — Config для записи: таблицы без ключей и пустые profile/destinations не пишутся
// (ParseConfig вернёт для них те же нулевые значения).
type encodedConfig struct {
	Profile   string          `toml:"profile,omitempty"`
	LAN       *bool           `toml:"lan"`
	TrustMode *string         `toml:"trust_mode"`
	Tunnel    *configTunnel   `toml:"tunnel"`
	Trust     *[]encodedTrust `toml:"trust"`
	DNS       *configDNS      `toml:"dns"`
	Repair    *configRepair   `toml:"repair"`
	Check     *configCheck    `toml:"check"`
}

type encodedTrust struct {
	Kind         string `toml:"kind"`
	Value        string `toml:"value"`
	Destinations string `toml:"destinations,omitempty"`
}

// tableOrNil — nil для таблицы без ключей.
func tableOrNil[T comparable](t T) *T {
	var zero T
	if t == zero {
		return nil
	}
	return &t
}

// TrustEntries — исключения [[trust]] конфига; false — ключа нет (действуют исключения профиля).
// Destinations может быть пустым: Build выберет его по trust_mode.
func (c Config) TrustEntries() ([]Trust, bool) {
	if c.Trust == nil {
		return nil, false
	}
	return toTrust(*c.Trust), true
}

// SetTrust задаёт [[trust]] конфига целиком; nil убирает ключ (действуют исключения профиля).
func (c *Config) SetTrust(t []Trust) {
	if t == nil {
		c.Trust = nil
		return
	}
	out := make([]trustTOML, 0, len(t))
	for _, x := range t {
		out = append(out, trustTOML{Kind: string(x.Kind), Value: x.Value, Destinations: string(x.Destinations)})
	}
	c.Trust = &out
}
