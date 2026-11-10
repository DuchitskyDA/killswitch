package window

import "github.com/DuchitskyDA/killswitch/internal/policy"

// configJSON — настройки для окна: те же ключи, что в config.toml. null — ключа в файле нет
// (действует значение профиля или умолчание), пустой список — ключ есть и заменяет список профиля.
type configJSON struct {
	Profile   string       `json:"profile"`
	LAN       *bool        `json:"lan"`
	TrustMode *string      `json:"trust_mode"`
	Tunnel    tunnelConfig `json:"tunnel"`
	Trust     *[]trustJSON `json:"trust"`
	DNS       dnsConfig    `json:"dns"`
	Repair    repairConfig `json:"repair"`
	Check     checkConfig  `json:"check"`
}

type tunnelConfig struct {
	Interfaces *[]string `json:"interfaces"`
	Endpoints  *[]string `json:"endpoints"`
}

type trustJSON struct {
	Kind         string `json:"kind"`
	Value        string `json:"value"`
	Destinations string `json:"destinations"` // пусто — по trust_mode
}

type dnsConfig struct {
	Mode      *string   `json:"mode"`
	Resolvers *[]string `json:"resolvers"`
	Health    *string   `json:"health"`
}

type repairConfig struct {
	Programs *[]string `json:"programs"`
	Names    *[]string `json:"names"`
}

type checkConfig struct {
	Targets *[]string `json:"targets"`
}

func configToJSON(c policy.Config) configJSON {
	out := configJSON{Profile: c.Profile, LAN: c.LAN, TrustMode: c.TrustMode,
		Tunnel: tunnelConfig{Interfaces: key(c.Tunnel.Interfaces), Endpoints: key(c.Tunnel.Endpoints)},
		DNS:    dnsConfig{Mode: c.DNS.Mode, Resolvers: key(c.DNS.Resolvers), Health: c.DNS.Health},
		Repair: repairConfig{Programs: key(c.Repair.Programs), Names: key(c.Repair.Names)},
		Check:  checkConfig{Targets: key(c.Check.Targets)}}
	if trust, ok := c.TrustEntries(); ok {
		t := trustToJSON(trust)
		out.Trust = &t
	}
	return out
}

// config — настройки из окна; проверяет их Save тем же путём, что команда on.
func (j configJSON) config() policy.Config {
	c := policy.Config{Profile: j.Profile, LAN: j.LAN, TrustMode: j.TrustMode}
	c.Tunnel.Interfaces, c.Tunnel.Endpoints = j.Tunnel.Interfaces, j.Tunnel.Endpoints
	c.DNS.Mode, c.DNS.Resolvers, c.DNS.Health = j.DNS.Mode, j.DNS.Resolvers, j.DNS.Health
	c.Repair.Programs, c.Repair.Names = j.Repair.Programs, j.Repair.Names
	c.Check.Targets = j.Check.Targets
	if j.Trust != nil {
		trust := make([]policy.Trust, 0, len(*j.Trust))
		for _, t := range *j.Trust {
			trust = append(trust, policy.Trust{Kind: policy.TrustKind(t.Kind), Value: t.Value, Destinations: policy.Destinations(t.Destinations)})
		}
		c.SetTrust(trust)
	}
	return c
}

func trustToJSON(in []policy.Trust) []trustJSON {
	out := make([]trustJSON, 0, len(in))
	for _, t := range in {
		out = append(out, trustJSON{Kind: string(t.Kind), Value: t.Value, Destinations: string(t.Destinations)})
	}
	return out
}

// key — список ключа для JSON: ключ есть — список (пустой — []), ключа нет — null.
func key(p *[]string) *[]string {
	if p == nil {
		return nil
	}
	l := list(*p)
	return &l
}
