package lab

import (
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/profile"
	"github.com/DuchitskyDA/killswitch/profiles"
)

// Ячейка: FAIL главнее всего, NOT_TESTED главнее PASS, проверка без семейства входит в v4 и v6, без проверок ячейки нет.
func TestSummarize(t *testing.T) {
	cells := Summarize([]Check{
		{Scenario: "1", Client: "wireguard", Family: "v4", Name: "tcp4", Status: Pass},
		{Scenario: "1", Client: "wireguard", Family: "v4", Name: "udp4", Status: Fail, Detail: "LEAK"},
		{Scenario: "1", Client: "wireguard", Family: "-", Name: "код on", Status: Pass},
		{Scenario: "3", Client: "wireguard", Family: "v6", Name: "lan", Status: Pass},
		{Scenario: "3", Client: "wireguard", Family: "v6", Name: "dns-tcp6", Status: NotTested, Detail: "без killswitch не прошла"},
		{Scenario: "3", Client: "wireguard", Family: "v6", Name: "http6", Status: Pass},
		{Scenario: "(в)", Client: "openvpn", Family: "-", Name: "нет на хосте", Status: NotTested},
	})
	got := map[string]Status{}
	for _, c := range cells {
		got[c.Scenario+" "+c.Client+" "+c.Family] = c.Status
	}
	want := map[string]Status{"1 wireguard v4": Fail, "1 wireguard v6": Pass, "3 wireguard v6": NotTested, "(в) openvpn v4": NotTested, "(в) openvpn v6": NotTested}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, ждали %s (все: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("ячеек %d, ждали %d: %v", len(got), len(want), got)
	}
}

// Таблица: причина FAIL попадает в примечания, отсутствующая ячейка — прочерк.
func TestRenderTable(t *testing.T) {
	out := RenderTable(Summarize([]Check{
		{Scenario: "9", Client: "xray", Family: "v6", Name: "check", Status: Fail, Detail: "код 5", Log: "xray/report.txt"},
	}))
	if !strings.Contains(out, "| 9 | — | FAIL |") || !strings.Contains(out, "9 xray v6 (FAIL): check: код 5") ||
		!strings.Contains(out, "- xray: xray/report.txt") {
		t.Errorf("таблица:\n%s", out)
	}
}

// Каждый вариант конфига приёмки проходит разбор, слияние с профилем и проверку политики linux.
func TestConfigsValidate(t *testing.T) {
	all, err := profile.Load(profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range Clients {
		for _, o := range []ConfigOpts{{}, {Strict: true}, {TunnelUpDNS: true}, {NoTargets: true}, {Strict: true, CgroupPath: "system.slice/x.scope/ksl-xray",
			ExtraEndpoints: []string{"203.0.113.130:443/udp", "[2001:db8:b::2]:443/udp", "203.0.113.130:53/tcp"}}} {
			cfg, err := policy.ParseConfig([]byte(c.Config(o)))
			if err != nil {
				t.Fatalf("%s %+v: %v", name, o, err)
			}
			var layer policy.Layer
			if c.Profile != "" {
				sec, _ := all[c.Profile].Section("linux")
				layer = sec.Layer()
			}
			p, err := policy.Build(layer, cfg)
			if err == nil {
				err = p.WithMode(policy.ModeOn).Validate(policy.CapabilitiesFor("linux"))
			}
			if err != nil {
				t.Errorf("%s %+v: %v\n%s", name, o, err, c.Config(o))
			}
		}
	}
}

// Интерфейсы приёмки совпадают с шаблоном туннеля (профиля или конфига) до и после переподключения.
func TestClientIfacesMatchPatterns(t *testing.T) {
	all, _ := profile.Load(profiles.FS)
	for name, c := range Clients {
		patterns := c.Patterns
		if patterns == nil {
			sec, _ := all[c.Profile].Section("linux")
			patterns = sec.Interfaces
		}
		for _, i := range c.Ifaces {
			if !slices.ContainsFunc(patterns, func(p string) bool { ok, _ := path.Match(p, i); return ok }) {
				t.Errorf("%s: %s не совпал с %v", name, i, patterns)
			}
		}
	}
}

// ExecStart разбирается как systemd: строка раннего юнита killswitch — sh -c с командой в кавычках.
func TestExecStart(t *testing.T) {
	unit := "[Service]\nType=oneshot\nExecStart=/bin/sh -c 'nft -f /var/lib/killswitch/on.nft || nft -f /var/lib/killswitch/fallback.nft'\n"
	argv, err := ExecStart(unit)
	want := []string{"/bin/sh", "-c", "nft -f /var/lib/killswitch/on.nft || nft -f /var/lib/killswitch/fallback.nft"}
	if err != nil || !slices.Equal(argv, want) {
		t.Errorf("ExecStart = %q, %v", argv, err)
	}
	if _, err := ExecStart("[Service]\nType=simple\n"); err == nil {
		t.Error("юнит без ExecStart: ждали ошибку")
	}
}

// StripTable убирает только свою таблицу, соседние остаются.
func TestStripTable(t *testing.T) {
	in := "table inet sing-box {\n\tchain a {\n\t}\n}\ntable inet killswitch {\n\tchain postrouting {\n\t}\n}\ntable ip nat {\n}\n"
	want := "table inet sing-box {\n\tchain a {\n\t}\n}\ntable ip nat {\n}\n"
	if got := StripTable(in, "inet killswitch"); got != want {
		t.Errorf("StripTable:\n%s\nждали:\n%s", got, want)
	}
}

// Строка «без default» видна в сводке, как и прочие сценарии.
func TestRenderTableNoDefaultRow(t *testing.T) {
	out := RenderTable(Summarize([]Check{
		{Scenario: ScenarioNoDefault, Client: "wireguard", Family: "-", Name: "check", Status: Fail, Detail: "код 5"},
	}))
	if !strings.Contains(out, "| "+ScenarioNoDefault+" |") || !strings.Contains(out, "(FAIL): check: код 5") {
		t.Errorf("таблица:\n%s", out)
	}
}

// (б) при перенаправлении клиента: check даёт 0 или 5 по правилам check, но не ложный LEAK.
func TestRedirectCheckOK(t *testing.T) {
	inconclusive := "INCONCLUSIVE c0 v4 http 203.0.113.130:80: цель не ответила через туннель: i/o timeout\nитог: INCONCLUSIVE\n"
	skipped := "SKIPPED c0 v4 http 203.0.113.130:80: перехвачено клиентом туннеля, через физический адаптер не ушло\n" +
		"BLOCKED c0 v4 udp-echo 203.0.113.130:443: отброшено нашим правилом\nитог: BLOCKED\n"
	leak := "LEAK c0 v4 http 203.0.113.130:80: сервер ответил мимо туннеля\nитог: LEAK\n"
	cases := []struct {
		out  string
		code int
		want bool
	}{{inconclusive, 5, true}, {skipped, 0, true}, {leak, 4, false}, {leak, 5, false}, {"ошибка запуска", 1, false}}
	for _, c := range cases {
		if got := RedirectCheckOK(c.out, c.code); got != c.want {
			t.Errorf("код %d, %q: %v, ждали %v", c.code, c.out, got, c.want)
		}
	}
}

// Без своих адресов check делает простую проверку: секции [check] в конфиге нет.
func TestConfigNoTargetsOmitsCheck(t *testing.T) {
	c := Clients["wireguard"]
	if cfg := c.Config(ConfigOpts{NoTargets: true}); strings.Contains(cfg, "[check]") {
		t.Errorf("в конфиге без целей осталась секция [check]:\n%s", cfg)
	}
	if cfg := c.Config(ConfigOpts{}); !strings.Contains(cfg, "[check]") {
		t.Errorf("в обычном конфиге нет секции [check]:\n%s", cfg)
	}
}
