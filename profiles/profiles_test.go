package profiles_test

import (
	"slices"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/profile"
	"github.com/DuchitskyDA/killswitch/profiles"
)

var clients = []string{"happ", "v2rayn", "sing-box", "hiddify", "wireguard", "amneziawg", "openvpn"}

func loadAll(t *testing.T) map[string]profile.Profile {
	t.Helper()
	all, err := profile.Load(profiles.FS)
	if err != nil {
		t.Fatalf("встроенные профили не грузятся: %v", err)
	}
	return all
}

var oses = []string{"windows", "linux", "darwin"}

// Встроены только клиенты: образец формата и фикстуры тестов в бинарник и в detect не попадают.
func TestEmbeddedAreClientsOnly(t *testing.T) {
	want := slices.Sorted(slices.Values(clients))
	if got := profile.Names(loadAll(t)); !slices.Equal(got, want) {
		t.Errorf("встроенные профили = %v, ожидались только клиенты %v", got, want)
	}
}

// Каждый клиент есть на всех трёх ОС: секции не должно пропасть.
func TestEmbeddedClientsCoverAllOS(t *testing.T) {
	all := loadAll(t)
	for _, name := range clients {
		for _, goos := range oses {
			if _, ok := all[name].Section(goos); !ok {
				t.Errorf("%s: нет секции [%s]", name, goos)
			}
		}
	}
}

// Каждая заданная секция даёт политику, которую принимает Validate своей ОС в режиме on.
func TestEmbeddedSectionsValidate(t *testing.T) {
	for name, p := range loadAll(t) {
		for _, goos := range oses {
			sec, ok := p.Section(goos)
			if !ok {
				continue
			}
			pol, err := policy.Build(sec.Layer(), policy.Config{})
			if err == nil {
				err = pol.WithMode(policy.ModeOn).Validate(policy.CapabilitiesFor(goos))
			}
			if err != nil {
				t.Errorf("%s [%s]: %v", name, goos, err)
			}
		}
	}
}

// verified — отметки живых прогонов с данными самого профиля: лаборатория Linux (lab/). CI Windows и macOS шёл
// со своими шаблонами адаптеров и доверием раннера, а не с профилями, — отметок не даёт.
var verified = map[string][]profile.Verification{
	"wireguard": {{OS: "linux", Backend: "nftables", ClientVersion: "linux 6.17 (модуль ядра)", Date: "2026-11-10"}},
	"sing-box":  {{OS: "linux", Backend: "nftables", ClientVersion: "1.14.4", Date: "2026-11-10"}},
}

// Отметку о проверке ставит только живая проверка; у остальных профилей — пусто.
func TestEmbeddedVerifiedOnlyByLiveRuns(t *testing.T) {
	for name, p := range loadAll(t) {
		if !slices.Equal(p.VerifiedOn, verified[name]) {
			t.Errorf("%s: verified_on = %v, ожидалось %v", name, p.VerifiedOn, verified[name])
		}
	}
}

// Список repair — выбор пользователя: exe клиента в нём сломал бы саму починку.
func TestEmbeddedRepairProgramsEmpty(t *testing.T) {
	for name, p := range loadAll(t) {
		for _, goos := range oses {
			if sec, _ := p.Section(goos); len(sec.RepairPrograms) != 0 {
				t.Errorf("%s [%s]: repair_programs = %v, ожидалось пусто", name, goos, sec.RepairPrograms)
			}
		}
	}
}
