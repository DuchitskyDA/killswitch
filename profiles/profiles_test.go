package profiles_test

import (
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

// Отметку о проверке ставит только живая проверка (рев. 2 A15).
func TestEmbeddedProfilesUnverified(t *testing.T) {
	for name, p := range loadAll(t) {
		if len(p.VerifiedOn) != 0 {
			t.Errorf("%s: verified_on = %v, ожидалось пусто", name, p.VerifiedOn)
		}
	}
}

// Список repair — выбор пользователя: exe клиента в нём сломал бы саму починку.
func TestEmbeddedRepairProgramsEmpty(t *testing.T) {
	all := loadAll(t)
	for _, name := range clients {
		for _, goos := range oses {
			if sec, _ := all[name].Section(goos); len(sec.RepairPrograms) != 0 {
				t.Errorf("%s [%s]: repair_programs = %v, ожидалось пусто", name, goos, sec.RepairPrograms)
			}
		}
	}
}
