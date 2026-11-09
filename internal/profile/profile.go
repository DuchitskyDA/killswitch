// Package profile — профили клиентов (данные): интерфейсы, исключения, repair, detect, verified_on.
package profile

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Verification — живая проверка профиля: ОС, backend, версия клиента, дата "ГГГГ-ММ-ДД".
type Verification struct {
	OS            string `toml:"os"`
	Backend       string `toml:"backend"`
	ClientVersion string `toml:"client_version"`
	Date          string `toml:"date"`
}

// Section — данные профиля для одной ОС. Programs — только windows; Users — linux и darwin;
// Cgroups, Marks — только linux; RepairPrograms — только windows (проверка — policy.Validate).
type Section struct {
	Interfaces     []string `toml:"interfaces"`
	Programs       []string `toml:"programs"`
	Users          []string `toml:"users"`
	Cgroups        []string `toml:"cgroups"`
	Marks          []string `toml:"marks"`
	RepairPrograms []string `toml:"repair_programs"`
	Detect         []string `toml:"detect"` // glob путей: найден любой — клиент установлен
}

// Profile — профиль клиента profiles/<имя>.toml.
type Profile struct {
	Name        string         `toml:"name"`
	Description string         `toml:"description"`
	VerifiedOn  []Verification `toml:"verified_on"`
	Windows     *Section       `toml:"windows"`
	Darwin      *Section       `toml:"darwin"`
	Linux       *Section       `toml:"linux"`
}

// Parse разбирает профиль; name — имя файла без .toml, должно совпасть с полем name.
func Parse(name string, data []byte) (Profile, error) {
	var p Profile
	md, err := toml.Decode(string(data), &p)
	if err != nil {
		return Profile{}, fmt.Errorf("профиль %s: %w", name, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return Profile{}, fmt.Errorf("профиль %s: неизвестные ключи %v", name, und)
	}
	return p, p.validate(name)
}

func (p Profile) validate(name string) error {
	var errs []error
	if p.Name != name {
		errs = append(errs, fmt.Errorf("профиль %s: name = %q не совпадает с именем файла", name, p.Name))
	}
	for _, v := range p.VerifiedOn {
		if _, err := time.Parse(time.DateOnly, v.Date); err != nil || v.OS == "" || v.Backend == "" || v.ClientVersion == "" {
			errs = append(errs, fmt.Errorf("профиль %s: verified_on %+v: нужны os, backend, client_version, date ГГГГ-ММ-ДД", name, v))
		}
	}
	return errors.Join(errs...)
}

// Load читает все *.toml из корня fsys.
func Load(fsys fs.FS) (map[string]Profile, error) {
	files, err := fs.Glob(fsys, "*.toml")
	if err != nil {
		return nil, err
	}
	out := make(map[string]Profile, len(files))
	var errs []error
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p, err := Parse(strings.TrimSuffix(path.Base(f), ".toml"), data)
		errs = append(errs, err)
		out[p.Name] = p
	}
	return out, errors.Join(errs...)
}

// Names — имена профилей по алфавиту.
func Names(m map[string]Profile) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Section — секция для ОС goos.
func (p Profile) Section(goos string) (Section, bool) {
	var s *Section
	switch goos {
	case "windows":
		s = p.Windows
	case "darwin":
		s = p.Darwin
	case "linux":
		s = p.Linux
	}
	if s == nil {
		return Section{}, false
	}
	return *s, true
}

// Layer — вклад секции в политику. Destinations пусты: Build выберет их по trust_mode.
func (s Section) Layer() policy.Layer {
	var trust []policy.Trust
	add := func(kind policy.TrustKind, values []string) {
		for _, v := range values {
			trust = append(trust, policy.Trust{Kind: kind, Value: v})
		}
	}
	add(policy.KindProgram, s.Programs)
	add(policy.KindUser, s.Users)
	add(policy.KindCgroup, s.Cgroups)
	add(policy.KindMark, s.Marks)
	return policy.Layer{Interfaces: s.Interfaces, RepairPrograms: s.RepairPrograms, Trust: trust}
}
