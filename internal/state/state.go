// Package state — state.json (поколение, намерение, хеши) и общий системный замок команд.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// ErrCorrupt — state.json не читается; ядро действует fail-closed.
var ErrCorrupt = errors.New("state.json повреждён")

// Intent — намерение перехода: пишется до Apply, снимается фиксацией.
type Intent struct {
	Gen      uint64      `json:"gen"`
	Target   policy.Mode `json:"target"`
	PlanHash string      `json:"plan_hash"`
}

// State — содержимое state.json.
type State struct {
	Gen         uint64                  `json:"gen"`
	Mode        policy.Mode             `json:"mode"`
	BootID      string                  `json:"boot_id"`
	PlanHash    string                  `json:"plan_hash"`
	AppliedHash string                  `json:"applied_hash"`
	PFToken     string                  `json:"pf_token,omitempty"`
	AnchorOK    bool                    `json:"anchor_ok"`
	Intent      *Intent                 `json:"intent,omitempty"`
	LastKnown   map[string][]netip.Addr `json:"last_known,omitempty"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

// FileName — имя файла состояния в каталоге.
const FileName = "state.json"

// Load читает состояние: отсутствие — ошибка с fs.ErrNotExist, порча — ErrCorrupt.
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var s State
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return State{}, fmt.Errorf("%w: данные после JSON", ErrCorrupt)
	}
	if err := s.validate(); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return s, nil
}

// validate: режим обязателен, кроме первой установки (поколение 0 с намерением — сбой до первой фиксации).
func (s State) validate() error {
	firstInstall := s.Gen == 0 && s.Mode == "" && s.Intent != nil
	if _, err := policy.ParseMode(string(s.Mode)); err != nil && !firstInstall {
		return err
	}
	if s.Intent == nil {
		return nil
	}
	_, err := policy.ParseMode(string(s.Intent.Target))
	return err
}

// Save пишет атомарно: временный файл в том же каталоге, fsync, rename.
func Save(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, FileName+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(append(data, '\n'))
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Remove удаляет state.json; отсутствие — не ошибка.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
