package windows

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
)

// Коды WFP «не найдено».
const (
	errFilterNotFound   = xwin.Errno(0x80320003)
	errProviderNotFound = xwin.Errno(0x80320005)
	errSublayerNotFound = xwin.Errno(0x80320007)
	errInUse            = xwin.Errno(0x80320006)
)

// Backend — WFP.
type Backend struct {
	mu   sync.Mutex
	evid evidenceState
}

var _ backend.Backend = (*Backend)(nil)

// New — backend WFP.
func New() *Backend { return &Backend{} }

// Capabilities — program + endpoints + repair.
func (b *Backend) Capabilities() policy.Capabilities { return policy.CapabilitiesFor("windows") }

// Plan — чистый план.
func (b *Backend) Plan(p policy.Policy, e env.Env) (backend.Ruleset, error) { return PlanRules(p, e) }

// Apply — одна транзакция: provider и sublayer (если их нет), удаление лишних наших фильтров, добавление плана.
// Ошибка — Abort: прежний набор остаётся (fail-closed).
func (b *Backend) Apply(rs backend.Ruleset) error {
	r, ok := rs.(Ruleset)
	if !ok {
		return fmt.Errorf("чужой план %T", rs)
	}
	s, err := openSession()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Begin(); err != nil {
		return fmt.Errorf("начать транзакцию WFP: %w", err)
	}
	if err := applyIn(s, r); err != nil {
		_ = s.Abort()
		return err
	}
	if err := s.Commit(); err != nil {
		return fmt.Errorf("зафиксировать транзакцию WFP: %w", err)
	}
	return nil
}

func applyIn(s *wf.Session, r Ruleset) error {
	if err := ensureOwners(s); err != nil {
		return err
	}
	have, err := ourRules(s)
	if err != nil {
		return err
	}
	want := map[wf.RuleID]Filter{}
	for _, f := range r.Filters {
		want[keyOf(f)] = f
	}
	keep := map[wf.RuleID]bool{}
	for _, h := range have {
		f, ok := want[h.ID]
		if ok && !h.Disabled && fromRule(h).Line() == f.Line() {
			keep[h.ID] = true
			continue
		}
		if err := s.DeleteRule(h.ID); err != nil && !errors.Is(err, errFilterNotFound) {
			return fmt.Errorf("удалить фильтр %s: %w", h.ID, err)
		}
	}
	for id, f := range want {
		if keep[id] {
			continue
		}
		if err := s.AddRule(toRule(f)); err != nil {
			return fmt.Errorf("добавить фильтр %q: %w", f.Line(), err)
		}
	}
	return nil
}

// ensureOwners создаёт наш provider и sublayer, если их нет; существующие не трогает.
func ensureOwners(s *wf.Session) error {
	provs, err := s.Providers()
	if err != nil {
		return fmt.Errorf("перечислить providers: %w", err)
	}
	if !hasProvider(provs) {
		p := &wf.Provider{ID: providerID, Name: "killswitch", Description: "killswitch: защита от утечек мимо туннеля", Persistent: true}
		if err := s.AddProvider(p); err != nil {
			return fmt.Errorf("создать provider: %w", err)
		}
	}
	subs, err := s.Sublayers()
	if err != nil {
		return fmt.Errorf("перечислить sublayers: %w", err)
	}
	for _, sl := range subs {
		if sl.ID == sublayerID {
			return nil
		}
	}
	sl := &wf.Sublayer{ID: sublayerID, Name: "killswitch", Description: "killswitch", Persistent: true,
		Provider: providerID, Weight: MaxWeight}
	if err := s.AddSublayer(sl); err != nil {
		return fmt.Errorf("создать sublayer: %w", err)
	}
	return nil
}

func hasProvider(provs []*wf.Provider) bool {
	for _, p := range provs {
		if p.ID == providerID {
			return true
		}
	}
	return false
}

// ourRules — наши фильтры на наших слоях, включая boot-time и выключенные.
func ourRules(s *wf.Session) ([]*wf.Rule, error) {
	pid := providerID
	var out []*wf.Rule
	for _, l := range Layers {
		rs, err := s.RulesOf(wf.RuleFilter{Provider: &pid, Layer: layerIDs[l], IncludeBootTime: true, IncludeDisabled: true})
		if err != nil {
			return nil, fmt.Errorf("перечислить фильтры %s: %w", l, err)
		}
		out = append(out, rs...)
	}
	return out, nil
}

// Remove — без конфига и сети: все фильтры нашего provider на всех слоях (с boot-time), sublayer, provider.
func (b *Backend) Remove() error {
	s, err := openSession()
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Begin(); err != nil {
		return fmt.Errorf("начать транзакцию WFP: %w", err)
	}
	if err := removeIn(s); err != nil {
		_ = s.Abort()
		return err
	}
	return s.Commit()
}

func removeIn(s *wf.Session) error {
	layers, err := s.Layers()
	if err != nil {
		return fmt.Errorf("перечислить слои: %w", err)
	}
	pid := providerID
	for _, l := range layers {
		rs, err := s.RulesOf(wf.RuleFilter{Provider: &pid, Layer: l.ID, IncludeBootTime: true, IncludeDisabled: true})
		if err != nil {
			if _, ours := layerOf(l.ID); ours {
				return fmt.Errorf("перечислить фильтры %s: %w", l.ID, err)
			}
			continue // слой без фильтров по шаблону; наши живут только на слоях ALE
		}
		if err := deleteRules(s, rs); err != nil {
			return err
		}
	}
	if err := deleteSublayer(s); err != nil {
		return err
	}
	if err := s.DeleteProvider(providerID); err != nil && !errors.Is(err, errProviderNotFound) {
		return fmt.Errorf("удалить provider: %w", err)
	}
	return nil
}

// deleteSublayer: если в нашем sublayer остались чужие фильтры, они удаляются тоже — иначе sublayer не снять.
func deleteSublayer(s *wf.Session) error {
	err := s.DeleteSublayer(sublayerID)
	if err == nil || errors.Is(err, errSublayerNotFound) {
		return nil
	}
	if !errors.Is(err, errInUse) {
		return fmt.Errorf("удалить sublayer: %w", err)
	}
	for _, l := range Layers {
		rs, err := s.RulesOf(wf.RuleFilter{Layer: layerIDs[l], IncludeBootTime: true, IncludeDisabled: true})
		if err != nil {
			return fmt.Errorf("перечислить фильтры %s: %w", l, err)
		}
		var inOurs []*wf.Rule
		for _, r := range rs {
			if r.Sublayer == sublayerID {
				inOurs = append(inOurs, r)
			}
		}
		if err := deleteRules(s, inOurs); err != nil {
			return err
		}
	}
	if err := s.DeleteSublayer(sublayerID); err != nil {
		return fmt.Errorf("удалить sublayer: %w", err)
	}
	return nil
}

func deleteRules(s *wf.Session, rs []*wf.Rule) error {
	for _, r := range rs {
		if err := s.DeleteRule(r.ID); err != nil && !errors.Is(err, errFilterNotFound) {
			return fmt.Errorf("удалить фильтр %s: %w", r.ID, err)
		}
	}
	return nil
}

// Status — факт: provider (Active), прочитанные обратно фильтры (Hash, Mode), структурные находки.
func (b *Backend) Status() (backend.Status, error) {
	s, err := openSession()
	if err != nil {
		return backend.Status{}, err
	}
	defer s.Close()
	provs, err := s.Providers()
	if err != nil {
		return backend.Status{}, fmt.Errorf("перечислить providers: %w", err)
	}
	if !hasProvider(provs) {
		return backend.Status{Details: "provider killswitch не установлен"}, nil
	}
	rules, err := ourRules(s)
	if err != nil {
		return backend.Status{}, err
	}
	filters := make([]Filter, len(rules))
	var structural []probe.StructuralFinding
	for i, r := range rules {
		filters[i] = fromRule(r)
		if r.Disabled {
			structural = append(structural, probe.StructuralFinding{Kind: "wfp-disabled", Repair: true,
				Detail: fmt.Sprintf("наш фильтр выключен: %s", filters[i].Line())})
		}
	}
	tie, details, err := tieCheck(s, filters)
	if err != nil {
		return backend.Status{}, err
	}
	st := backend.Status{Active: true, Mode: ModeOf(filters), Rules: len(filters), Hash: backend.HashOf(Ruleset{Filters: filters}),
		Structural: append(append(structural, MissingFindings(filters)...), tie...), Details: details}
	return st, nil
}

// tieCheck — ничья 0xFFFF и наличие sublayer.
func tieCheck(s *wf.Session, own []Filter) ([]probe.StructuralFinding, string, error) {
	subs, err := s.Sublayers()
	if err != nil {
		return nil, "", fmt.Errorf("перечислить sublayers: %w", err)
	}
	var infos []SublayerInfo
	found := false
	for _, sl := range subs {
		infos = append(infos, SublayerInfo{ID: sl.ID.String(), Name: sl.Name, Weight: sl.Weight})
		found = found || sl.ID == sublayerID
	}
	if !found {
		return []probe.StructuralFinding{{Kind: "wfp-sublayer-missing", Repair: true,
			Detail: "provider есть, sublayer killswitch нет: фильтры не действуют"}}, "sublayer нет", nil
	}
	var foreign []ForeignFilter
	var warns []string
	for _, l := range Layers {
		rs, err := s.RulesOf(wf.RuleFilter{Layer: layerIDs[l], IncludeDisabled: true})
		if err != nil {
			warns = append(warns, fmt.Sprintf("WARN чужие фильтры %s не прочитаны: %v", l, err))
			continue
		}
		for _, r := range rs {
			if r.Sublayer == sublayerID || r.Disabled {
				continue
			}
			f := fromRule(r)
			foreign = append(foreign, ForeignFilter{Sublayer: r.Sublayer.String(), Name: r.Name, Layer: l,
				Permit: r.Action == wf.ActionPermit, Hard: r.HardAction, Conds: f.Conds})
		}
	}
	details := fmt.Sprintf("sublayer killswitch 0x%X, sublayers всего %d", MaxWeight, len(infos))
	if len(warns) > 0 {
		details += "; " + strings.Join(warns, "; ")
	}
	return TieFindings(infos, sublayerID.String(), foreign, own), details, nil
}
