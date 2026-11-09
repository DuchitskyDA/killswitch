package windows

import (
	"fmt"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
)

// Ожидание события: BFE пишет события отброса с задержкой.
const (
	evidenceWait = 3 * time.Second
	evidenceStep = 250 * time.Millisecond
)

// evidenceState — включали ли мы сбор событий сами (тогда выключаем после пробы).
type evidenceState struct {
	enabledByUs bool
}

var _ probe.Preparer = (*Backend)(nil)

// BeforeProbe включает сбор событий отброса на время пробы.
func (b *Backend) BeforeProbe(probe.ProbeID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := openSession()
	if err != nil {
		return err
	}
	defer s.Close()
	on, err := s.CollectNetEvents()
	if err != nil {
		return fmt.Errorf("опция сбора событий WFP: %w", err)
	}
	if on {
		return nil
	}
	if err := s.SetCollectNetEvents(true); err != nil {
		return fmt.Errorf("включить сбор событий WFP: %w", err)
	}
	b.evid.enabledByUs = true
	return nil
}

// Evidence — событие отброса пробы id нашим block-фильтром после since.
func (b *Backend) Evidence(id probe.ProbeID, since time.Time) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := openSession()
	if err != nil {
		return false, err
	}
	defer s.Close()
	defer b.restoreCollection(s)
	ours, err := ourBlockIDs(s)
	if err != nil {
		return false, err
	}
	deadline := time.Now().Add(evidenceWait)
	for {
		events, err := s.DropEventsSince(since.Add(-clockSlack), time.Now().Add(clockSlack))
		if err != nil {
			return false, fmt.Errorf("события отброса WFP: %w", err)
		}
		for _, ev := range events {
			d := Drop{At: ev.Timestamp, Proto: ev.IPProtocol, Local: ev.LocalAddr, Remote: ev.RemoteAddr, FilterID: ev.FilterID}
			if MatchDrop(d, id, since, ours) {
				return true, nil
			}
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(evidenceStep)
	}
}

func (b *Backend) restoreCollection(s *wf.Session) {
	if b.evid.enabledByUs {
		_ = s.SetCollectNetEvents(false)
		b.evid.enabledByUs = false
	}
}

// ourBlockIDs — рабочие id наших block-фильтров (в событии отброса стоит id, а не GUID).
func ourBlockIDs(s *wf.Session) (map[uint64]bool, error) {
	rules, err := ourRules(s)
	if err != nil {
		return nil, err
	}
	out := map[uint64]bool{}
	for _, r := range rules {
		if r.Action == wf.ActionBlock {
			out[r.KernelID] = true
		}
	}
	return out, nil
}
