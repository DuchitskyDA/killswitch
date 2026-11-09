//go:build windows

// Дополнения killswitch к копии tailscale/wf (см. ORIGIN.md): транзакции, перечисление фильтров
// с boot-time и выключенными, опции движка (сбор событий отброса), события отброса с окном времени.

package wf

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFwpmEngineSetOption0 = modfwpuclnt.NewProc("FwpmEngineSetOption0")
	procFwpmEngineGetOption0 = modfwpuclnt.NewProc("FwpmEngineGetOption0")
)

func fwpCall(p *windows.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if r != 0 {
		return windows.Errno(r)
	}
	return nil
}

// Begin открывает транзакцию сессии: все изменения до Commit применяются разом или не применяются.
func (s *Session) Begin() error { return fwpmTransactionBegin0(s.handle, 0) }

// Commit фиксирует транзакцию.
func (s *Session) Commit() error { return fwpmTransactionCommit0(s.handle) }

// Abort откатывает транзакцию.
func (s *Session) Abort() error { return fwpmTransactionAbort0(s.handle) }

// RuleFilter — что перечислять в RulesOf.
type RuleFilter struct {
	Provider        *ProviderID // nil — все
	Layer           LayerID     // обязателен
	IncludeBootTime bool
	IncludeDisabled bool
}

// RulesOf перечисляет фильтры одного слоя по шаблону (Rules() не видит boot-time).
func (s *Session) RulesOf(f RuleFilter) ([]*Rule, error) {
	tpl := fwpmFilterEnumTemplate0{
		ProviderKey: f.Provider,
		LayerKey:    windows.GUID(f.Layer),
		EnumType:    filterEnumTypeOverlapping,
		ActionMask:  0xFFFFFFFF,
	}
	if f.IncludeBootTime {
		tpl.Flags |= filterEnumFlagsIncludeBootTime
	}
	if f.IncludeDisabled {
		tpl.Flags |= filterEnumFlagsIncludeDisabled
	}
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, &tpl, &enum); err != nil {
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)
	var ret []*Rule
	for {
		rules, err := s.getRulePage(enum)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return ret, nil
		}
		ret = append(ret, rules...)
	}
}

// Опции движка FWPM_ENGINE_OPTION.
const engineOptionCollectNetEvents = 0

// CollectNetEvents сообщает, включён ли сбор событий отброса.
func (s *Session) CollectNetEvents() (bool, error) {
	var v *fwpValue0
	if err := fwpCall(procFwpmEngineGetOption0, uintptr(s.handle), engineOptionCollectNetEvents,
		uintptr(unsafe.Pointer(&v))); err != nil {
		return false, err
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&v)))
	return v.Type == dataTypeUint32 && uint32(v.Value) != 0, nil
}

// SetCollectNetEvents включает или выключает сбор событий отброса.
func (s *Session) SetCollectNetEvents(on bool) error {
	v := fwpValue0{Type: dataTypeUint32}
	if on {
		v.Value = 1
	}
	return fwpCall(procFwpmEngineSetOption0, uintptr(s.handle), engineOptionCollectNetEvents, uintptr(unsafe.Pointer(&v)))
}

type fwpmNetEventEnumTemplate0 struct {
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition0
}

// DropEventsSince — события отброса в окне [since, until].
func (s *Session) DropEventsSince(since, until time.Time) ([]*DropEvent, error) {
	tpl := fwpmNetEventEnumTemplate0{
		StartTime: windows.NsecToFiletime(since.UnixNano()),
		EndTime:   windows.NsecToFiletime(until.UnixNano()),
	}
	var enum windows.Handle
	if err := fwpmNetEventCreateEnumHandle0(s.handle, (*struct{})(unsafe.Pointer(&tpl)), &enum); err != nil {
		return nil, err
	}
	defer fwpmNetEventDestroyEnumHandle0(s.handle, enum)
	var ret []*DropEvent
	for {
		events, n, err := s.getEventPage(enum)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return ret, nil
		}
		ret = append(ret, events...)
	}
}
