package main

// Чего нет в github.com/tailscale/wf@6fbb0a67: транзакции (не экспортированы)
// и перечисление фильтров с boot-time (Rules() их не видит, а константы
// filterEnumFlags в wf неверные). Здесь — свои вызовы fwpuclnt.dll.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

var (
	fwpuclnt              = windows.NewLazySystemDLL("fwpuclnt.dll")
	procTxBegin           = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procTxCommit          = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procTxAbort           = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFilterCreateEnum  = fwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFilterEnum        = fwpuclnt.NewProc("FwpmFilterEnum0")
	procFilterDestroyEnum = fwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFilterDeleteByKey = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFreeMemory        = fwpuclnt.NewProc("FwpmFreeMemory0")
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procSetTcpEntry       = iphlpapi.NewProc("SetTcpEntry")
)

// Правильные значения FWP_FILTER_ENUM_FLAG_*.
const (
	enumFlagBootTimeOnly    = 0x4
	enumFlagIncludeBootTime = 0x8
	enumFlagIncludeDisabled = 0x10
	enumTypeOverlapping     = 1

	filterFlagPersistent       = 0x1
	filterFlagBootTime         = 0x2
	filterFlagClearActionRight = 0x8
)

func fwpErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("0x%08X (%v)", uint32(r), windows.Errno(r))
}

// engineHandle — неэкспортированное первое поле wf.Session. Раскладка
// зависит от закреплённой версии wf; проверка — успешный вызов enum.
func engineHandle(s *wf.Session) windows.Handle {
	return *(*windows.Handle)(unsafe.Pointer(s))
}

func txBegin(s *wf.Session) error {
	r, _, _ := procTxBegin.Call(uintptr(engineHandle(s)), 0)
	return fwpErr(r)
}

func txCommit(s *wf.Session) error {
	r, _, _ := procTxCommit.Call(uintptr(engineHandle(s)))
	return fwpErr(r)
}

func txAbort(s *wf.Session) error {
	r, _, _ := procTxAbort.Call(uintptr(engineHandle(s)))
	return fwpErr(r)
}

type fwpValue0 struct {
	Type  uint32
	_     uint32
	Value unsafe.Pointer
}

type fwpmAction0 struct {
	Type uint32
	GUID windows.GUID
}

// fwpmFilter0 — раскладка FWPM_FILTER0 на amd64.
type fwpmFilter0 struct {
	FilterKey          windows.GUID
	Name               *uint16
	Description        *uint16
	Flags              uint32
	ProviderKey        *windows.GUID
	ProviderDataSize   uint32
	ProviderData       *byte
	LayerKey           windows.GUID
	SubLayerKey        windows.GUID
	Weight             fwpValue0
	NumConditions      uint32
	Conditions         uintptr
	Action             fwpmAction0
	ProviderContextKey [2]uint64
	Reserved           *windows.GUID
	FilterID           uint64
	EffectiveWeight    fwpValue0
}

type fwpmFilterEnumTemplate0 struct {
	ProviderKey             *windows.GUID
	LayerKey                windows.GUID
	EnumType                uint32
	Flags                   uint32
	ProviderContextTemplate uintptr
	NumConditions           uint32
	Conditions              uintptr
	ActionMask              uint32
	CalloutKey              *windows.GUID
}

// FilterInfo — то, что спайк читает о фильтре.
type FilterInfo struct {
	Key             windows.GUID
	Name            string
	Flags           uint32
	Provider        windows.GUID
	HasProvider     bool
	Layer           windows.GUID
	Sublayer        windows.GUID
	Weight          string
	EffectiveWeight string
	Action          uint32
	FilterID        uint64
}

func valueString(v fwpValue0) string {
	switch v.Type {
	case 0:
		return "empty"
	case 1:
		return fmt.Sprintf("u8:%d", uint8(uintptr(v.Value)))
	case 4:
		if v.Value == nil {
			return "u64:nil"
		}
		return fmt.Sprintf("u64:%d", *(*uint64)(v.Value))
	}
	return fmt.Sprintf("type%d", v.Type)
}

// enumFilters перечисляет фильтры слоя; provider == nil — все.
func enumFilters(s *wf.Session, layer wf.LayerID, provider *windows.GUID, flags uint32) ([]FilterInfo, error) {
	tmpl := fwpmFilterEnumTemplate0{
		ProviderKey: provider,
		LayerKey:    windows.GUID(layer),
		EnumType:    enumTypeOverlapping,
		Flags:       flags,
		ActionMask:  0xFFFFFFFF,
	}
	var enum windows.Handle
	h := uintptr(engineHandle(s))
	if r, _, _ := procFilterCreateEnum.Call(h, uintptr(unsafe.Pointer(&tmpl)), uintptr(unsafe.Pointer(&enum))); r != 0 {
		return nil, fmt.Errorf("FwpmFilterCreateEnumHandle0: %w", fwpErr(r))
	}
	defer procFilterDestroyEnum.Call(h, uintptr(enum))
	var out []FilterInfo
	for {
		var arr **fwpmFilter0
		var n uint32
		if r, _, _ := procFilterEnum.Call(h, uintptr(enum), 100, uintptr(unsafe.Pointer(&arr)), uintptr(unsafe.Pointer(&n))); r != 0 {
			return out, fmt.Errorf("FwpmFilterEnum0: %w", fwpErr(r))
		}
		if n == 0 {
			return out, nil
		}
		ptrs := unsafe.Slice(arr, n)
		for _, f := range ptrs {
			fi := FilterInfo{
				Key:             f.FilterKey,
				Name:            windows.UTF16PtrToString(f.Name),
				Flags:           f.Flags,
				Layer:           f.LayerKey,
				Sublayer:        f.SubLayerKey,
				Weight:          valueString(f.Weight),
				EffectiveWeight: valueString(f.EffectiveWeight),
				Action:          f.Action.Type,
				FilterID:        f.FilterID,
			}
			if f.ProviderKey != nil {
				fi.Provider = *f.ProviderKey
				fi.HasProvider = true
			}
			out = append(out, fi)
		}
		procFreeMemory.Call(uintptr(unsafe.Pointer(&arr)))
	}
}

func deleteFilter(s *wf.Session, key windows.GUID) error {
	r, _, _ := procFilterDeleteByKey.Call(uintptr(engineHandle(s)), uintptr(unsafe.Pointer(&key)))
	return fwpErr(r)
}

// ourFilters — все фильтры нашего provider на всех слоях, включая boot-time.
func ourFilters(s *wf.Session) ([]FilterInfo, error) {
	layers, err := s.Layers()
	if err != nil {
		return nil, err
	}
	pid := windows.GUID(providerID)
	var out []FilterInfo
	var errs []error
	for _, l := range layers {
		fs, err := enumFilters(s, l.ID, &pid, enumFlagIncludeBootTime|enumFlagIncludeDisabled)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", l.ID, err))
			continue
		}
		out = append(out, fs...)
	}
	return out, errors.Join(errs...)
}

// MIB_TCPROW для SetTcpEntry; адреса и порты — в сетевом порядке.
type mibTCPRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
}

const mibTCPStateDeleteTCB = 12

// deleteTCB обрывает TCP-соединение v4 (только v4: у SetTcpEntry нет v6).
func deleteTCB(local, remote netip.AddrPort) error {
	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return errors.New("SetTcpEntry: только IPv4")
	}
	l4, r4 := local.Addr().As4(), remote.Addr().As4()
	row := mibTCPRow{
		State:      mibTCPStateDeleteTCB,
		LocalAddr:  binary.LittleEndian.Uint32(l4[:]),
		LocalPort:  uint32(htons(local.Port())),
		RemoteAddr: binary.LittleEndian.Uint32(r4[:]),
		RemotePort: uint32(htons(remote.Port())),
	}
	r, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 {
		return fmt.Errorf("SetTcpEntry: %v", windows.Errno(r))
	}
	return nil
}

func htons(p uint16) uint16 { return p<<8 | p>>8 }

// Adapter — интерфейс машины.
type Adapter struct {
	Index        uint32
	LUID         uint64
	FriendlyName string
	Description  string
	Up           bool
	IfType       uint32
}

func adapters() ([]Adapter, error) {
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []Adapter
		for a := aa; a != nil; a = a.Next {
			out = append(out, Adapter{
				Index:        a.IfIndex,
				LUID:         a.Luid,
				FriendlyName: windows.UTF16PtrToString(a.FriendlyName),
				Description:  windows.UTF16PtrToString(a.Description),
				Up:           a.OperStatus == windows.IfOperStatusUp,
				IfType:       a.IfType,
			})
		}
		return out, nil
	}
}

// bestAdapter — интерфейс маршрута к адресу.
func bestAdapter(ip netip.Addr) (Adapter, error) {
	var idx uint32
	sa := &windows.SockaddrInet4{Addr: ip.As4()}
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return Adapter{}, err
	}
	as, err := adapters()
	if err != nil {
		return Adapter{}, err
	}
	for _, a := range as {
		if a.Index == idx {
			return a, nil
		}
	}
	return Adapter{}, fmt.Errorf("интерфейс %d не найден", idx)
}

func adapterByName(name string) (Adapter, bool) {
	as, err := adapters()
	if err != nil {
		return Adapter{}, false
	}
	for _, a := range as {
		if a.FriendlyName == name {
			return a, true
		}
	}
	return Adapter{}, false
}

// orphanFilters — фильтры спайка без provider (по префиксу имени) на всех слоях.
func orphanFilters(s *wf.Session) ([]FilterInfo, error) {
	layers, err := s.Layers()
	if err != nil {
		return nil, err
	}
	var out []FilterInfo
	var errs []error
	for _, l := range layers {
		fs, err := enumFilters(s, l.ID, nil, enumFlagIncludeBootTime|enumFlagIncludeDisabled)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", l.ID, err))
		}
		for _, f := range fs {
			if !f.HasProvider && strings.HasPrefix(f.Name, "ks-spike/") {
				out = append(out, f)
			}
		}
	}
	return out, errors.Join(errs...)
}
