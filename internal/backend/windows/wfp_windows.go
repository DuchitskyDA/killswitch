package windows

import (
	"fmt"
	"net/netip"

	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
)

// Фиксированные GUID: provider и sublayer создаются один раз и никогда не пересоздаются (рев. 3).
var (
	providerID = wf.ProviderID(xwin.GUID{Data1: 0x8f2c6a41, Data2: 0x93d7, Data3: 0x4b0e,
		Data4: [8]byte{0xa5, 0xf1, 0x27, 0xc9, 0x4e, 0x6d, 0x0b, 0x3a}})
	sublayerID = wf.SublayerID(xwin.GUID{Data1: 0xc3e18b5d, Data2: 0x0f64, Data3: 0x4a29,
		Data4: [8]byte{0x8d, 0x7b, 0x5e, 0x9a, 0x12, 0xf4, 0xc6, 0x07}})
)

var layerIDs = map[Layer]wf.LayerID{
	ConnectV4: wf.LayerALEAuthConnectV4,
	ConnectV6: wf.LayerALEAuthConnectV6,
	AcceptV4:  wf.LayerALEAuthRecvAcceptV4,
	AcceptV6:  wf.LayerALEAuthRecvAcceptV6,
}

func layerOf(id wf.LayerID) (Layer, bool) {
	for l, lid := range layerIDs {
		if lid == id {
			return l, true
		}
	}
	return "", false
}

// openSession — сессия без флага dynamic: НЕ-persistent надстройки off/repair должны пережить выход CLI.
func openSession() (*wf.Session, error) {
	s, err := wf.New(&wf.Options{Name: "killswitch", Description: "killswitch"})
	if err != nil {
		return nil, fmt.Errorf("открыть движок WFP: %w", err)
	}
	return s, nil
}

func keyOf(f Filter) wf.RuleID {
	k := f.Key()
	return wf.RuleID(guidFromBytes(k))
}

func guidFromBytes(k [16]byte) xwin.GUID {
	return xwin.GUID{
		Data1: uint32(k[0])<<24 | uint32(k[1])<<16 | uint32(k[2])<<8 | uint32(k[3]),
		Data2: uint16(k[4])<<8 | uint16(k[5]),
		Data3: uint16(k[6])<<8 | uint16(k[7]),
		Data4: [8]byte{k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]},
	}
}

// toRule — наш фильтр в правило wf.
func toRule(f Filter) *wf.Rule {
	action := wf.ActionBlock
	if f.Action == Permit {
		action = wf.ActionPermit
	}
	name := "killswitch " + f.Name
	r := &wf.Rule{ID: keyOf(f), Name: name, Layer: layerIDs[f.Layer], Sublayer: sublayerID, Weight: f.Weight,
		Action: action, HardAction: f.Hard, Persistent: f.Persistent, BootTime: f.BootTime, Provider: providerID}
	for _, c := range f.Conds {
		r.Conditions = append(r.Conditions, toMatch(c))
	}
	return r
}

func toMatch(c Cond) *wf.Match {
	op := wf.MatchTypeEqual
	if c.Op == OpNeq {
		op = wf.MatchTypeNotEqual
	}
	switch c.Field {
	case FieldLoopback:
		return &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback}
	case FieldLocalIface:
		return &wf.Match{Field: wf.FieldIPLocalInterface, Op: op, Value: c.LUID}
	case FieldAppID:
		return &wf.Match{Field: wf.FieldALEAppID, Op: op, Value: c.AppID}
	case FieldProto:
		return &wf.Match{Field: wf.FieldIPProtocol, Op: op, Value: c.Proto}
	case FieldLocalPort:
		return &wf.Match{Field: wf.FieldIPLocalPort, Op: op, Value: c.Port}
	case FieldRemotePort:
		return &wf.Match{Field: wf.FieldIPRemotePort, Op: op, Value: c.Port}
	}
	return &wf.Match{Field: wf.FieldIPRemoteAddress, Op: op, Value: c.Prefix}
}

// fromRule — правило, прочитанное из WFP, в нашу модель (для хеша и Mode).
func fromRule(r *wf.Rule) Filter {
	l, _ := layerOf(r.Layer)
	f := Filter{Name: r.Name, Layer: l, Action: Block, Weight: r.Weight, Hard: r.HardAction,
		Persistent: r.Persistent, BootTime: r.BootTime}
	if r.Action == wf.ActionPermit {
		f.Action = Permit
	} else if r.Action != wf.ActionBlock {
		f.Action = Action(fmt.Sprintf("action-0x%x", uint32(r.Action)))
	}
	for _, m := range r.Conditions {
		f.Conds = append(f.Conds, fromMatch(m))
	}
	return f
}

func fromMatch(m *wf.Match) Cond {
	raw := Cond{Raw: m.String()}
	op := Op("")
	switch m.Op {
	case wf.MatchTypeEqual:
	case wf.MatchTypeNotEqual:
		op = OpNeq
	case wf.MatchTypeFlagsAllSet:
		if m.Field == wf.FieldFlags && flagValue(m.Value) == uint32(wf.ConditionFlagIsLoopback) {
			return Cond{Field: FieldLoopback}
		}
		return raw
	default:
		return raw
	}
	switch v := m.Value.(type) {
	case uint64:
		if m.Field == wf.FieldIPLocalInterface {
			return Cond{Field: FieldLocalIface, Op: op, LUID: v}
		}
	case string:
		if m.Field == wf.FieldALEAppID {
			return Cond{Field: FieldAppID, Op: op, AppID: v}
		}
	case uint8:
		if m.Field == wf.FieldIPProtocol {
			return Cond{Field: FieldProto, Op: op, Proto: v}
		}
	case uint16:
		switch m.Field {
		case wf.FieldIPLocalPort:
			return Cond{Field: FieldLocalPort, Op: op, Port: v}
		case wf.FieldIPRemotePort:
			return Cond{Field: FieldRemotePort, Op: op, Port: v}
		}
	case netip.Prefix:
		if m.Field == wf.FieldIPRemoteAddress {
			return Cond{Field: FieldRemoteAddr, Op: op, Prefix: v}
		}
	case netip.Addr:
		if m.Field == wf.FieldIPRemoteAddress {
			return Cond{Field: FieldRemoteAddr, Op: op, Prefix: netip.PrefixFrom(v, v.BitLen())}
		}
	}
	return raw
}

// flagValue — флаги условия: из WFP приходят uint32, из toMatch — wf.ConditionFlag.
func flagValue(v any) uint32 {
	switch f := v.(type) {
	case uint32:
		return f
	case wf.ConditionFlag:
		return uint32(f)
	}
	return 0
}
