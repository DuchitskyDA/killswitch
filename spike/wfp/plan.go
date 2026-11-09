package main

import (
	"crypto/sha1"
	"fmt"
	"sort"
	"strings"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Фиксированные идентификаторы спайка: снятие по ним работает без конфига.
var (
	providerID = wf.ProviderID(mustGUID("291b5078-c763-4e83-822a-b3108ed5213a"))
	sublayerID = wf.SublayerID(mustGUID("f6581b03-4fb4-49ef-9c82-56b34a22582c"))
	// Пространство имён для детерминированных ключей фильтров (GUID v5).
	ruleNamespace = mustGUID("2d0b3e4c-6550-45f9-bd84-7032c0ed6928")
)

const (
	providerName = "ks-spike-wfp"
	sublayerName = "ks-spike-wfp"

	weightBlock  uint64 = 1
	weightPermit uint64 = 10
)

// Слои ALE, на которых стоит набор.
var aleLayers = []wf.LayerID{
	wf.LayerALEAuthConnectV4,
	wf.LayerALEAuthConnectV6,
	wf.LayerALEAuthRecvAcceptV4,
	wf.LayerALEAuthRecvAcceptV6,
}

var layerNames = map[wf.LayerID]string{
	wf.LayerALEAuthConnectV4:    "ALE_AUTH_CONNECT_V4",
	wf.LayerALEAuthConnectV6:    "ALE_AUTH_CONNECT_V6",
	wf.LayerALEAuthRecvAcceptV4: "ALE_AUTH_RECV_ACCEPT_V4",
	wf.LayerALEAuthRecvAcceptV6: "ALE_AUTH_RECV_ACCEPT_V6",
}

func isV6(l wf.LayerID) bool {
	return l == wf.LayerALEAuthConnectV6 || l == wf.LayerALEAuthRecvAcceptV6
}

func isConnect(l wf.LayerID) bool {
	return l == wf.LayerALEAuthConnectV4 || l == wf.LayerALEAuthConnectV6
}

// AppPermit — программа, которой разрешён выход (app-id уже получен).
type AppPermit struct {
	Name  string
	AppID string
}

// IfacePermit — интерфейс, через который выход разрешён.
type IfacePermit struct {
	Name string
	LUID uint64
}

// Plan — набор фильтров спайка.
type Plan struct {
	Tag        string // часть имени и ключа фильтра, разделяет варианты
	Block      bool
	HardBlock  bool
	Loopback   bool
	DHCP       bool
	Apps       []AppPermit
	Ifaces     []IfacePermit
	Persistent bool
	BootTime   bool
	// NoProvider и NoSublayer — запасные варианты для boot-time.
	NoProvider bool
	NoSublayer bool
}

// guidV5 — RFC 4122 v5 от пространства имён и имени.
func guidV5(ns windows.GUID, name string) windows.GUID {
	b := guidBytes(ns)
	h := sha1.New()
	h.Write(b[:])
	h.Write([]byte(name))
	s := h.Sum(nil)
	var u [16]byte
	copy(u[:], s[:16])
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return windows.GUID{
		Data1: uint32(u[0])<<24 | uint32(u[1])<<16 | uint32(u[2])<<8 | uint32(u[3]),
		Data2: uint16(u[4])<<8 | uint16(u[5]),
		Data3: uint16(u[6])<<8 | uint16(u[7]),
		Data4: [8]byte{u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]},
	}
}

func guidBytes(g windows.GUID) [16]byte {
	return [16]byte{
		byte(g.Data1 >> 24), byte(g.Data1 >> 16), byte(g.Data1 >> 8), byte(g.Data1),
		byte(g.Data2 >> 8), byte(g.Data2), byte(g.Data3 >> 8), byte(g.Data3),
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
	}
}

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString("{" + s + "}")
	if err != nil {
		panic(err)
	}
	return g
}

func ruleKey(name string) wf.RuleID {
	return wf.RuleID(guidV5(ruleNamespace, name))
}

// Rules строит фильтры плана. Порядок: сначала permit, потом block —
// без транзакции окно «блок без исключений раннера» не возникает.
func (p Plan) Rules() []*wf.Rule {
	var permits, blocks []*wf.Rule
	for _, l := range aleLayers {
		ln := layerNames[l]
		mk := func(kind string, w uint64, a wf.Action, hard bool, conds []*wf.Match) *wf.Rule {
			name := fmt.Sprintf("ks-spike/%s/%s/%s", p.variant(), kind, ln)
			r := &wf.Rule{
				ID:         ruleKey(name),
				Name:       name,
				Layer:      l,
				Weight:     w,
				Conditions: conds,
				Action:     a,
				HardAction: hard,
				Persistent: p.Persistent,
				BootTime:   p.BootTime,
			}
			if !p.NoProvider {
				r.Provider = providerID
			}
			if !p.NoSublayer {
				r.Sublayer = sublayerID
			}
			return r
		}
		if p.Loopback {
			permits = append(permits, mk("permit-loopback", weightPermit, wf.ActionPermit, false, []*wf.Match{
				{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback},
			}))
		}
		for _, a := range p.Apps {
			permits = append(permits, mk("permit-app-"+a.Name, weightPermit, wf.ActionPermit, false, []*wf.Match{
				{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: a.AppID},
			}))
		}
		for _, i := range p.Ifaces {
			permits = append(permits, mk("permit-iface-"+i.Name, weightPermit, wf.ActionPermit, false, []*wf.Match{
				{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: i.LUID},
			}))
		}
		if p.DHCP && isConnect(l) {
			local, remote := uint16(68), uint16(67)
			if isV6(l) {
				local, remote = 546, 547
			}
			permits = append(permits, mk("permit-dhcp", weightPermit, wf.ActionPermit, false, []*wf.Match{
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
				{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: local},
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: remote},
			}))
		}
		if p.Block {
			blocks = append(blocks, mk("block-all", weightBlock, wf.ActionBlock, p.HardBlock, nil))
		}
	}
	return append(permits, blocks...)
}

func (p Plan) variant() string {
	v := p.Tag
	if v == "" {
		v = "run"
	}
	switch {
	case p.BootTime:
		v += "-boot"
	case p.Persistent:
		v += "-persist"
	}
	if p.HardBlock {
		v += "-hard"
	}
	return v
}

// Render — детерминированный текст плана (основа эталонов боевого backend).
func Render(rules []*wf.Rule) string {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		action := "permit"
		if r.Action == wf.ActionBlock {
			action = "block"
		}
		conds := make([]string, 0, len(r.Conditions))
		for _, c := range r.Conditions {
			conds = append(conds, fmt.Sprintf("%s %s %v", fieldName(c.Field), c.Op, c.Value))
		}
		lines = append(lines, fmt.Sprintf("%s weight=%d %s hard=%t persistent=%t boottime=%t provider=%t sublayer=%t [%s] %s",
			layerNames[r.Layer], r.Weight, action, r.HardAction, r.Persistent, r.BootTime,
			!r.Provider.IsZero(), !r.Sublayer.IsZero(), strings.Join(conds, " && "), r.Name))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func fieldName(f wf.FieldID) string {
	switch f {
	case wf.FieldFlags:
		return "FLAGS"
	case wf.FieldALEAppID:
		return "ALE_APP_ID"
	case wf.FieldIPLocalInterface:
		return "IP_LOCAL_INTERFACE"
	case wf.FieldIPProtocol:
		return "IP_PROTOCOL"
	case wf.FieldIPLocalPort:
		return "IP_LOCAL_PORT"
	case wf.FieldIPRemotePort:
		return "IP_REMOTE_PORT"
	}
	return f.String()
}
