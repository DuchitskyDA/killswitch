package main

import (
	"strings"
	"testing"

	"github.com/tailscale/wf"
)

func demoPlan() Plan {
	return Plan{Tag: "x", Block: true, Loopback: true, DHCP: true,
		Apps:   []AppPermit{{Name: "a", AppID: `\device\x\a.exe`}},
		Ifaces: []IfacePermit{{Name: "tun", LUID: 42}}}
}

func TestRulesPermitsBeforeBlock(t *testing.T) {
	rules := demoPlan().Rules()
	// 4 слоя × (loopback + app + iface + block) + DHCP на двух CONNECT-слоях
	if len(rules) != 4*4+2 {
		t.Fatalf("фильтров %d", len(rules))
	}
	seenBlock := false
	for _, r := range rules {
		if r.Action == wf.ActionBlock {
			seenBlock = true
			if r.Weight != weightBlock || len(r.Conditions) != 0 {
				t.Errorf("block: %+v", r)
			}
		} else if seenBlock {
			t.Errorf("permit %s после block", r.Name)
		}
		if r.Provider != providerID || r.Sublayer != sublayerID {
			t.Errorf("%s без provider/sublayer", r.Name)
		}
	}
}

func TestRuleKeysDeterministicAndUnique(t *testing.T) {
	a, b := demoPlan().Rules(), demoPlan().Rules()
	seen := map[wf.RuleID]bool{}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("ключ не детерминирован: %s", a[i].Name)
		}
		if seen[a[i].ID] {
			t.Fatalf("дубль ключа: %s", a[i].Name)
		}
		seen[a[i].ID] = true
	}
	p := demoPlan()
	p.HardBlock = true
	if p.Rules()[0].ID == a[0].ID {
		t.Fatal("варианты soft/hard делят ключи")
	}
}

func TestBootVariants(t *testing.T) {
	v := bootVariants(nil)
	if !v[1].Rules()[0].Provider.IsZero() || v[2].Rules()[0].Sublayer != (wf.SublayerID{}) {
		t.Fatal("запасные варианты boot-time не сняли provider/sublayer")
	}
	for _, p := range v {
		for _, r := range p.Rules() {
			if !r.BootTime || r.Persistent {
				t.Fatalf("%s: boottime=%t persistent=%t", r.Name, r.BootTime, r.Persistent)
			}
		}
	}
}

func TestRenderStable(t *testing.T) {
	r := Render(demoPlan().Rules())
	if r != Render(demoPlan().Rules()) {
		t.Fatal("Render не детерминирован")
	}
	for _, want := range []string{"ALE_AUTH_CONNECT_V6 weight=10 permit", "ALE_AUTH_RECV_ACCEPT_V4 weight=1 block", "IP_LOCAL_INTERFACE == 42"} {
		if !strings.Contains(r, want) {
			t.Errorf("нет %q в\n%s", want, r)
		}
	}
}

func TestGUIDv5Version(t *testing.T) {
	g := guidV5(ruleNamespace, "x")
	if g.Data3>>12 != 5 || g.Data4[0]>>6 != 2 {
		t.Fatalf("не v5: %v", g)
	}
}
