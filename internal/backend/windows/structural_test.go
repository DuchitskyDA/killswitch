package windows

import (
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

const oursID = "{ours}"

func ownOn(t *testing.T) []Filter {
	return plan(t, basePolicy(policy.ModeOn), baseEnv()).Filters
}

func foreignPermitAll(sub string) ForeignFilter {
	return ForeignFilter{Sublayer: sub, Name: "allow all", Layer: ConnectV4, Permit: true, Hard: true}
}

func TestTieForeignBeforeOursIsLeak(t *testing.T) {
	subs := []SublayerInfo{{ID: "{x}", Name: "other", Weight: 0xFFFF}, {ID: oursID, Weight: 0xFFFF}}
	got := TieFindings(subs, oursID, []ForeignFilter{foreignPermitAll("{x}")}, ownOn(t))
	if len(got) != 1 || got[0].Kind != "wfp-tie" || got[0].Repair {
		t.Errorf("ожидалась одна находка wfp-tie без Repair, получено %+v", got)
	}
}

// WFP даёт созданному позже sublayer 0xFFFE: чужой после нашего — ниже нас.
func TestTieForeignAfterOursIsFine(t *testing.T) {
	subs := []SublayerInfo{{ID: "{x}", Weight: 0xFFFE}, {ID: oursID, Weight: 0xFFFF}}
	if got := TieFindings(subs, oursID, []ForeignFilter{foreignPermitAll("{x}")}, ownOn(t)); len(got) != 0 {
		t.Errorf("sublayer после нашего не пробивает: %+v", got)
	}
}

// Наш создан после чужого 0xFFFF и получил 0xFFFE: чужой выше — утечка, где бы он ни стоял в перечислении.
func TestTieOursDemotedIsLeak(t *testing.T) {
	subs := []SublayerInfo{{ID: oursID, Weight: 0xFFFE}, {ID: "{x}", Weight: 0xFFFF}}
	if got := TieFindings(subs, oursID, []ForeignFilter{foreignPermitAll("{x}")}, ownOn(t)); len(got) != 1 {
		t.Errorf("чужой выше нашего — утечка: %+v", got)
	}
}

func TestTieLowerWeightIsFine(t *testing.T) {
	subs := []SublayerInfo{{ID: "{x}", Weight: 0x0100}, {ID: oursID, Weight: 0xFFFF}}
	if got := TieFindings(subs, oursID, []ForeignFilter{foreignPermitAll("{x}")}, ownOn(t)); len(got) != 0 {
		t.Errorf("вес ниже нашего не пробивает: %+v", got)
	}
}

func TestTieClientSublayerByProgramIsFine(t *testing.T) {
	subs := []SublayerInfo{{ID: "{singbox}", Weight: 0xFFFF}, {ID: oursID, Weight: 0xFFFF}}
	f := foreignPermitAll("{singbox}")
	f.Conds = []Cond{{Field: FieldAppID, AppID: happApp}}
	if got := TieFindings(subs, oursID, []ForeignFilter{f}, ownOn(t)); len(got) != 0 {
		t.Errorf("hard permit только программы профиля — не утечка: %+v", got)
	}
}

func TestTieForeignProgramIsLeak(t *testing.T) {
	subs := []SublayerInfo{{ID: "{x}", Weight: 0xFFFF}, {ID: oursID, Weight: 0xFFFF}}
	f := foreignPermitAll("{x}")
	f.Conds = []Cond{{Field: FieldAppID, AppID: happApp}, {Field: FieldAppID, AppID: `\device\x\other.exe`}}
	if got := TieFindings(subs, oursID, []ForeignFilter{f}, ownOn(t)); len(got) != 1 {
		t.Errorf("hard permit чужой программы — утечка: %+v", got)
	}
}

func TestTieSoftPermitIsFine(t *testing.T) {
	subs := []SublayerInfo{{ID: "{x}", Weight: 0xFFFF}, {ID: oursID, Weight: 0xFFFF}}
	f := foreignPermitAll("{x}")
	f.Hard = false
	if got := TieFindings(subs, oursID, []ForeignFilter{f}, ownOn(t)); len(got) != 0 {
		t.Errorf("soft permit наш hard block не пробивает: %+v", got)
	}
}
