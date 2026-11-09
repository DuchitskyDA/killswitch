package windows

import (
	"fmt"

	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// MaxWeight — вес нашего sublayer.
const MaxWeight uint16 = 0xFFFF

// SublayerInfo — sublayer в порядке перечисления WFP.
type SublayerInfo struct {
	ID, Name string
	Weight   uint16
}

// ForeignFilter — чужой фильтр на наших слоях.
type ForeignFilter struct {
	Sublayer, Name string
	Layer          Layer
	Permit, Hard   bool
	Conds          []Cond
}

// TieFindings — ничья 0xFFFF (решение владельца «б»): чужой sublayer с весом ≥ фактического веса нашего и с hard
// permit, который пускает не только наше. WFP не держит два sublayer с одним весом: созданный позже получает 0xFFFE
// (дым windows-2025), поэтому «создан раньше нашего» видно по весам, а не по порядку перечисления.
// Подслой клиента (sing-box со случайным GUID) узнаётся по условиям его permit: все значения одного поля — наши
// app-id, LUID туннеля или loopback (рев. 6).
func TieFindings(sublayers []SublayerInfo, ours string, foreign []ForeignFilter, own []Filter) []probe.StructuralFinding {
	ourWeight := MaxWeight
	for _, s := range sublayers {
		if s.ID == ours {
			ourWeight = s.Weight
		}
	}
	above := map[string]SublayerInfo{}
	for _, s := range sublayers {
		if s.ID != ours && s.Weight >= ourWeight {
			above[s.ID] = s
		}
	}
	allowed := allowedValues(own)
	var out []probe.StructuralFinding
	for _, f := range foreign {
		s, ok := above[f.Sublayer]
		if !ok || !f.Permit || !f.Hard || restrictedTo(f.Conds, allowed) {
			continue
		}
		out = append(out, probe.StructuralFinding{Kind: "wfp-tie", Detail: fmt.Sprintf(
			"чужой sublayer %s %q (вес 0x%X ≥ нашего 0x%X) — hard permit %q на %s пробивает наш block",
			s.ID, s.Name, s.Weight, ourWeight, f.Name, f.Layer)})
	}
	return out
}

// allowedValues — app-id и LUID из наших permit-фильтров.
func allowedValues(own []Filter) map[string]bool {
	out := map[string]bool{}
	for _, f := range own {
		if f.Action != Permit {
			continue
		}
		for _, c := range f.Conds {
			if c.Field == FieldAppID || c.Field == FieldLocalIface {
				out[c.String()] = true
			}
		}
	}
	return out
}

// restrictedTo: есть поле, все условия которого (ИЛИ внутри поля) — только разрешённое нам; поля между собой — И.
func restrictedTo(conds []Cond, allowed map[string]bool) bool {
	byField := map[Field][]Cond{}
	for _, c := range conds {
		if c.Raw == "" {
			byField[c.Field] = append(byField[c.Field], c)
		}
	}
	for field, cs := range byField {
		if field == FieldLoopback || allWithin(cs, allowed) {
			return true
		}
	}
	return false
}

func allWithin(cs []Cond, allowed map[string]bool) bool {
	for _, c := range cs {
		if (c.Op != "" && c.Op != OpEq) || !allowed[c.String()] {
			return false
		}
	}
	return true
}

// MissingFindings — provider есть, а persistent block на слое нет: защита не действует; повторный Apply чинит.
func MissingFindings(filters []Filter) []probe.StructuralFinding {
	have := map[Layer]bool{}
	for _, f := range filters {
		if f.Persistent && f.Action == Block && f.Weight == WeightBlock && f.Hard && len(f.Conds) == 0 {
			have[f.Layer] = true
		}
	}
	var out []probe.StructuralFinding
	for _, l := range Layers {
		if !have[l] {
			out = append(out, probe.StructuralFinding{Kind: "wfp-missing", Repair: true,
				Detail: fmt.Sprintf("нет persistent block на %s: защита не действует", l)})
		}
	}
	return out
}
