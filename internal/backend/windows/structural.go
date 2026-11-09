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
// permit, область которого выходит за нашу фактическую область. WFP не держит два sublayer с одним весом: созданный
// позже получает 0xFFFE (дым windows-2025), поэтому «создан раньше нашего» видно по весам, а не по порядку перечисления.
// Чужой permit безопасен, только если весь пропускаемый им трафик наш набор пропустил бы и сам в текущем режиме:
// есть наш permit на том же слое, чья область его покрывает, и ни один наш block выше этого permit (block-repair 30)
// с ним не пересекается. Так подслой клиента (sing-box со случайным GUID) узнаётся по программам профиля (рев. 6),
// strict ограничивает их Endpoints, а программы repair безопасной области не имеют вовсе.
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
	var out []probe.StructuralFinding
	for _, f := range foreign {
		s, ok := above[f.Sublayer]
		if !ok || !f.Permit || !f.Hard || withinOurs(f, own) {
			continue
		}
		out = append(out, probe.StructuralFinding{Kind: "wfp-tie", Detail: fmt.Sprintf(
			"чужой sublayer %s %q (вес 0x%X ≥ нашего 0x%X) — hard permit %q на %s пробивает наш block",
			s.ID, s.Name, s.Weight, ourWeight, f.Name, f.Layer)})
	}
	return out
}

// withinOurs: на слое чужого фильтра есть наш действующий permit, покрывающий его область, и ни один наш block
// с весом выше этого permit с ней не пересекается. Boot-time-фильтры при работающем BFE не действуют.
func withinOurs(f ForeignFilter, own []Filter) bool {
	for _, p := range own {
		if p.Layer != f.Layer || p.BootTime || p.Action != Permit || !covers(p.Conds, f.Conds) {
			continue
		}
		if !blockedAbove(f, own, p.Weight) {
			return true
		}
	}
	return false
}

func blockedAbove(f ForeignFilter, own []Filter, weight uint64) bool {
	for _, b := range own {
		if b.Layer == f.Layer && !b.BootTime && b.Action == Block && b.Weight > weight && !disjoint(b.Conds, f.Conds) {
			return true
		}
	}
	return false
}

// groups — условия по полям: внутри поля ИЛИ, между полями И. Условия неизвестного поля (Raw без поля)
// только сужают фильтр и в группы не попадают.
func groups(conds []Cond) map[Field][]Cond {
	out := map[Field][]Cond{}
	for _, c := range conds {
		if c.Field != "" {
			out[c.Field] = append(out[c.Field], c)
		}
	}
	return out
}

// covers: область inner внутри области outer — каждое поле outer есть у inner, и каждое значение inner
// по этому полю входит в одно из значений outer.
func covers(outer, inner []Cond) bool {
	in := groups(inner)
	for field, og := range groups(outer) {
		ig, ok := in[field]
		if !ok {
			return false
		}
		for _, c := range ig {
			if !condWithin(c, og) {
				return false
			}
		}
	}
	return true
}

// condWithin: условие c (одно из ИЛИ внутри поля) не шире группы outer.
func condWithin(c Cond, outer []Cond) bool {
	if c.Raw != "" {
		return false
	}
	for _, o := range outer {
		if o.Raw != "" {
			continue
		}
		switch {
		case c.String() == o.String():
			return true
		case o.Op == OpNeq && isEq(c) && valueOf(c) != valueOf(o):
			return true
		case c.Field == FieldRemoteAddr && isEq(c) && isEq(o) && o.Prefix.Bits() <= c.Prefix.Bits() &&
			o.Prefix.Contains(c.Prefix.Addr()):
			return true
		}
	}
	return false
}

// disjoint: есть поле, по которому все значения a и b — равенства без общих значений.
func disjoint(a, b []Cond) bool {
	gb := groups(b)
	for field, ga := range groups(a) {
		if bs, ok := gb[field]; ok && eqOnly(ga) && eqOnly(bs) && !overlapAny(ga, bs) {
			return true
		}
	}
	return false
}

func overlapAny(a, b []Cond) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Field == FieldRemoteAddr && x.Prefix.Overlaps(y.Prefix) || x.String() == y.String() {
				return true
			}
		}
	}
	return false
}

func eqOnly(cs []Cond) bool {
	for _, c := range cs {
		if c.Raw != "" || !isEq(c) {
			return false
		}
	}
	return true
}

func isEq(c Cond) bool { return c.Raw == "" && (c.Op == "" || c.Op == OpEq) }

// valueOf — значение условия без поля и оператора.
func valueOf(c Cond) string {
	o := c
	o.Op = OpEq
	return o.String()
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
