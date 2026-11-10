// Package probe — контракт и общая логика check: пробы, свидетельства и итог.
package probe

import (
	"net/netip"
	"time"
)

// Class — класс пробы или итога.
type Class string

const (
	Blocked      Class = "BLOCKED"
	Leak         Class = "LEAK"
	Inconclusive Class = "INCONCLUSIVE"
	// Skipped — семейства адресов нет на интерфейсе: проба не делалась и в итог не входит.
	Skipped Class = "SKIPPED"
)

// ProbeResult — одна проба через один физический интерфейс.
type ProbeResult struct {
	Target, Family, Proto, Iface string
	Class                        Class
	Detail                       string
}

// StructuralFinding — структурная утечка без пробы: WFP-ничья, pf-сосед или quick выше якоря,
// якорь недостижим, pf выключен. Любая — итог LEAK.
// Repair — повторный Apply того же плана её устраняет (pf выключен, токен потерян, нет anchor-точки):
// enforce применяет заново. Без Repair (чужое quick-правило, сосед, WFP-ничья) — только LEAK.
type StructuralFinding struct {
	Kind, Detail string
	Repair       bool
}

// CheckResult — итог check.
type CheckResult struct {
	Probes     []ProbeResult
	Structural []StructuralFinding
	Overall    Class
}

// ProbeID — 5-кортеж и время пробы: по нему backend ищет свидетельство отброса своим правилом.
type ProbeID struct {
	Proto    string // "tcp" | "udp"
	Src, Dst netip.AddrPort
	Iface    string
	At       time.Time
}

// Порты-источники проб: выделенный диапазон ниже эфемерных диапазонов всех трёх ОС
// (Linux 32768–60999, macOS и Windows 49152–65535). Обычные соединения, в том числе
// доверенного клиента туннеля, в него не попадают, поэтому правила проб стоят выше Trust,
// а счётчики backend отличают пробные пакеты.
const (
	SrcPortFirst uint16 = 30000
	SrcPortLast  uint16 = 30063
)

// Overall: любой Structural или LEAK → LEAK; иначе любая INCONCLUSIVE или ни одной пробы → INCONCLUSIVE; иначе BLOCKED.
func Overall(probes []ProbeResult, structural []StructuralFinding) Class {
	if len(structural) > 0 {
		return Leak
	}
	counted, inconclusive := 0, false
	for _, p := range probes {
		switch p.Class {
		case Leak:
			return Leak
		case Inconclusive:
			inconclusive = true
		case Skipped:
			continue
		}
		counted++
	}
	if inconclusive || counted == 0 {
		return Inconclusive
	}
	return Blocked
}

// ExitCode — код выхода CLI по итогу: 0 BLOCKED, 4 LEAK, 5 INCONCLUSIVE.
func ExitCode(c Class) int {
	switch c {
	case Blocked:
		return 0
	case Leak:
		return 4
	}
	return 5
}
