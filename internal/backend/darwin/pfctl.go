package darwin

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// Разбор вывода pfctl. Форматы сверены со спайком (ks-spike-pf.md, прогон 42623686584).

// pfEnabled: `pfctl -s info` → строка "Status: Enabled …".
func pfEnabled(info string) bool {
	for _, l := range lines(info) {
		if strings.HasPrefix(l, "Status:") {
			return strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(l, "Status:")), "Enabled")
		}
	}
	return false
}

// ref — ссылка enable-токена pf: `pfctl -s References`, колонки PID, имя процесса, токен, время.
type ref struct {
	PID   int
	Name  string
	Token string
}

func parseReferences(out string) []ref {
	var refs []ref
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		if _, err := strconv.ParseUint(f[2], 10, 64); err != nil {
			continue
		}
		refs = append(refs, ref{PID: pid, Name: f[1], Token: f[2]})
	}
	return refs
}

// parseToken: `pfctl -E` → "Token : 123".
func parseToken(out string) string {
	for _, l := range lines(out) {
		if rest, ok := strings.CutPrefix(l, "Token"); ok {
			if f := strings.Fields(strings.TrimLeft(strings.TrimSpace(rest), ":")); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

const anchorPoint = `anchor "com.apple/*"`

// mainFilter — правила фильтра основного набора (`pfctl -sr`) без scrub.
func mainFilter(out string) []string {
	var rules []string
	for _, l := range lines(out) {
		if l == "" || strings.HasPrefix(l, "scrub") || strings.HasPrefix(l, "[") {
			continue
		}
		rules = append(rules, l)
	}
	return rules
}

func isAnchorPoint(rule string) bool { return strings.HasPrefix(rule, anchorPoint) }

// anchorChildren: `pfctl -a com.apple -sA` → имена детей без префикса.
func anchorChildren(out string) []string {
	var names []string
	for _, l := range lines(out) {
		if l == "" {
			continue
		}
		names = append(names, l[strings.LastIndex(l, "/")+1:])
	}
	return names
}

// hasPassQuick — в наборе есть pass quick (сосед, способный перебить наш блок).
func hasPassQuick(rules string) bool {
	for _, l := range lines(rules) {
		if strings.HasPrefix(l, "pass") && strings.Contains(" "+l+" ", " quick ") {
			return true
		}
	}
	return false
}

var labelRe = regexp.MustCompile(`label "([^"]+)"`)

// labelPackets: `pfctl -a … -vsr` → label → счётчик пакетов. Строка счётчиков идёт под правилом:
// "  [ Evaluations: 10  Packets: 5  Bytes: 300  States: 0 ]".
func labelPackets(out string) map[string]uint64 {
	counts := map[string]uint64{}
	label := ""
	for _, raw := range strings.Split(out, "\n") {
		l := strings.TrimSpace(raw)
		if !strings.HasPrefix(l, "[") {
			label = ""
			if m := labelRe.FindStringSubmatch(l); m != nil {
				label = m[1]
			}
			continue
		}
		if label == "" {
			continue
		}
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "Packets:" {
				if n, err := strconv.ParseUint(f[i+1], 10, 64); err == nil {
					counts[label] += n
				}
				break
			}
		}
	}
	return counts
}

// ruleLines — непустые строки правил в выводе `-sr` (без строк счётчиков).
func ruleLines(out string) []string {
	var rules []string
	for _, l := range lines(out) {
		if l != "" && !strings.HasPrefix(l, "[") {
			rules = append(rules, l)
		}
	}
	return rules
}

func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		out = append(out, strings.TrimSpace(sc.Text()))
	}
	return out
}
