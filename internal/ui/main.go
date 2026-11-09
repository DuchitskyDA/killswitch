package ui

import (
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

func (m *menu) mainScreen() {
	for !m.done {
		title := m.headerText(m.act.Header())
		items := []item{{"Включить защиту", func() { m.report(m.act.Transition(policy.ModeOn)) }}}
		if m.caps.Repair {
			items = append(items, item{"Починка туннеля (открыто всем, кроме закрытых в починке)",
				func() { m.report(m.act.Transition(policy.ModeRepair)) }})
		}
		items = append(items,
			item{"Выключить до перезагрузки", func() { m.report(m.act.Transition(policy.ModeOff)) }},
			item{"Проверить утечки", func() { m.report(m.act.Check(m.ctx)) }},
			item{"Настройки ▸", m.settingsScreen},
		)
		if !m.choose(title, items, "Выход") {
			return
		}
	}
}

func (m *menu) headerText(h Header) string {
	var b strings.Builder
	b.WriteString("killswitch — защита: " + modeText(h) + ", туннель: " + tunnelText(h.Tunnels))
	for _, n := range h.Notes {
		b.WriteString("\n" + n)
	}
	return b.String()
}

func modeText(h Header) string {
	switch {
	case h.Mode == "" && !h.Active:
		return "не включена"
	case h.Mode == policy.ModeOff:
		return "ВЫКЛ до перезагрузки (off)"
	case h.Mode == policy.ModeRepair:
		return "починка до перезагрузки (repair)"
	case !h.Active:
		return "правила не загружены (" + string(h.Mode) + ")"
	}
	return "ВКЛ (on)"
}

func tunnelText(ts []Tunnel) string {
	if len(ts) == 0 {
		return "не найден"
	}
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		mark := "▼"
		if t.Up {
			mark = "▲"
		}
		parts = append(parts, t.Name+" "+mark)
	}
	return strings.Join(parts, ", ")
}
