package ui

import (
	"slices"
	"strconv"
	"strings"
)

// listValue — список настройки: set — ключ задан в конфиге (иначе действует список профиля или умолчание).
type listValue[T any] struct {
	items []T
	set   bool
}

// listSpec — как редактировать список.
type listSpec[T comparable] struct {
	title   string
	profile []T  // список профиля
	inherit bool // ключ можно убрать, чтобы вернуть список профиля
	format  func(T) string
	add     func() (T, bool)
}

// editList — экран списка: добавить, удалить, вернуть как в профиле. Ключ конфига заменяет список профиля
// целиком, поэтому первая правка начинается с действующего списка. changed — список изменился.
func editList[T comparable](m *menu, s listSpec[T], v listValue[T]) (out listValue[T], changed bool) {
	if !v.set {
		v.items = s.profile
	}
	for !m.done {
		m.printf("\n%s%s\n", s.title, inheritNote(s.inherit, v.set))
		if len(v.items) == 0 {
			m.printf("    (пусто)\n")
		}
		for i, x := range v.items {
			m.printf("    %d. %s\n", i+1, s.format(x))
		}
		items := []item{{"Добавить", func() {
			if x, ok := s.add(); ok {
				v = listValue[T]{items: append(slices.Clone(v.items), x), set: true}
				changed = true
			}
		}}}
		if len(v.items) > 0 {
			items = append(items, item{"Удалить", func() {
				if i, ok := m.pickLine(len(v.items)); ok {
					v = listValue[T]{items: slices.Delete(slices.Clone(v.items), i, i+1), set: true}
					changed = true
				}
			}})
		}
		if s.inherit && v.set {
			items = append(items, item{"Как в профиле", func() {
				v, changed = listValue[T]{items: s.profile}, true
			}})
		}
		if !m.choose("", items, "Готово") {
			break
		}
	}
	if !s.inherit && len(v.items) == 0 {
		v.set = false // пустой список без профиля — то же, что ключа нет
	}
	if !v.set {
		v.items = nil
	}
	if v.set && v.items == nil {
		v.items = []T{}
	}
	return v, changed
}

func inheritNote(inherit, set bool) string {
	if inherit && !set {
		return " (из профиля)"
	}
	return ""
}

// pickLine читает номер строки списка (с 1) и возвращает индекс.
func (m *menu) pickLine(n int) (int, bool) {
	s := m.ask("Номер строки ")
	i, err := strconv.Atoi(s)
	if err != nil || i < 1 || i > n {
		if !m.done {
			m.printf("нет такой строки\n")
		}
		return 0, false
	}
	return i - 1, true
}

// prompt читает непустое значение и проверяет его; пустая строка — отказ.
func (m *menu) prompt(label string, check func(string) error) (string, bool) {
	s := m.ask(label + " (пусто — отмена) ")
	if s == "" {
		return "", false
	}
	if err := check(s); err != nil {
		m.printf("не принято: %v\n", err)
		return "", false
	}
	return s, true
}

// strList / putStrList — список строк конфига ↔ listValue.
func strList(p *[]string) listValue[string] {
	if p == nil {
		return listValue[string]{}
	}
	return listValue[string]{items: slices.Clone(*p), set: true}
}

func putStrList(v listValue[string]) *[]string {
	if !v.set {
		return nil
	}
	items := slices.Clone(v.items)
	if items == nil {
		items = []string{}
	}
	return &items
}

func identity(s string) string { return s }

// summary — короткая строка списка для пункта меню.
func summary(items []string, empty string) string {
	switch {
	case len(items) == 0:
		return empty
	case len(items) > 3:
		return strings.Join(items[:3], ", ") + "…"
	}
	return strings.Join(items, ", ")
}
