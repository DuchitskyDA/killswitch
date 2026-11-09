// Package ui — меню в терминале: одно на все ОС. Чистая логика: ввод — строки, вывод — io.Writer,
// действия (on/off/repair/check, сохранение конфига) — через Actions, которые реализует cmd/killswitch.
package ui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Header — состояние для шапки главного экрана, по тем же признакам, что команда status.
type Header struct {
	Mode    policy.Mode // пусто — защита не установлена
	Active  bool        // наши правила есть в системе
	Tunnels []Tunnel    // адаптеры, совпавшие с шаблонами туннеля
	Notes   []string    // строки WARN и LEAK
}

// Tunnel — совпавший адаптер туннеля.
type Tunnel struct {
	Name string
	Up   bool
}

// Profile — встроенный профиль клиента с секцией текущей ОС.
type Profile struct {
	Name, Description string
	Layer             policy.Layer
}

// Actions — действия меню. Реализация вызывает ту же логику, что команды CLI.
type Actions interface {
	Header() Header
	Transition(m policy.Mode) error     // on | off | repair
	Check(ctx context.Context) error    // пробы утечек, вывод — сама команда
	Detect() []string                   // имена профилей установленных клиентов
	Profiles() []Profile                // по имени
	LoadConfig() (policy.Config, error) // нет файла — пустой конфиг
	// Save проверяет конфиг тем же путём, что on, при успехе атомарно пишет config.toml и применяет
	// текущий режим. saved — строка итога, непустая, если файл записан (в том числе когда применение не удалось);
	// err — готовый для показа текст ошибки.
	Save(data []byte) (saved string, err error)
}

// Run показывает главное меню до выхода, конца ввода или отмены ctx.
func Run(ctx context.Context, caps policy.Capabilities, act Actions, in io.Reader, out io.Writer) {
	m := &menu{ctx: ctx, caps: caps, act: act, out: out, lines: readLines(in)}
	m.mainScreen()
}

type menu struct {
	ctx   context.Context
	caps  policy.Capabilities
	act   Actions
	out   io.Writer
	lines <-chan string
	done  bool // ввод кончился или отменён: все экраны выходят
}

// item — пункт экрана; do вызывается при выборе.
type item struct {
	label string
	do    func()
}

func readLines(r io.Reader) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			ch <- sc.Text()
		}
	}()
	return ch
}

func (m *menu) printf(format string, args ...any) { fmt.Fprintf(m.out, format, args...) }

// ask печатает приглашение и ждёт строку; конец ввода или отмена — пустая строка и m.done.
func (m *menu) ask(prompt string) string {
	m.printf("%s> ", prompt)
	select {
	case <-m.ctx.Done():
		m.done = true
		return ""
	case line, ok := <-m.lines:
		if !ok {
			m.done = true
			return ""
		}
		return strings.TrimSpace(line)
	}
}

// choose печатает пункты с номерами и «0) back», выполняет выбранный. false — выбран 0 или ввод кончился.
func (m *menu) choose(title string, items []item, back string) bool {
	if title != "" {
		m.printf("\n%s\n", title)
	}
	for i, it := range items {
		m.printf("  %d) %s\n", i+1, it.label)
	}
	m.printf("  0) %s\n", back)
	for !m.done {
		n, ok := m.number(len(items))
		if !ok {
			m.printf("нет такого пункта\n")
			continue
		}
		if n == 0 {
			return false
		}
		items[n-1].do()
		return !m.done
	}
	return false
}

// number читает номер от 0 до max.
func (m *menu) number(max int) (int, bool) {
	n, err := strconv.Atoi(m.ask(""))
	if m.done {
		return 0, true
	}
	return n, err == nil && n >= 0 && n <= max
}

// confirm — вопрос «1) yes 0) no»; true — выбран yes.
func (m *menu) confirm(title, yes, no string) bool {
	agreed := false
	m.choose(title, []item{{yes, func() { agreed = true }}}, no)
	return agreed
}

func (m *menu) report(err error) {
	if err != nil {
		m.printf("ошибка: %v\n", err)
	}
}
