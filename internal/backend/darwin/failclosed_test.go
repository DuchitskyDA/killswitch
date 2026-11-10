package darwin

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// anchorRunner — фейк pf, который помнит загруженный якорь: `-a Anchor -f <файл|->` заменяет его, `-sr` читает.
// afterLoad срабатывает после загрузки — так подставляется сбой хвоста Apply.
type anchorRunner struct {
	base      *fakeRunner
	active    string
	afterLoad func(text string)
	failSR    bool
	reject    func(text string) bool // отказ pfctl загрузить этот текст
}

func (r *anchorRunner) Run(stdin, name string, args ...string) (Result, error) {
	if name == pfctlPath && len(args) == 4 && args[0] == "-a" && args[1] == Anchor && args[2] == "-f" {
		text := stdin
		if args[3] != "-" {
			data, err := os.ReadFile(args[3])
			if err != nil {
				return Result{}, err
			}
			text = string(data)
		}
		if r.reject != nil && r.reject(text) {
			return Result{}, errors.New("pfctl отверг набор")
		}
		r.active = strings.Join(ruleLinesOf(text), "\n")
		if r.afterLoad != nil {
			r.afterLoad(text)
		}
		return Result{}, nil
	}
	if name == pfctlPath && len(args) == 3 && args[0] == "-a" && args[1] == Anchor && args[2] == "-sr" {
		if r.failSR {
			return Result{}, errors.New("сбой чтения якоря")
		}
		return Result{Out: r.active}, nil
	}
	return r.base.Run(stdin, name, args...)
}

func ruleLinesOf(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func offRules() Rules { return Rules{Mode: "off", Text: headerMode + "off\n"} }

// onThenFaultyOff: on применён, затем Apply(off), у которого после успешной загрузки пустого якоря падает хвост.
func onThenFaultyOff(t *testing.T, fault func(f *fixture, r *anchorRunner)) (*anchorRunner, error) {
	t.Helper()
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run}
	f.b.run = r
	f.apply(onRules())
	fault(f, r)
	return r, f.b.Apply(offRules())
}

// Находка PR 3 р1, п. 2: запись .loaded упала после загрузки off — защита on должна вернуться, ошибка — остаться.
func TestApplyOffLateWriteFailureRestoresOn(t *testing.T) {
	r, err := onThenFaultyOff(t, func(f *fixture, r *anchorRunner) {
		r.afterLoad = func(text string) {
			if strings.HasPrefix(text, headerMode+"off") {
				_ = os.Mkdir(f.paths.loadedFile()+".tmp", 0o755) // .loaded.tmp — каталог: запись записи падает
			}
		}
	})
	if err == nil {
		t.Fatal("сбой хвоста Apply(off) — ошибка Apply")
	}
	if r.active != strings.Join(ruleLinesOf(onRules().Text), "\n") {
		t.Errorf("после сбоя off в якоре должен остаться прежний on-набор, получено %q", r.active)
	}
}

func TestApplyOffLateReadbackFailureRestoresOn(t *testing.T) {
	r, err := onThenFaultyOff(t, func(_ *fixture, r *anchorRunner) {
		r.afterLoad = func(text string) { r.failSR = strings.HasPrefix(text, headerMode+"off") }
	})
	if err == nil {
		t.Fatal("сбой чтения после загрузки off — ошибка Apply")
	}
	if r.active != strings.Join(ruleLinesOf(onRules().Text), "\n") {
		t.Errorf("после сбоя off в якоре должен остаться прежний on-набор, получено %q", r.active)
	}
}

// Прежний набор уже off (пустой якорь): сбой хвоста off оставляет прежний набор, блок не навязывается.
func TestApplyOffLateFailureAfterOffKeepsPreviousOff(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run}
	f.b.run = r
	f.apply(offRules())
	r.afterLoad = func(string) { r.failSR = true }
	if err := f.b.Apply(offRules()); err == nil || r.active != "" {
		t.Errorf("off → off со сбоем: ошибка и прежний пустой якорь, получено err=%v якорь %q", err, r.active)
	}
}

// Ни запись on, ни фактический прежний набор не загрузились обратно — последний рубеж: lo0 и блок всего.
func TestApplyOffLateFailureFallsBackToBlockAll(t *testing.T) {
	r, err := onThenFaultyOff(t, func(_ *fixture, r *anchorRunner) {
		r.afterLoad = func(text string) { r.failSR = strings.HasPrefix(text, headerMode+"off") }
		r.reject = func(text string) bool { return text != offRules().Text && text != blockAllText } // прежние наборы не грузятся
	})
	if err == nil || r.active != "pass out quick on lo0 all no state\nblock return out quick all" {
		t.Errorf("откат на блок всего: ошибка и lo0 + block, получено err=%v якорь %q", err, r.active)
	}
}

// Прежний on не дописал запись (упал сброс состояний) — запись говорит off, но в якоре on. Сбой хвоста следующего
// off должен вернуть фактический прежний набор, а не довериться записи.
func TestApplyOffLateFailureAfterUnfinishedOnRestoresProtection(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run}
	f.b.run = r
	f.apply(offRules())
	f.run.fails["pfctl -F states"] = true
	_ = f.b.Apply(onRules())
	f.run.fails["pfctl -F states"] = false
	r.afterLoad = func(text string) { r.failSR = strings.HasPrefix(text, headerMode+"off") }
	if err := f.b.Apply(offRules()); err == nil || r.active != strings.Join(ruleLinesOf(onRules().Text), "\n") {
		t.Errorf("сбой off после незавершённого on: ошибка и фактический прежний on, получено err=%v якорь %q", err, r.active)
	}
}

// Откат возвращает и отзыв состояний: в окне пустого якоря чужие keep-state правила могли открыть поток.
func TestApplyOffRollbackFlushesStates(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run}
	f.b.run = r
	f.apply(onRules())
	r.afterLoad = func(text string) { r.failSR = strings.HasPrefix(text, headerMode+"off") }
	_ = f.b.Apply(offRules())
	n := 0
	for _, c := range f.run.calls {
		if c == "pfctl -F states" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("сброс состояний: при on и после отката — 2 раза, получено %d", n)
	}
}

// Якорь до загрузки не читается и записи on нет — считаем, что защищал: откат на блок всего.
func TestApplyOffLateFailureWithUnreadablePriorBlocksAll(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run, failSR: true}
	f.b.run = r
	if err := f.b.Apply(offRules()); err == nil || r.active != "pass out quick on lo0 all no state\nblock return out quick all" {
		t.Errorf("нечитаемый прежний якорь: ошибка и блок всего, получено err=%v якорь %q", err, r.active)
	}
}

// После отката pf снова держит наш токен: чужая ссылка может исчезнуть и выключить pf.
func TestApplyOffRollbackRetakesOwnToken(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run}
	f.b.run = r
	f.apply(onRules())
	f.run.replies["pfctl -s References"] = []Result{{Out: refsForeign}}
	f.run.on("killswitchd -E", "Token : 18446744071234567899\n")
	r.afterLoad = func(text string) { r.failSR = strings.HasPrefix(text, headerMode+"off") }
	_ = f.b.Apply(offRules())
	if !f.run.called("killswitchd -E") {
		t.Errorf("откат без нашего токена: -E из копии pfctl, вызовы %q", f.run.calls)
	}
}

// Сбой токена при откате не отменяет сброс состояний.
func TestApplyOffRollbackFlushesEvenIfTokenFails(t *testing.T) {
	f := newFixture(t)
	f.healthy()
	r := &anchorRunner{base: f.run}
	f.b.run = r
	f.apply(onRules())
	f.run.fails["pfctl -s References"] = true
	r.afterLoad = func(text string) { r.failSR = strings.HasPrefix(text, headerMode+"off") }
	err := f.b.Apply(offRules())
	if err == nil || f.run.calls[len(f.run.calls)-1] != "pfctl -F states" {
		t.Errorf("сбой токена при откате: ошибка и всё равно -F states последним, получено err=%v вызовы %q", err, f.run.calls)
	}
}
