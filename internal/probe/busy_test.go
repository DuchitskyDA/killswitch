package probe

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

// busyProber — порты из busy заняты (прошлая проверка оставила соединение в ожидании закрытия).
type busyProber struct {
	fakeProber
	busy func(port uint16) bool
}

func (b *busyProber) Direct(ctx context.Context, s Service, id ProbeID, iface env.Iface) (bool, error) {
	if b.busy(id.Src.Port()) {
		b.sent = append(b.sent, id)
		return false, fmt.Errorf("%w: bind: address already in use", ErrSourcePortBusy)
	}
	return b.fakeProber.Direct(ctx, s, id, iface)
}

// Занятый порт-источник — не повод для «нет уверенности»: проба уходит со следующего порта.
func TestBusySourcePortRetriesNextPort(t *testing.T) {
	p := &busyProber{busy: func(port uint16) bool { return port == SrcPortFirst }}
	ev := &finishingEvidence{dropped: true}
	res := finishRun(p, ev)
	eq(t, res.Overall, Blocked)
	eq(t, strings.Contains(res.Probes[0].Detail, fmt.Sprint(SrcPortFirst+1)), true)
	eq(t, len(p.sent), len(Services)+1)
	eq(t, len(ev.finished), len(Services)+1)
}

// Заняты все попытки: проба не уходила — «нет уверенности», число попыток ограничено.
func TestBusySourcePortGivesUpAfterAttempts(t *testing.T) {
	p := &busyProber{busy: func(uint16) bool { return true }}
	ev := &finishingEvidence{dropped: true}
	res := finishRun(p, ev)
	eq(t, res.Overall, Inconclusive)
	eq(t, strings.Contains(res.Probes[0].Detail, "проба не отправлена"), true)
	eq(t, len(p.sent), len(Services)*srcPortAttempts)
	eq(t, len(ev.finished), len(Services)*srcPortAttempts)
}
