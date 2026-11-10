package darwin

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// watchInterval — опрос наблюдателя macOS (событий смены интерфейсов нет, опрос 10 с).
const watchInterval = 10 * time.Second

// Changes — событие, когда изменился отпечаток: интерфейсы, pf Enabled, правила якоря, основной набор, токены.
// Шаг enforce сам решает, нужно ли что-то менять; пропущенное событие подберёт полный пересчёт ядра.
func (b *Backend) Changes() <-chan struct{} {
	b.watchOnce.Do(func() {
		b.changes = make(chan struct{}, 1)
		go b.watch()
	})
	return b.changes
}

func (b *Backend) watch() {
	prev := b.fingerprint()
	t := time.NewTicker(watchInterval)
	defer t.Stop()
	for range t.C {
		cur := b.fingerprint()
		if cur == prev {
			continue
		}
		prev = cur
		select {
		case b.changes <- struct{}{}:
		default:
		}
	}
}

func (b *Backend) fingerprint() string {
	var sb strings.Builder
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			fmt.Fprintf(&sb, "%s/%d/%v/%v;", i.Name, i.Index, i.Flags, addrs)
		}
	}
	info, _ := b.pf("", "-s", "info")
	fmt.Fprintf(&sb, "\nenabled=%t\n", pfEnabled(info))
	anchor, _ := b.pf("", "-a", Anchor, "-sr")
	main, _ := b.pf("", "-sr")
	sb.WriteString(anchor + "\n" + main + "\n")
	refs, _ := b.pf("", "-s", "References")
	for _, r := range parseReferences(refs) {
		sb.WriteString(r.Token + ";")
	}
	return sb.String()
}
