package windows

import (
	"sync"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	xwin "golang.org/x/sys/windows"
)

var _ backend.Watcher = (*Backend)(nil)

// Подписка NotifyIpInterfaceChange одна на процесс: событие смены интерфейса → сигнал enforce (буфер 1, без потерь
// смысла: несколько событий подряд дают один пересчёт).
var (
	watchOnce   sync.Once
	watchCh     = make(chan struct{}, 1)
	watchHandle xwin.Handle
	watchCb     = xwin.NewCallback(func(ctx, row, kind uintptr) uintptr {
		select {
		case watchCh <- struct{}{}:
		default:
		}
		return 0
	})
)

// Changes — события смены интерфейсов; подписка создаётся при первом вызове. Ошибка подписки — канал без событий:
// enforce всё равно пересчитывает раз в 60 с.
func (b *Backend) Changes() <-chan struct{} {
	watchOnce.Do(func() {
		_ = xwin.NotifyIpInterfaceChange(xwin.AF_UNSPEC, watchCb, nil, false, &watchHandle)
	})
	return watchCh
}
