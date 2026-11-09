package windows

import (
	"os"

	"github.com/DuchitskyDA/killswitch/internal/state"
	"golang.org/x/sys/windows/svc"
)

// ServiceName — имя службы Windows (её регистрирует dist/windows/menu.ps1; ImagePath — `killswitch.exe enforce`).
const ServiceName = "killswitch"

// ServeIfService: процесс запущен SCM — отвечаем ему в фоне, а основной поток выполняет обычную команду (enforce).
// Stop/Shutdown: захват общего замка (Apply и запись state.json не обрываются посередине), затем выход;
// замок отпускает завершение процесса.
func ServeIfService() {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return
	}
	go func() {
		_ = svc.Run(ServiceName, handler{})
		os.Exit(0)
	}()
}

type handler struct{}

func (handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			_, _ = state.Acquire(state.LockName(""), true) // держим до выхода процесса
			return false, 0
		}
	}
	return false, 0
}
