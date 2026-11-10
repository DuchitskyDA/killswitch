package windows

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	wfp "github.com/DuchitskyDA/killswitch/internal/backend/windows"
)

const serviceDescription = "killswitch: наблюдатель правил (enforce)"

// serviceStopTimeout — сколько ждать остановки: обработчик Stop сначала дожидается общего замка.
const serviceStopTimeout = 60 * time.Second

// withService открывает службу; её нет — fn не вызывается, nil.
func withService(fn func(s *mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("диспетчер служб: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(wfp.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}

// stopService останавливает службу и ждёт остановки; её нет или она стоит — nil.
func stopService() error {
	return withService(func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) &&
			!errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
			return fmt.Errorf("служба %s не остановлена: %w", wfp.ServiceName, err)
		}
		for deadline := time.Now().Add(serviceStopTimeout); ; time.Sleep(200 * time.Millisecond) {
			if st, err = s.Query(); err != nil {
				return err
			}
			if st.State == svc.Stopped {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("служба %s не остановилась за %s", wfp.ServiceName, serviceStopTimeout)
			}
		}
	})
}

// deleteService останавливает и удаляет службу; её нет — nil.
func deleteService() error {
	if err := stopService(); err != nil {
		return err
	}
	return withService(func(s *mgr.Service) error {
		if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("служба %s не удалена: %w", wfp.ServiceName, err)
		}
		return nil
	})
}

// ensureService — служба `"<exe>" enforce`: запуск автоматический, при сбое — перезапуск через 5 с трижды;
// есть — путь и запуск обновляются. Затем служба запускается.
func ensureService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("диспетчер служб: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(wfp.ServiceName)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		s, err = m.CreateService(wfp.ServiceName, exe, mgr.Config{StartType: mgr.StartAutomatic,
			DisplayName: wfp.ServiceName, Description: serviceDescription}, "enforce")
		if err != nil {
			return fmt.Errorf("служба %s не создана: %w", wfp.ServiceName, err)
		}
	case err != nil:
		return err
	default:
		c, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		c.BinaryPathName = syscall.EscapeArg(exe) + " enforce"
		c.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(c); err != nil {
			s.Close()
			return fmt.Errorf("служба %s не обновлена: %w", wfp.ServiceName, err)
		}
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 0); err != nil {
		return fmt.Errorf("перезапуск службы %s не задан: %w", wfp.ServiceName, err)
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("служба %s не запущена: %w", wfp.ServiceName, err)
	}
	return nil
}
