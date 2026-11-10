package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// setup — запуск с рабочего стола (двойной клик) или killswitch setup: права администратора, установка
// в систему, затем окно. Консоль при этом свёрнута или закрывается сразу — ошибку показывает alert.
func (a *app) setup(ctx context.Context) error {
	err := a.installThenWindow(ctx)
	if err != nil && a.d.alert != nil {
		a.d.alert(err.Error())
	}
	return err
}

func (a *app) installThenWindow(ctx context.Context) error {
	if a.d.admin == nil || !a.d.admin() {
		if err := a.ownConfigOnly("setup"); err != nil {
			return err
		}
		return a.needAdmin("setup", "установка продолжится в окне с правами администратора")
	}
	if err := a.install(); err != nil {
		return err
	}
	return a.window(ctx)
}

// install — killswitch install: установка в систему без окна (терминал, CI). ОС без установки — ничего.
func (a *app) install() error {
	if a.d.admin == nil || !a.d.admin() {
		if err := a.ownConfigOnly("install"); err != nil {
			return err
		}
		return a.needAdmin("install", "установка продолжится с правами администратора")
	}
	if a.d.installSelf == nil {
		return nil
	}
	if err := a.d.installSelf(a.enableIfConfigured); err != nil {
		code := exitApply
		var ce cliError
		if errors.As(err, &ce) {
			code = ce.code
		}
		return cliError{code: code, err: fmt.Errorf("установка: %w", err)}
	}
	fmt.Fprintln(a.d.out, "killswitch установлен: служба, ярлык окна на рабочем столе, запись в «Приложения»")
	return nil
}

// enableIfConfigured — настройки уже есть (прежняя установка или -config): защита включается сразу, тем же
// путём, что команда on; настроек нет — их задают в окне.
func (a *app) enableIfConfigured() error {
	if _, err := os.Stat(a.configPath); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	b, err := a.d.backend()
	if err != nil {
		return fail(exitApply, "%v", err)
	}
	a.b = b
	return a.transition(policy.ModeOn)
}

// ownConfigOnly: перезапуск с повышением получает только команду — чужой -config он бы молча потерял.
func (a *app) ownConfigOnly(command string) error {
	if filepath.Clean(a.configPath) == filepath.Clean(filepath.Join(a.d.dir, "config.toml")) {
		return nil
	}
	return fail(exitConfig, "-config при повышении прав не передаётся: запустите killswitch -config <путь> %s "+
		"из терминала администратора", command)
}
