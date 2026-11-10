package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Тесты установки с рабочего стола: установка в систему — заглушка, окно — как в window_test.

func (h *harness) setupDeps(installed *[]string, browser func(string) error) deps {
	d := h.windowDeps(browser)
	d.terminal = func() bool { return false }
	d.desktop = func() bool { return true }
	d.installSelf = func(enable func() error) error {
		*installed = append(*installed, "install")
		return enable()
	}
	d.alert = func(msg string) { *installed = append(*installed, "alert: "+msg) }
	return d
}

func TestDesktopLaunchInstallsThenOpensWindow(t *testing.T) {
	h := newHarness(t, baseConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var steps []string
	d := h.setupDeps(&steps, func(string) error { steps = append(steps, "window"); cancel(); return nil })
	eq(t, run(ctx, nil, d), exitOK)
	eq(t, steps, []string{"install", "window"})
}

func TestDesktopLaunchWithoutAdminElevatesSetup(t *testing.T) {
	h := newHarness(t, baseConfig)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { t.Error("окно без прав"); return nil })
	d.admin = func() bool { return false }
	var asked []string
	d.elevate = func(command string) error { asked = append(asked, command); return nil }
	eq(t, run(context.Background(), nil, d), exitOK)
	eq(t, asked, []string{"setup"})
	eq(t, steps, []string(nil))
}

func TestSetupElevationRefusedIsShown(t *testing.T) {
	h := newHarness(t, baseConfig)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { t.Error("окно без прав"); return nil })
	d.admin = func() bool { return false }
	d.elevate = func(string) error { return errors.New("отменено пользователем") }
	eq(t, run(context.Background(), nil, d), exitConfig)
	eq(t, len(steps), 1)
	eq(t, strings.Contains(steps[0], "отменено пользователем"), true)
}

func TestSetupFailureIsShownAndWindowStaysClosed(t *testing.T) {
	h := newHarness(t, baseConfig)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { t.Error("окно после неудачной установки"); return nil })
	d.installSelf = func(func() error) error { return errors.New("небезопасный каталог: X") }
	eq(t, run(context.Background(), []string{"setup"}, d), exitApply)
	eq(t, steps, []string{"alert: установка: небезопасный каталог: X"})
}

func TestInstallWithSettingsTurnsProtectionOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { t.Error("install открыл окно"); return nil })
	eq(t, run(context.Background(), []string{"install"}, d), exitOK)
	eq(t, steps, []string{"install"})
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestInstallWithoutSettingsLeavesProtectionOff(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, os.Remove(h.configPath()))
	var steps []string
	d := h.setupDeps(&steps, func(string) error { t.Error("install открыл окно"); return nil })
	eq(t, run(context.Background(), []string{"install"}, d), exitOK)
	eq(t, len(h.fb.Applies), 0)
}

// Повторная установка (обновление, второй двойной клик) режим не меняет: on — только при первой установке.
func TestReinstallKeepsRecordedMode(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("off"), exitOK)
	applies := len(h.fb.Applies)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { t.Error("install открыл окно"); return nil })
	eq(t, run(context.Background(), []string{"install"}, d), exitOK)
	eq(t, steps, []string{"install"})
	eq(t, len(h.fb.Applies), applies)
	eq(t, h.state().Mode, policy.ModeOff)
}

func TestInstallOverCorruptStateTurnsProtectionOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.writeState(`{"gen": 3, "mode": "off", broken`)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { return nil })
	eq(t, run(context.Background(), []string{"install"}, d), exitOK)
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestReinstallWithForeignConfigAdoptsItAndKeepsMode(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("off"), exitOK)
	chosen := "lan = false\n" + baseConfig
	other := filepath.Join(t.TempDir(), "chosen.toml")
	noErr(t, os.WriteFile(other, []byte(chosen), 0o600))
	var steps []string
	d := h.setupDeps(&steps, func(string) error { return nil })
	eq(t, run(context.Background(), []string{"-config", other, "install"}, d), exitOK)
	eq(t, h.config(), chosen)
	eq(t, h.state().Mode, policy.ModeOff)
}

// Незавершённый переход (сбой между Apply и фиксацией) чужой -config не отменяет: доводится до цели намерения.
func TestReinstallWithForeignConfigFinishesPendingIntent(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.writeState(`{"gen": 1, "mode": "off", "boot_id": "boot-1", "plan_hash": "", "applied_hash": "",
		"anchor_ok": false, "intent": {"gen": 2, "target": "on", "plan_hash": "x"}, "updated_at": "2026-11-09T12:00:00Z"}`)
	other := filepath.Join(t.TempDir(), "chosen.toml")
	noErr(t, os.WriteFile(other, []byte(baseConfig), 0o600))
	var steps []string
	d := h.setupDeps(&steps, func(string) error { return nil })
	eq(t, run(context.Background(), []string{"-config", other, "install"}, d), exitOK)
	eq(t, h.state().Mode, policy.ModeOn)
}

func TestInstallBrokenSettingsFailsInstall(t *testing.T) {
	h := newHarness(t, "lan = ")
	var steps []string
	d := h.setupDeps(&steps, func(string) error { return nil })
	eq(t, run(context.Background(), []string{"install"}, d), exitConfig)
	eq(t, len(h.fb.Applies), 0)
}

func TestTerminalLaunchStillOpensMenu(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.menuDeps("0")
	d.desktop = func() bool { return false }
	d.installSelf = func(func() error) error {
		t.Error("установка из терминала без команды")
		return nil
	}
	eq(t, run(context.Background(), nil, d), exitOK)
}

func TestUninstallRemovesInstallAroundRules(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	d := h.deps()
	var steps []string
	d.uninstallSelf = func(removeRules func() error) error {
		steps = append(steps, "service")
		if err := removeRules(); err != nil {
			return err
		}
		steps = append(steps, "files")
		return nil
	}
	locks := h.locks
	eq(t, run(context.Background(), []string{"uninstall"}, d), exitOK)
	eq(t, steps, []string{"service", "files"})
	eq(t, h.fb.Installed == nil, true)
	eq(t, h.locks, locks+1)
}

func TestUninstallRulesFailureKeepsInstall(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.RemoveErr = errors.New("WFP недоступен")
	d := h.deps()
	var gotErr error
	d.uninstallSelf = func(removeRules func() error) error { gotErr = removeRules(); return gotErr }
	eq(t, run(context.Background(), []string{"uninstall"}, d), exitApply)
	eq(t, gotErr != nil, true)
}

func TestUninstallElevatesWhereElevationExists(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	d := h.deps()
	d.admin = func() bool { return false }
	var asked []string
	d.elevate = func(command string) error { asked = append(asked, command); return nil }
	eq(t, run(context.Background(), []string{"uninstall"}, d), exitOK)
	eq(t, asked, []string{"uninstall"})
	eq(t, h.fb.Removes, 0)
}

func TestInstallWithForeignConfigNeedsAdminTerminal(t *testing.T) {
	h := newHarness(t, baseConfig)
	var steps []string
	d := h.setupDeps(&steps, func(string) error { return nil })
	d.admin = func() bool { return false }
	d.elevate = func(string) error { t.Error("повышение потеряло бы -config"); return nil }
	other := filepath.Join(t.TempDir(), "chosen.toml")
	eq(t, run(context.Background(), []string{"-config", other, "install"}, d), exitConfig)
	eq(t, strings.Contains(h.err.String(), "-config при повышении прав не передаётся"), true)
}

func TestInstallWithForeignConfigAdoptsIt(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, os.Remove(h.configPath()))
	other := filepath.Join(t.TempDir(), "chosen.toml")
	noErr(t, os.WriteFile(other, []byte(baseConfig), 0o600))
	var steps []string
	d := h.setupDeps(&steps, func(string) error { return nil })
	eq(t, run(context.Background(), []string{"-config", other, "install"}, d), exitOK)
	eq(t, h.installedMode(), policy.ModeOn)
	eq(t, h.config(), baseConfig)
}

// Меню, перезапущенное с повышением в новой консоли, — команда menu: двойным кликом оно не считается.
func TestElevatedMenuCommandOpensMenuNotSetup(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.menuDeps("0")
	d.desktop = func() bool { return true }
	d.installSelf = func(func() error) error { t.Error("меню открыло установку"); return nil }
	eq(t, run(context.Background(), []string{"menu"}, d), exitOK)
}
