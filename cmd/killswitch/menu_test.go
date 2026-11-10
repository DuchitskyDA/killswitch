package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/state"
)

// Тесты меню — только на фейковом backend и во временном каталоге: права и повышение — заглушки.

const lanOffConfig = "lan = false\n" + baseConfig

func (h *harness) menuDeps(input ...string) deps {
	d := h.deps()
	d.in = strings.NewReader(strings.Join(input, "\n") + "\n")
	d.terminal = func() bool { return true }
	d.admin = func() bool { return true }
	return d
}

func (h *harness) runMenu(input ...string) int {
	return run(context.Background(), nil, h.menuDeps(input...))
}

func (h *harness) actions() *menuActions {
	return &menuActions{a: &app{d: h.menuDeps(), b: h.fb, configPath: h.configPath()}}
}

func (h *harness) configPath() string { return filepath.Join(h.dir, "config.toml") }

func (h *harness) config() string {
	h.t.Helper()
	data, err := os.ReadFile(h.configPath())
	noErr(h.t, err)
	return string(data)
}

func TestMenuWithoutTerminalPrintsUsage(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.menuDeps()
	d.terminal = func() bool { return false }
	eq(t, run(context.Background(), nil, d), exitConfig)
	eq(t, strings.Contains(h.err.String(), "использование"), true)
}

func TestMenuWithoutRootRefuses(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.menuDeps("1", "0")
	d.admin = func() bool { return false }
	eq(t, run(context.Background(), nil, d), exitConfig)
	eq(t, strings.Contains(h.err.String(), "запустите sudo killswitch"), true)
	eq(t, h.fb.Snapshots, 0)
}

func TestMenuElevatesWhenNotAdmin(t *testing.T) {
	h := newHarness(t, baseConfig)
	d, calls := h.menuDeps("1", "0"), 0
	d.admin = func() bool { return false }
	d.elevate = func() error { calls++; return nil }
	eq(t, run(context.Background(), nil, d), exitOK)
	eq(t, calls, 1)
	eq(t, len(h.fb.Applies), 0)
}

func TestMenuElevationRefusedIsError(t *testing.T) {
	h := newHarness(t, baseConfig)
	d := h.menuDeps()
	d.admin = func() bool { return false }
	d.elevate = func() error { return errors.New("отменено пользователем") }
	eq(t, run(context.Background(), nil, d), exitConfig)
}

func TestMenuOnAppliesFromMainScreen(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.runMenu("1", "0"), exitOK)
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestMenuOnWithoutConfigAsksForSettings(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, os.Remove(h.configPath()))
	h.runMenu("1", "0")
	eq(t, strings.Contains(h.out.String(), "нет настроек — откройте «Настройки»"), true)
	eq(t, len(h.fb.Applies), 0)
}

func TestMenuHeaderShowsModeAndTunnel(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	hd := h.actions().Header()
	eq(t, hd.Mode, policy.ModeOn)
	eq(t, len(hd.Tunnels), 1)
	eq(t, hd.Tunnels[0].Up, true)
}

func TestMenuHeaderShowsStructuralLeak(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Structural = []probe.StructuralFinding{{Kind: "wfp-tie", Detail: "чужой permit"}}
	eq(t, h.actions().Header().Notes, []string{"LEAK wfp-tie: чужой permit"})
}

func TestSaveInvalidConfigKeepsFile(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	_, err := h.actions().Save([]byte("trust_mode = \"strict\"\n" + baseConfig))
	eq(t, strings.HasPrefix(fmt.Sprint(err), "не сохранено: trust_mode = strict"), true)
	eq(t, h.config(), baseConfig)
	eq(t, len(h.fb.Applies), 1)
}

func TestSavePlanErrorKeepsFile(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	h.fb.PlanErr = errors.New("план не собран")
	_, err := h.actions().Save([]byte(lanOffConfig))
	eq(t, err != nil, true)
	eq(t, h.config(), baseConfig)
}

func TestSaveAppliesCurrentMode(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	eq(t, h.run("off"), exitOK)
	_, err := h.actions().Save([]byte(lanOffConfig))
	noErr(t, err)
	eq(t, h.config(), lanOffConfig)
	eq(t, h.installedMode(), policy.ModeOff)
	eq(t, strings.Contains(h.fb.Installed.Text, "lan=false"), true)
	tmp, _ := filepath.Glob(filepath.Join(h.dir, "*.tmp"))
	eq(t, len(tmp), 0)
}

func TestSaveWithoutInstallOnlyWrites(t *testing.T) {
	h := newHarness(t, baseConfig)
	msg, err := h.actions().Save([]byte(lanOffConfig))
	noErr(t, err)
	eq(t, h.config(), lanOffConfig)
	eq(t, len(h.fb.Applies), 0)
	eq(t, strings.Contains(msg, "защита не включена"), true)
}

func TestSaveApplyFailureSaysSavedNotApplied(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	h.fb.ApplyErr = errors.New("транзакция отклонена")
	saved, err := h.actions().Save([]byte(lanOffConfig))
	eq(t, saved, "сохранено, но не применено")
	eq(t, strings.HasPrefix(fmt.Sprint(err), "применение on"), true)
	eq(t, h.config(), lanOffConfig)
}

func TestMenuSettingsSaveEndToEnd(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	eq(t, h.runMenu("5", "2", "8", "0", "0"), exitOK)
	c, err := policy.ParseConfig([]byte(h.config()))
	noErr(t, err)
	eq(t, *c.LAN, false)
	eq(t, h.installedMode(), policy.ModeOn)
	eq(t, strings.Contains(h.fb.Installed.Text, "lan=false"), true)
}

func TestSaveKeepsRepair(t *testing.T) {
	h := newHarness(t, repairConfig)
	h.fb.Env.Programs[blockedExe] = []string{blockedExe}
	eq(t, h.run("repair"), exitOK)
	_, err := h.actions().Save([]byte("lan = false\n" + repairConfig))
	noErr(t, err)
	eq(t, h.installedMode(), policy.ModeRepair)
}

func TestSaveFinishesPendingIntent(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("off"), exitOK)
	st := h.state()
	st.Intent = &state.Intent{Gen: st.Gen + 1, Target: policy.ModeOn}
	noErr(t, state.Save(filepath.Join(h.dir, state.FileName), st))
	_, err := h.actions().Save([]byte(lanOffConfig))
	noErr(t, err)
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestSaveAfterRebootAppliesOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("off"), exitOK)
	h.fb.Env.BootID = "boot-2" // off — до перезагрузки
	_, err := h.actions().Save([]byte(lanOffConfig))
	noErr(t, err)
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestSaveChoosesAndAppliesUnderOneLock(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	m, locks, snapsAtLock := h.actions(), 0, -1
	m.a.d.lock = func(string) (func(), error) { locks, snapsAtLock = locks+1, h.fb.Snapshots; return func() {}, nil }
	before := h.fb.Snapshots
	_, err := m.Save([]byte(lanOffConfig))
	noErr(t, err)
	eq(t, locks, 1)
	eq(t, snapsAtLock, before) // режим выбран уже под замком
}

func TestMenuDetectFindsInstalledProfile(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.actions().Detect(), []string{"example", "wireguard"}) // оба профиля ищут wireguard.exe
}

func TestSaveWithoutInstallPlanErrorKeepsFile(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.PlanErr = errors.New("план не собран")
	_, err := h.actions().Save([]byte(lanOffConfig))
	eq(t, strings.HasPrefix(fmt.Sprint(err), "не сохранено: план"), true)
	eq(t, h.config(), baseConfig)
}
