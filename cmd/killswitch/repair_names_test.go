package main

import (
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Починка по именам: node найден (снимок backend), ghost — нет.
const namesConfig = baseConfig + "[repair]\nnames = ['node', 'ghost']\n"

const nodeExe = `C:\Program Files\nodejs\node.exe`

func foundNode(h *harness, ids ...string) {
	h.fb.Env.Programs[backend.NameKey("node")] = ids
	h.fb.Env.Programs[backend.NameFilesKey("node")] = []string{nodeExe}
}

func TestRepairNameNotFoundWarnsAndContinues(t *testing.T) {
	h := newHarness(t, namesConfig)
	foundNode(h, "node-1")
	eq(t, h.run("repair"), exitOK)
	eq(t, strings.Contains(h.err.String(), `WARN repair: по имени "ghost" программа не найдена`), true)
	eq(t, strings.Contains(h.err.String(), `"node"`), false)
	eq(t, h.installedMode(), policy.ModeRepair)
}

func TestRepairNoFileByAnyNameIsConfigError(t *testing.T) {
	h := newHarness(t, namesConfig)
	eq(t, h.run("repair"), exitConfig)
	eq(t, strings.Contains(h.err.String(), "не найдено ни одной программы"), true)
	eq(t, len(h.fb.Applies), 0)
}

func TestRepairProgramsFoundNamesMissingContinues(t *testing.T) {
	h := newHarness(t, baseConfig+"[repair]\nprograms = ['"+blockedExe+"']\nnames = ['ghost']\n")
	h.fb.Env.Programs[blockedExe] = []string{blockedExe}
	eq(t, h.run("repair"), exitOK)
	eq(t, h.installedMode(), policy.ModeRepair)
}

// Шаблон пути без файлов — ошибка, как раньше, даже когда по имени программа найдена.
func TestRepairProgramsGlobNotFoundStaysConfigErrorWithNames(t *testing.T) {
	h := newHarness(t, baseConfig+"[repair]\nprograms = ['"+blockedExe+"']\nnames = ['node']\n")
	foundNode(h, "node-1")
	eq(t, h.run("repair"), exitConfig)
	eq(t, len(h.fb.Applies), 0)
}

func TestPlanRepairShowsFilesFoundByName(t *testing.T) {
	h := newHarness(t, namesConfig)
	foundNode(h, "node-1")
	eq(t, h.run("plan", "repair"), exitOK)
	eq(t, strings.Contains(h.out.String(), "починка: node — "+nodeExe+"\n"), true)
	eq(t, strings.Contains(h.out.String(), "починка: ghost — не найдено\n"), true)
	eq(t, len(h.fb.Applies), 0)
}

func TestPlanOnDoesNotListRepairNames(t *testing.T) {
	h := newHarness(t, namesConfig)
	foundNode(h, "node-1")
	eq(t, h.run("plan", "on"), exitOK)
	eq(t, strings.Contains(h.out.String(), "починка:"), false)
}

func TestStatusShowsFilesFoundByName(t *testing.T) {
	h := newHarness(t, namesConfig)
	foundNode(h, "node-1")
	h.run("on")
	h.out.Reset()
	eq(t, h.run("status"), exitOK)
	eq(t, strings.Contains(h.out.String(), "починка: node — "+nodeExe+"\n"), true)
	eq(t, strings.Contains(h.out.String(), "починка: ghost — не найдено\n"), true)
}

// Программа с тем же именем запущена из нового места — шаг службы переприменяет починку с новым файлом.
func TestEnforceReappliesRepairWhenNamedProgramAppears(t *testing.T) {
	h := newHarness(t, namesConfig)
	foundNode(h, "node-1")
	eq(t, h.run("repair"), exitOK)
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, len(h.fb.Applies), 1)
	foundNode(h, "node-1", "node-2")
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, len(h.fb.Applies), 2)
	eq(t, strings.Contains(h.fb.Installed.Text, "node-2"), true)
}

func TestMenuRunningListsBackendPrograms(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Running = []backend.Program{{Name: "node", Path: nodeExe}}
	got, err := h.actions().Running()
	noErr(t, err)
	eq(t, got, h.fb.Running)
}
