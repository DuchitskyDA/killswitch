package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

func TestUnknownCommandIsConfigError(t *testing.T) {
	eq(t, newHarness(t, baseConfig).run("onn"), exitConfig)
}

func TestNoCommandIsConfigError(t *testing.T) {
	eq(t, newHarness(t, baseConfig).run(), exitConfig)
}

func TestBadConfigIsConfigError(t *testing.T) {
	h := newHarness(t, "lan = \"yes\"\n")
	eq(t, h.run("on"), exitConfig)
	eq(t, len(h.fb.Applies), 0)
}

func TestUnknownProfileIsConfigError(t *testing.T) {
	eq(t, newHarness(t, "profile = \"nope\"\n").run("on"), exitConfig)
}

func TestRepairOnLinuxIsConfigError(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Caps = policy.CapabilitiesFor("linux")
	eq(t, h.run("repair"), exitConfig)
}

// blockedExe — программа, закрытая в repair. Список repair задаёт конфиг: профили его не заполняют.
const blockedExe = `C:\Tools\blocked.exe`

const repairConfig = baseConfig + "[repair]\nprograms = ['" + blockedExe + "']\n"

func TestRepairProgramsNotFoundIsConfigError(t *testing.T) {
	h := newHarness(t, repairConfig)
	h.fb.Env.Programs = nil
	eq(t, h.run("repair"), exitConfig)
	eq(t, strings.Contains(h.err.String(), "не найдено ни одной программы"), true)
	eq(t, len(h.fb.Applies), 0)
}

func TestBackendNotImplementedIsApplyError(t *testing.T) {
	d := newHarness(t, baseConfig).deps()
	d.backend = func() (backend.Backend, error) { return nil, backend.ErrNotImplemented }
	eq(t, run(context.Background(), []string{"status"}, d), exitApply)
}

func TestPlanPrintsWithoutApplying(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("plan", "off"), exitOK)
	eq(t, strings.HasPrefix(h.out.String(), "mode=off tunnel=wg-example#7"), true)
	eq(t, len(h.fb.Applies), 0)
}

func TestStatusStructuralFindingIsLeak(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.Structural = []probe.StructuralFinding{{Kind: "wfp-tie", Detail: "provider X sublayer Y"}}
	eq(t, h.run("status"), exitLeak)
	eq(t, strings.Contains(h.out.String(), "LEAK wfp-tie"), true)
}

func TestStatusWarnsOnSeveralTunnelAdapters(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Env.Ifaces = append(h.fb.Env.Ifaces, env.Iface{Name: "wg-example", Index: 9, Up: true})
	h.run("on")
	eq(t, h.run("status"), exitOK)
	eq(t, strings.Contains(h.out.String(), "WARN шаблону туннеля соответствует больше одного"), true)
}

func TestCheckBlockedIsOK(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.Dropped = true
	eq(t, h.run("check"), exitOK)
	eq(t, strings.Contains(h.out.String(), "итог: BLOCKED"), true)
}

// Маршрут к цели через туннель — baseline по маршруту, без привязки к TUN (перенаправление клиента).
func TestCheckBaselineByRouteWhenRouteViaTunnel(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Env.Routes = map[netip.Addr]env.Route{netip.MustParseAddr("203.0.113.130"): {IfaceIndex: 7, ViaTunnel: true}}
	h.fb.Dropped = true
	eq(t, h.run("check"), exitOK)
	eq(t, h.prober.routed, len(probe.Services))
}

func TestCheckRulesRemovedIsLeak(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.prober.answered = true
	eq(t, h.run("check"), exitLeak)
}

// simpleCheck — check без своих адресов: простая проверка по сайту с адресом 203.0.113.10.
func simpleCheck(t *testing.T) *harness {
	h := newHarness(t, "profile = \"example\"\n")
	h.prober.resolved = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	return h
}

const simpleNote = "проверен только TCP; UDP и DNS не проверялись — для полной проверки задайте свои адреса"

// С физического адаптера ответа нет, обычным путём сайт отвечает: код 0 и честная оговорка.
func TestCheckSimpleNoLeakIsOKWithNote(t *testing.T) {
	h := simpleCheck(t)
	eq(t, h.run("check"), exitOK)
	out := h.out.String()
	eq(t, strings.Contains(out, "простая проверка: HTTP к example.com"), true)
	eq(t, strings.Contains(out, "BLOCKED Ethernet v4 http 203.0.113.10:80"), true)
	eq(t, strings.Contains(out, "утечек не найдено (простая проверка)\n"+simpleNote), true)
}

func TestCheckSimpleAnswerFromPhysicalIsLeak(t *testing.T) {
	h := simpleCheck(t)
	h.prober.answered = true
	eq(t, h.run("check"), exitLeak)
	out := h.out.String()
	eq(t, strings.Contains(out, "УТЕЧКА (простая проверка)"), true)
	eq(t, strings.Contains(out, "утечек не найдено"), false)
}

func TestCheckSimpleNoAnswerAnywhereIsInconclusiveWithReason(t *testing.T) {
	h := simpleCheck(t)
	h.prober.plainErr = errors.New("i/o timeout")
	eq(t, h.run("check"), exitInconclusive)
	out := h.out.String()
	eq(t, strings.Contains(out, "нет уверенности (простая проверка): ответа нет, но и обычным путём example.com не ответил: i/o timeout"), true)
	eq(t, strings.Contains(out, simpleNote), false)
}

// Свои адреса заданы — полная проверка, строк простой нет.
func TestCheckWithTargetsHasNoSimpleLines(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Dropped = true
	eq(t, h.run("check"), exitOK)
	eq(t, strings.Contains(h.out.String(), "простая проверка"), false)
}

func TestDetectFindsProfileByPath(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("detect"), exitOK)
	eq(t, h.out.String(), "example: "+wireguardExe+"\nwireguard: "+wireguardExe+"\n")
}

func TestStatusSnapshotFailureIsApplyError(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.SnapshotErr = errors.New("netlink down")
	eq(t, h.run("status"), exitApply)
}

func TestStatusWithoutConfigWarnsAndSucceeds(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, os.Remove(filepath.Join(h.dir, "config.toml")))
	eq(t, h.run("status"), exitOK)
	eq(t, strings.Contains(h.out.String(), "WARN туннель не проверен"), true)
}
