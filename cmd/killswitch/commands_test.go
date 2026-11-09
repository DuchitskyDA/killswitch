package main

import (
	"context"
	"errors"
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

func TestRepairProgramsNotFoundIsConfigError(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Env.Programs = nil
	eq(t, h.run("repair"), exitConfig)
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

func TestCheckRulesRemovedIsLeak(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.prober.answered = true
	eq(t, h.run("check"), exitLeak)
}

func TestCheckWithoutTargetsIsInconclusive(t *testing.T) {
	h := newHarness(t, "profile = \"example\"\n")
	h.fb.Dropped = true
	eq(t, h.run("check"), exitInconclusive)
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
