package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/backend"
	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
	"github.com/DuchitskyDA/killswitch/internal/state"
)

func TestOnAppliesAndCommitsGeneration(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("on"), exitOK)
	st := h.state()
	eq(t, st.Gen, uint64(1))
	eq(t, st.Mode, policy.ModeOn)
	eq(t, st.AppliedHash, backend.HashOf(*h.fb.Installed))
	eq(t, st.Intent == nil && st.BootID == "boot-1", true)
}

func TestEnforceSameBootKeepsOff(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.run("off")
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.state().Mode, policy.ModeOff)
	eq(t, h.installedMode(), policy.ModeOff)
	eq(t, len(h.fb.Applies), 2)
}

func TestEnforceNewBootFromOffGoesOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("off")
	h.fb.Env.BootID = "boot-2"
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.state().Mode, policy.ModeOn)
	eq(t, h.state().BootID, "boot-2")
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestEnforceNewBootFromRepairGoesOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	eq(t, h.run("repair"), exitOK)
	h.fb.Env.BootID = "boot-2"
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.state().Mode, policy.ModeOn)
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestFailedApplyLeavesIntentAndEnforceCompletesIt(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.ApplyErr = errors.New("transaction aborted")
	eq(t, h.run("off"), exitApply)
	eq(t, h.state().Intent.Target, policy.ModeOff)
	h.fb.ApplyErr = nil
	noErr(t, h.reconcile(env.HealthUnknown))
	st := h.state()
	eq(t, []any{st.Mode, st.Gen, st.Intent == nil, h.installedMode()}, []any{policy.ModeOff, uint64(2), true, policy.ModeOff})
}

func TestEnforceIntentAlreadyAppliedOnlyCommits(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.run("off")
	st := h.state()
	st.Intent = &state.Intent{Gen: st.Gen + 1, Target: policy.ModeOff, PlanHash: st.PlanHash}
	st.Mode = policy.ModeOn
	noErr(t, state.Save(filepath.Join(h.dir, state.FileName), st))
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.state().Mode, policy.ModeOff)
	eq(t, h.state().Intent == nil, true)
	eq(t, len(h.fb.Applies), 2)
}

func TestEnforceCorruptStateWithOurRulesGoesOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("off")
	h.writeState("{not json")
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.state().Mode, policy.ModeOn)
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestEnforceMissingStateWithOurRulesGoesOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("off")
	noErr(t, os.Remove(filepath.Join(h.dir, state.FileName)))
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestEnforceNothingInstalledDoesNothing(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, h.reconcile(env.HealthUnknown))
	_, err := os.Stat(filepath.Join(h.dir, state.FileName))
	eq(t, os.IsNotExist(err), true)
	eq(t, len(h.fb.Applies), 0)
}

func TestEnforceRestoresDrift(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.Tamper()
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, len(h.fb.Applies), 2)
	eq(t, h.state().AppliedHash, h.state().PlanHash)
	eq(t, h.state().Gen, uint64(2))
}

func TestEnforceNoChangeDoesNotApplyOrBumpGeneration(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, len(h.fb.Applies), 1)
	eq(t, h.state().Gen, uint64(1))
}

func TestEnforceReplansWhenHealthChanges(t *testing.T) {
	h := newHarness(t, tunnelUpConfig)
	h.run("on")
	noErr(t, h.reconcile(env.HealthUp))
	eq(t, len(h.fb.Applies), 2)
	eq(t, h.state().Mode, policy.ModeOn)
}

func TestEnforceBrokenConfigKeepsRules(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("off")
	h.fb.Env.BootID = "boot-2"
	noErr(t, os.WriteFile(filepath.Join(h.dir, "config.toml"), []byte("lan = "), 0o600))
	err := h.reconcile(env.HealthUnknown)
	eq(t, err != nil, true)
	eq(t, h.installedMode(), policy.ModeOff)
}

func TestUninstallWorksWithCorruptStateAndNoConfig(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.writeState("garbage")
	noErr(t, os.Remove(filepath.Join(h.dir, "config.toml")))
	eq(t, h.run("uninstall"), exitOK)
	_, err := os.Stat(filepath.Join(h.dir, state.FileName))
	eq(t, os.IsNotExist(err), true)
	eq(t, h.fb.Installed == nil, true)
}

func TestOnWithCorruptStateStartsFresh(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.writeState("garbage")
	eq(t, h.run("on"), exitOK)
	eq(t, h.state().Gen, uint64(1))
}

func TestOnKeepsLastKnownAddresses(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Env.Resolved = map[string][]netip.Addr{"vpn.example.org": {netip.MustParseAddr("203.0.113.2")}}
	h.run("on")
	h.fb.Env.Resolved = nil
	h.fb.Env.ResolveErr = map[string]string{"vpn.example.org": "timeout"}
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.state().LastKnown["vpn.example.org"], []netip.Addr{netip.MustParseAddr("203.0.113.2")})
}

func TestFirstInstallFailedApplyIsCompletedByEnforce(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.ApplyErr = errors.New("transaction aborted")
	eq(t, h.run("on"), exitApply)
	h.fb.ApplyErr = nil
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.installedMode(), policy.ModeOn)
	eq(t, h.state().Gen, uint64(1))
}

func TestEnforceReappliesOnRepairableStructural(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.Structural = []probe.StructuralFinding{{Kind: "pf-disabled", Repair: true}}
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, len(h.fb.Applies), 2)
	eq(t, len(h.fb.Structural), 0)
}

func TestEnforceDoesNotReapplyOnForeignStructural(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	h.fb.Structural = []probe.StructuralFinding{{Kind: "pf-quick-above-anchor"}}
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, len(h.fb.Applies), 1)
}

func TestOnAppliedSetDiffersFromPlanIsApplyError(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.ApplyDrifts = true
	eq(t, h.run("on"), exitApply)
}

func TestTransitionTakesSystemLock(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("on")
	eq(t, h.locks, 1)
}

func TestEnforceStepTakesSystemLock(t *testing.T) {
	h := newHarness(t, baseConfig)
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.locks, 1)
}

func TestHealthCheckTakesFreshSnapshot(t *testing.T) {
	h := newHarness(t, tunnelUpConfig)
	a := &app{d: h.deps(), b: h.fb, configPath: filepath.Join(h.dir, "config.toml")}
	p, err := a.loadPolicy(policy.ModeOn)
	noErr(t, err)
	a.healthChanged(context.Background(), health.NewMachine(), p)
	eq(t, h.fb.Snapshots, 1)
}

func TestFirstOffFailedThenRebootGoesOn(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.ApplyErr = errors.New("transaction aborted")
	eq(t, h.run("off"), exitApply)
	h.fb.ApplyErr = nil
	h.fb.Env.BootID = "boot-2"
	noErr(t, h.reconcile(env.HealthUnknown))
	eq(t, h.installedMode(), policy.ModeOn)
}

func TestEnforceWithoutBootIDFailsWithoutApplying(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.run("off")
	h.fb.Env.BootID = ""
	eq(t, h.reconcile(env.HealthUnknown) != nil, true)
	eq(t, len(h.fb.Applies), 1)
}

func TestOnWithoutBootIDIsApplyError(t *testing.T) {
	h := newHarness(t, baseConfig)
	h.fb.Env.BootID = ""
	eq(t, h.run("on"), exitApply)
	eq(t, len(h.fb.Applies), 0)
}
