//go:build linux

package helper

import (
	"context"
	"os"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

type fakeSandboxHost struct {
	facts    agentSandboxFacts
	installs int
	restores int
}

func (h *fakeSandboxHost) Inspect(context.Context) (agentSandboxFacts, error) { return h.facts, nil }
func (h *fakeSandboxHost) Install(context.Context) error {
	h.installs++
	h.facts.DropInExists = true
	h.facts.DropInDigest = sandboxManagedDigest()
	h.facts.StateWritable = true
	h.facts.StagingWritable = true
	return nil
}
func (h *fakeSandboxHost) Restore(_ context.Context, snapshot agentSandboxFacts) error {
	h.restores++
	h.facts = snapshot
	return nil
}

func TestAgentSandboxActionPlansAppliesAndRollsBackExactDropIn(t *testing.T) {
	journalDir := t.TempDir()
	if err := os.Chmod(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(journalDir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeSandboxHost{facts: agentSandboxFacts{Unit: agentUnitName, LoadState: "loaded", Active: true, DropInContent: []byte{}}}
	action, err := newAgentSandboxAction("nginx", journal, host)
	if err != nil {
		t.Fatal(err)
	}
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionRepairAgentSandboxPaths, LogicalTarget: helperprotocol.LogicalTargetAgentUnit, DiagnosticReference: "diagnostic-1"}
	plan, err := action.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeSystemdSandboxDenied, "nginx", "systemd_sandbox", nil)
	if plan.ResourceFingerprint != want || plan.RollbackCoverage != helperprotocol.RollbackCoveragePartial {
		t.Fatalf("plan = %+v", plan)
	}
	helperPlan := helperprotocol.HelperPlan{Action: request.Action, ExecutionPlanHash: plan.ExecutionPlanHash}
	prepared, err := action.Prepare(context.Background(), "operation-1", helperPlan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := action.Execute(context.Background(), "operation-1", helperPlan, prepared)
	if err != nil || !result.Mutated || !result.Validated || host.installs != 1 {
		t.Fatalf("execute = %+v, %v installs=%d", result, err, host.installs)
	}
	if err := action.Rollback(context.Background(), "operation-1", helperPlan, prepared); err != nil || host.restores != 1 || host.facts.DropInExists {
		t.Fatalf("rollback err=%v restores=%d facts=%+v", err, host.restores, host.facts)
	}
}

func TestAgentSandboxActionRefusesAlreadySatisfiedOrForeignDropIn(t *testing.T) {
	journalDir := t.TempDir()
	if err := os.Chmod(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(journalDir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionRepairAgentSandboxPaths, LogicalTarget: helperprotocol.LogicalTargetAgentUnit, DiagnosticReference: "diagnostic-1"}
	for name, facts := range map[string]agentSandboxFacts{
		"satisfied": {Unit: agentUnitName, LoadState: "loaded", Active: true, DropInExists: true, DropInDigest: sandboxManagedDigest(), StateWritable: true, StagingWritable: true},
		"foreign":   {Unit: agentUnitName, LoadState: "loaded", Active: true, DropInExists: true, DropInDigest: "foreign"},
	} {
		t.Run(name, func(t *testing.T) {
			action, _ := newAgentSandboxAction("nginx", journal, &fakeSandboxHost{facts: facts})
			if _, err := action.Plan(context.Background(), request); err == nil {
				t.Fatal("unsafe or stale sandbox repair was planned")
			}
		})
	}
}
