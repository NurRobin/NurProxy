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

type fakeManagedAccessHost struct {
	facts    managedAccessFacts
	repaired int
	restored int
}

func (h *fakeManagedAccessHost) Inspect() (managedAccessFacts, error) { return h.facts, nil }
func (h *fakeManagedAccessHost) Repair(uid, gid uint32, mode uint32) error {
	h.repaired++
	h.facts.UID, h.facts.GID, h.facts.Mode = uid, gid, mode
	return nil
}
func (h *fakeManagedAccessHost) Restore(snapshot managedAccessFacts) error {
	h.restored++
	h.facts = snapshot
	return nil
}

func TestManagedAccessActionRepairsOnlyExclusiveStagingDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	journal, err := NewJournal(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeManagedAccessHost{facts: managedAccessFacts{Path: agentHelperStageDir, Exists: true, Directory: true, UID: 0, GID: 0, Mode: 0o700}}
	action, err := newManagedAccessAction("nginx", 1001, journal, host)
	if err != nil {
		t.Fatal(err)
	}
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionRepairManagedPathAccess, LogicalTarget: helperprotocol.LogicalTargetManagedPath, DiagnosticReference: "diagnostic-1"}
	material, err := action.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodePermissionDenied, "nginx", "permission_denied", nil)
	if material.ResourceFingerprint != want {
		t.Fatalf("fingerprint = %s, want %s", material.ResourceFingerprint, want)
	}
	plan := helperprotocol.HelperPlan{Action: request.Action, ExecutionPlanHash: material.ExecutionPlanHash}
	prepared, err := action.Prepare(context.Background(), "operation-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := action.Execute(context.Background(), "operation-1", plan, prepared)
	if err != nil || !result.Validated || host.facts.GID != 1001 || host.facts.Mode != 0o770 {
		t.Fatalf("execute = %+v, %v facts=%+v", result, err, host.facts)
	}
	if err := action.Rollback(context.Background(), "operation-1", plan, prepared); err != nil || host.restored != 1 || host.facts.Mode != 0o700 {
		t.Fatalf("rollback err=%v facts=%+v", err, host.facts)
	}
}

func TestManagedAccessActionRefusesNonExclusiveOrAlreadyCorrectTarget(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	journal, _ := NewJournal(dir, uint32(os.Getuid()))
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionRepairManagedPathAccess, LogicalTarget: helperprotocol.LogicalTargetManagedPath, DiagnosticReference: "diagnostic-1"}
	for name, facts := range map[string]managedAccessFacts{
		"shared":  {Path: "/etc/nginx/sites-available", Exists: true, Directory: true, UID: 0, GID: 1001, Mode: 0o770},
		"correct": {Path: agentHelperStageDir, Exists: true, Directory: true, UID: 0, GID: 1001, Mode: 0o770},
	} {
		t.Run(name, func(t *testing.T) {
			action, _ := newManagedAccessAction("nginx", 1001, journal, &fakeManagedAccessHost{facts: facts})
			if _, err := action.Plan(context.Background(), request); err == nil {
				t.Fatal("unsafe or stale access repair planned")
			}
		})
	}
}
