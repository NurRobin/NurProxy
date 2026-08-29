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

type fakeFirewallHost struct {
	facts   firewallFacts
	adds    []int
	removes []int
}

func (h *fakeFirewallHost) Inspect(context.Context, FirewallTargetConfig) (firewallFacts, error) {
	return h.facts, nil
}
func (h *fakeFirewallHost) Add(_ context.Context, _ FirewallTargetConfig, port int) error {
	h.adds = append(h.adds, port)
	if port == 80 {
		h.facts.Port80, h.facts.Owned80 = true, true
	} else {
		h.facts.Port443, h.facts.Owned443 = true, true
	}
	return nil
}
func (h *fakeFirewallHost) Remove(_ context.Context, _ FirewallTargetConfig, port int) error {
	h.removes = append(h.removes, port)
	if port == 80 {
		h.facts.Port80, h.facts.Owned80 = false, false
	} else {
		h.facts.Port443, h.facts.Owned443 = false, false
	}
	return nil
}

func TestFirewallActionAddsOnlyMissingProxyPortsAndRollsBackOwnedRules(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	journal, err := NewJournal(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	target := FirewallTargetConfig{Backend: "ufw", Binary: "/usr/sbin/ufw"}
	host := &fakeFirewallHost{facts: firewallFacts{Backend: "ufw", Active: true, Port80: true, Owned80: false}}
	action, err := newFirewallAction("nginx", target, journal, host)
	if err != nil {
		t.Fatal(err)
	}
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionOpenProxyFirewallPorts, LogicalTarget: helperprotocol.LogicalTargetLocalFirewall, DiagnosticReference: "diagnostic-1"}
	material, err := action.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeUnknownProxyError, "nginx", "local_firewall", nil)
	if material.ResourceFingerprint != want || material.RollbackCoverage != helperprotocol.RollbackCoveragePartial {
		t.Fatalf("material = %+v", material)
	}
	plan := helperprotocol.HelperPlan{Action: request.Action, ExecutionPlanHash: material.ExecutionPlanHash}
	prepared, err := action.Prepare(context.Background(), "operation-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := action.Execute(context.Background(), "operation-1", plan, prepared)
	if err != nil || !result.Validated || len(host.adds) != 1 || host.adds[0] != 443 {
		t.Fatalf("execute = %+v, %v adds=%v", result, err, host.adds)
	}
	if err := action.Rollback(context.Background(), "operation-1", plan, prepared); err != nil || len(host.removes) != 1 || host.removes[0] != 443 || !host.facts.Port80 {
		t.Fatalf("rollback err=%v removes=%v facts=%+v", err, host.removes, host.facts)
	}
}

func TestFirewallActionRefusesInactiveAmbiguousOrAlreadyOpenScope(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	journal, _ := NewJournal(dir, uint32(os.Getuid()))
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionOpenProxyFirewallPorts, LogicalTarget: helperprotocol.LogicalTargetLocalFirewall, DiagnosticReference: "diagnostic-1"}
	for name, facts := range map[string]firewallFacts{
		"inactive":  {Backend: "ufw"},
		"ambiguous": {Backend: "ufw", Active: true, Ambiguous: true},
		"open":      {Backend: "ufw", Active: true, Port80: true, Port443: true},
	} {
		t.Run(name, func(t *testing.T) {
			action, _ := newFirewallAction("nginx", FirewallTargetConfig{Backend: "ufw", Binary: "/usr/sbin/ufw"}, journal, &fakeFirewallHost{facts: facts})
			if _, err := action.Plan(context.Background(), request); err == nil {
				t.Fatal("unsafe or stale firewall action planned")
			}
		})
	}
}
