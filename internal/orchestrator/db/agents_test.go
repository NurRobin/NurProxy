package db

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestAgentSafeAutoRepairOverrideRoundTripsNullable(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)

	got, err := d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SafeAutoRepairOverride != nil || !got.SafeAutoRepairEffective {
		t.Fatalf("fresh agent override/effective = %v/%v, want nil/true", got.SafeAutoRepairOverride, got.SafeAutoRepairEffective)
	}
	pending, err := d.ListPendingAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !pending[0].SafeAutoRepairEffective {
		t.Fatalf("pending agent effective policy = %#v, want inherited true", pending)
	}

	disabled := false
	if err := d.SetAgentSafeAutoRepairOverride(a.ID, &disabled); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SafeAutoRepairOverride == nil || *got.SafeAutoRepairOverride || got.SafeAutoRepairEffective {
		t.Fatalf("disabled override/effective = %v/%v, want false/false", got.SafeAutoRepairOverride, got.SafeAutoRepairEffective)
	}

	if err := d.SetAgentSafeAutoRepairOverride(a.ID, nil); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SafeAutoRepairOverride != nil || !got.SafeAutoRepairEffective {
		t.Fatalf("cleared override/effective = %v/%v, want nil/true", got.SafeAutoRepairOverride, got.SafeAutoRepairEffective)
	}
}

func TestAgentSafeAutoRepairEffectiveAndNarrowUpdate(t *testing.T) {
	tests := []struct {
		name     string
		global   string
		override *bool
		want     bool
	}{
		{name: "inherit enabled", global: "true", want: true},
		{name: "inherit disabled", global: "false", want: false},
		{name: "explicit enabled", global: "false", override: boolPtr(true), want: true},
		{name: "explicit disabled", global: "true", override: boolPtr(false), want: false},
		{name: "missing fails closed", global: "", want: false},
		{name: "invalid fails closed", global: "yes", override: boolPtr(true), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EffectiveSafeAutoRepair(tt.global, tt.override); got != tt.want {
				t.Fatalf("EffectiveSafeAutoRepair(%q, %v) = %v, want %v", tt.global, tt.override, got, tt.want)
			}
		})
	}

	d := testDB(t)
	a := createTestAgent(t, d)
	a.Name = "must survive narrow update"
	if err := d.UpdateAgent(a); err != nil {
		t.Fatal(err)
	}
	if err := d.SetAgentSafeAutoRepairOverride(a.ID, boolPtr(false)); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != a.Name {
		t.Fatalf("narrow update changed name to %q", got.Name)
	}
	if err := d.SetAgentSafeAutoRepairOverride("missing", boolPtr(true)); err == nil {
		t.Fatal("missing agent override update succeeded")
	}
}

func TestAgentRecoveryCapabilityRoundTripAndClear(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	capability := &recoverymodel.Capability{
		Stage: 1,
		Actions: []recoverymodel.Action{
			recoverymodel.ActionPruneManagedOrphan,
			recoverymodel.ActionRemoveManagedTemp,
		},
	}
	if err := d.UpdateAgentRecoveryCapability(a.ID, capability); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RecoveryCapability == nil || got.RecoveryCapability.Stage != 1 || len(got.RecoveryCapability.Actions) != 2 {
		t.Fatalf("capability round trip = %#v", got.RecoveryCapability)
	}
	if err := d.UpdateAgentRecoveryCapability(a.ID, nil); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetAgent(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RecoveryCapability != nil {
		t.Fatalf("cleared capability = %#v, want nil", got.RecoveryCapability)
	}
	if err := d.UpdateAgentRecoveryCapability("missing", capability); err == nil {
		t.Fatal("missing agent capability update succeeded")
	}
}

func TestAgentRecoveryCapabilityRejectsInvalidInputAndStoredJSON(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	invalid := &recoverymodel.Capability{Stage: 0}
	if err := d.UpdateAgentRecoveryCapability(a.ID, invalid); err == nil {
		t.Fatal("invalid capability update succeeded")
	}
	if _, err := d.sql.Exec(`UPDATE agents SET recovery_capability = '{"stage":1,"actions":[],"future":true}' WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetAgent(a.ID); err == nil {
		t.Fatal("GetAgent accepted capability JSON with an unknown field")
	}
}

func TestAgentSafeAutoRepairOverrideRejectsCorruptStoredBoolean(t *testing.T) {
	d := testDB(t)
	a := createTestAgent(t, d)
	if _, err := d.sql.Exec(`UPDATE agents SET safe_auto_repair_override = 2 WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetAgent(a.ID); err == nil {
		t.Fatal("GetAgent accepted a non-boolean auto-repair override")
	}
}

func boolPtr(v bool) *bool { return &v }
