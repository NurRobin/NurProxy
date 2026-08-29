package proxymodel

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestRecoveryWireRoundTrips(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 15, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   any
		out  any
	}{
		{
			name: "policy envelope",
			in:   RecoveryPolicyEnvelope{Policy: RecoveryPolicy{SafeAutoRepair: true}},
			out:  &RecoveryPolicyEnvelope{},
		},
		{
			name: "request envelope",
			in: RepairRequestEnvelope{Request: recoverymodel.RepairRequest{
				OperationID: "op-1", DiagnosticID: "diag-1", Action: recoverymodel.ActionRemoveManagedTemp, StartedAt: now, InitialStep: recoverymodel.Step{Name: "planned", Summary: "safe typed repair requested", State: recoverymodel.OperationStatePlanned, At: now},
			}},
			out: &RepairRequestEnvelope{},
		},
		{
			name: "report envelope",
			in: RecoveryReportEnvelope{Report: RecoveryReport{
				Diagnostics: []recoverymodel.Diagnostic{{
					ID: "diag-1", Code: recoverymodel.CodeManagedStaleTemp,
					Subsystem: "nginx", ResourceFingerprint: "fingerprint-1",
					Severity: recoverymodel.SeverityWarning, Ownership: recoverymodel.OwnershipNurProxy,
					ProposedAction: recoverymodel.ActionRemoveManagedTemp,
					FirstSeenAt:    now, LastSeenAt: now, Occurrences: 1,
				}},
				Operations: []recoverymodel.OperationReport{{
					OperationID: "op-1", DiagnosticID: "diag-1",
					Action: recoverymodel.ActionRemoveManagedTemp,
					Source: recoverymodel.RequestSourceAutomatic,
					State:  recoverymodel.OperationStateSucceeded, StartedAt: now,
				}},
			}},
			out: &RecoveryReportEnvelope{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if err := recoverymodel.DecodeStrict(b, tt.out); err != nil {
				t.Fatal(err)
			}
			got := reflect.ValueOf(tt.out).Elem().Interface()
			if !reflect.DeepEqual(got, tt.in) {
				t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", got, tt.in)
			}
		})
	}
}

func TestRepairRequestWireHasNoPathOrCommand(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 15, 0, 0, time.UTC)
	b, err := json.Marshal(RepairRequestEnvelope{Request: recoverymodel.RepairRequest{
		OperationID: "op-1", DiagnosticID: "diag-1", Action: recoverymodel.ActionPruneManagedOrphan, StartedAt: now, InitialStep: recoverymodel.Step{Name: "planned", State: recoverymodel.OperationStatePlanned, At: now},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	request, ok := fields["request"].(map[string]any)
	if !ok {
		t.Fatalf("request envelope = %#v", fields)
	}
	for _, forbidden := range []string{"path", "paths", "command", "environment", "service"} {
		if _, exists := request[forbidden]; exists {
			t.Errorf("request contains forbidden field %q", forbidden)
		}
	}
}

func TestRepairRequestWireStrictlyRejectsInjectedFields(t *testing.T) {
	for _, field := range []string{"command", "path"} {
		raw := `{"request":{"operation_id":"op-1","diagnostic_id":"diag-1","action":"remove_managed_temp","` + field + `":"attacker-controlled"}}`
		var envelope RepairRequestEnvelope
		if err := recoverymodel.DecodeStrict([]byte(raw), &envelope); err == nil {
			t.Fatalf("strict decoder accepted %q", field)
		}
	}
}

func TestRecoveryWireRejectsUnknownActionAndState(t *testing.T) {
	tests := []struct {
		raw    string
		target any
	}{
		{`{"request":{"operation_id":"op-1","diagnostic_id":"diag-1","action":"shell"}}`, &RepairRequestEnvelope{}},
		{`{"report":{"operations":[{"operation_id":"op-1","diagnostic_id":"diag-1","action":"remove_managed_temp","source":"user","state":"waiting","started_at":"2026-08-28T20:15:00Z"}]}}`, &RecoveryReportEnvelope{}},
	}
	for _, tt := range tests {
		if err := json.Unmarshal([]byte(tt.raw), tt.target); err == nil {
			t.Fatalf("json.Unmarshal(%s) succeeded", tt.raw)
		}
	}
}
