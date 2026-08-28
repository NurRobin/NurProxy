package recoverymodel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestEnumsValidateFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		valid   bool
		invalid bool
	}{
		{"code", CodeManagedOrphanConfig.Valid(), Code("future_code").Valid()},
		{"severity", SeverityError.Valid(), Severity("urgent").Valid()},
		{"ownership", OwnershipNurProxy.Valid(), Ownership("shared").Valid()},
		{"action", ActionPruneManagedOrphan.Valid(), Action("run_command").Valid()},
		{"operation state", OperationStateDetected.Valid(), OperationState("retrying").Valid()},
		{"request source", RequestSourceAutomatic.Valid(), RequestSource("api").Valid()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.valid {
				t.Fatal("documented value is invalid")
			}
			if tt.invalid {
				t.Fatal("unknown value is valid")
			}
		})
	}

	allCodes := []Code{
		CodeManagedOrphanConfig, CodeManagedStaleTemp,
		CodeManagedCertFileMissing, CodeManagedRuntimeKeyMissing,
		CodeManagedRuntimeKeyMismatch, CodeGeneratedConfigInvalid,
		CodeOperatorConfigInvalid, CodePermissionDenied,
		CodeSystemdSandboxDenied, CodeProxyReloadFailed,
		CodeProxyNotRunning, CodePortConflict, CodeProxyBinaryMissing,
		CodeUnknownProxyError,
	}
	if len(allCodes) != 14 {
		t.Fatalf("codes = %d, want 14", len(allCodes))
	}
	for _, code := range allCodes {
		if !code.Valid() {
			t.Errorf("code %q is invalid", code)
		}
	}
}

func TestDiagnosticJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 15, 0, 0, time.UTC)
	want := Diagnostic{
		ID: "diag_deadbeef", Code: CodeManagedOrphanConfig,
		Subsystem: "nginx", Severity: SeverityError, Ownership: OwnershipNurProxy,
		Summary: "managed vhost is orphaned", Evidence: "nginx: file is missing",
		AffectedPaths:       []string{"/etc/nginx/sites-available/nurproxy-app.conf"},
		ResourceFingerprint: "sha256:resource", ProposedAction: ActionPruneManagedOrphan,
		AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 2,
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"affected_paths"`, `"resource_fingerprint"`, `"proposed_action"`, `"auto_repair_eligible"`, `"first_seen_at"`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("JSON %s lacks %s", b, field)
		}
	}
	var got Diagnostic
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Code != want.Code || got.ProposedAction != want.ProposedAction || !got.FirstSeenAt.Equal(now) || len(got.AffectedPaths) != 1 {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestOperationReportJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 15, 0, 0, time.UTC)
	finished := now.Add(time.Second)
	want := OperationReport{
		OperationID: "op-1", DiagnosticID: "diag-1",
		Action: ActionRemoveManagedTemp, Source: RequestSourceUser,
		State:             OperationStateSucceeded,
		Steps:             []Step{{Name: "validate", Summary: "configuration valid", State: OperationStateSucceeded, At: finished}},
		SnapshotReference: "recovery/operations/op-1", ValidationOutcome: "valid",
		StartedAt: now, FinishedAt: &finished,
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got OperationReport
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.OperationID != want.OperationID || got.State != want.State || len(got.Steps) != 1 || got.FinishedAt == nil || !got.FinishedAt.Equal(finished) {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestStableDiagnosticID(t *testing.T) {
	got := StableDiagnosticID("agent-1", CodeManagedOrphanConfig, "resource-1")
	if got != "diag_457e12d3a997072838a0e105b78dfe0ec09c791e1800c23350d7390532b0c584" {
		t.Fatalf("ID = %q", got)
	}
	if again := StableDiagnosticID("agent-1", CodeManagedOrphanConfig, "resource-1"); again != got {
		t.Fatalf("ID is unstable: %q != %q", again, got)
	}
	if other := StableDiagnosticID("agent-11", CodeManagedOrphanConfig, "resource-1"); other == got {
		t.Fatal("length-delimited inputs collided")
	}
}

func TestSanitizeEvidenceRedactsAndRemovesControls(t *testing.T) {
	in := "Authorization: Bearer abc.def\napi_key=np_secret\x00\x1b[31m\n" +
		"-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----"
	got := SanitizeEvidence(in)
	for _, secret := range []string{"abc.def", "np_secret", "secret material", "\x00", "\x1b"} {
		if strings.Contains(got, secret) {
			t.Errorf("sanitized evidence contains %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("sanitized evidence lacks redaction marker: %q", got)
	}
}

func TestSanitizeEvidenceTruncatesAtUTF8Boundary(t *testing.T) {
	in := strings.Repeat("a", MaxEvidenceBytes-1) + "€" + "tail"
	got := SanitizeEvidence(in)
	if len(got) > MaxEvidenceBytes {
		t.Fatalf("evidence bytes = %d, want <= %d", len(got), MaxEvidenceBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("evidence is invalid UTF-8: %q", got[len(got)-8:])
	}
}

func TestUnknownActionAndStateAreRejectedFromJSON(t *testing.T) {
	for _, raw := range []string{
		`{"operation_id":"op-1","diagnostic_id":"diag-1","action":"run_command"}`,
		`{"operation_id":"op-1","diagnostic_id":"diag-1","action":"remove_managed_temp","source":"user","state":"retrying","started_at":"2026-08-28T20:15:00Z"}`,
	} {
		var target any
		if strings.Contains(raw, `"state"`) {
			target = &OperationReport{}
		} else {
			target = &RepairRequest{}
		}
		if err := json.Unmarshal([]byte(raw), target); err == nil {
			t.Fatalf("json.Unmarshal(%s) succeeded", raw)
		}
	}
}
