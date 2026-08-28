package recoverymodel

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestEnumsValidateFailClosed(t *testing.T) {
	assertEnumList(t, "code", []Code{
		CodeManagedOrphanConfig, CodeManagedStaleTemp, CodeManagedCertFileMissing,
		CodeManagedRuntimeKeyMissing, CodeManagedRuntimeKeyMismatch, CodeGeneratedConfigInvalid,
		CodeOperatorConfigInvalid, CodePermissionDenied, CodeSystemdSandboxDenied,
		CodeProxyReloadFailed, CodeProxyNotRunning, CodePortConflict,
		CodeProxyBinaryMissing, CodeUnknownProxyError,
	}, 14, Code.Valid)
	assertEnumList(t, "severity", []Severity{
		SeverityInfo, SeverityWarning, SeverityError, SeverityCritical,
	}, 4, Severity.Valid)
	assertEnumList(t, "ownership", []Ownership{
		OwnershipNurProxy, OwnershipOperator, OwnershipSystem, OwnershipUnknown,
	}, 4, Ownership.Valid)
	assertEnumList(t, "action", []Action{
		ActionPruneManagedOrphan, ActionRemoveManagedTemp, ActionRematerializeCertBundle,
		ActionRematerializeRuntimeKey, ActionRestoreLastLiveArtifact,
	}, 5, Action.Valid)
	assertEnumList(t, "operation state", []OperationState{
		OperationStateDetected, OperationStateDiagnosisOnly, OperationStatePlanned,
		OperationStateSnapshotted, OperationStateApplying, OperationStateValidating,
		OperationStateSucceeded, OperationStateRollingBack, OperationStateRolledBack,
		OperationStateRollbackFailed, OperationStateSuppressed,
	}, 11, OperationState.Valid)
	assertEnumList(t, "request source", []RequestSource{
		RequestSourceAutomatic, RequestSourceUser,
	}, 2, RequestSource.Valid)

	if Code("future_code").Valid() || Severity("urgent").Valid() || Ownership("shared").Valid() ||
		Action("run_command").Valid() || OperationState("retrying").Valid() || RequestSource("api").Valid() {
		t.Fatal("an unknown enum value is valid")
	}
}

func assertEnumList[T ~string](t *testing.T, name string, values []T, want int, valid func(T) bool) {
	t.Helper()
	if len(values) != want {
		t.Fatalf("%s values = %d, want %d", name, len(values), want)
	}
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if value == "" || !valid(value) {
			t.Errorf("documented %s value %q is invalid", name, value)
		}
		if _, exists := seen[value]; exists {
			t.Errorf("documented %s value %q is duplicated", name, value)
		}
		seen[value] = struct{}{}
	}
}

func TestClosedEnumsRejectUnknownJSON(t *testing.T) {
	tests := []struct {
		name   string
		target any
	}{
		{"code", new(Code)},
		{"severity", new(Severity)},
		{"ownership", new(Ownership)},
		{"action", new(Action)},
		{"operation state", new(OperationState)},
		{"request source", new(RequestSource)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(`"not_in_contract"`), tt.target); err == nil {
				t.Fatal("unknown JSON value was accepted")
			}
		})
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

func TestSanitizeEvidenceRedactsRealisticSecrets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		secrets []string
	}{
		{"JSON token", `{"token":"abc"}`, []string{"abc"}},
		{"quoted assignment", `token="abc def"`, []string{"abc", "def"}},
		{"namespaced API key", `NP_API_KEY=np_secret`, []string{"np_secret"}},
		{"environment variants", "DATABASE_PASSWORD=hunter2 CLIENT_SECRET='client value' NP_AGENT_TOKEN=tok", []string{"hunter2", "client value", "tok"}},
		{"basic authorization", "Authorization: Basic dXNlcjpwYXNz", []string{"dXNlcjpwYXNz"}},
		{"bearer authorization", "authorization=Bearer abc.def", []string{"abc.def"}},
		{"nginx authorization", `proxy_set_header Authorization "Bearer upstream-secret";`, []string{"upstream-secret"}},
		{"complete private key", "-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----", []string{"secret material"}},
		{"truncated private key", "-----BEGIN RSA PRIVATE KEY-----\nleaked-to-eof", []string{"leaked-to-eof"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeEvidence(tt.input)
			for _, secret := range tt.secrets {
				if strings.Contains(got, secret) {
					t.Errorf("sanitized evidence contains %q: %q", secret, got)
				}
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Fatalf("sanitized evidence lacks redaction marker: %q", got)
			}
		})
	}
}

func TestSanitizeEvidenceNormalizesLineEndingsAndRemovesUnsafeUnicode(t *testing.T) {
	got := SanitizeEvidence("safe\r\nnext\rline\x00\x1b[31m\u202Eevil\u2066text\u200B")
	if got != "safe\nnextline[31meviltext" {
		t.Fatalf("sanitized evidence = %q", got)
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

func TestShapeValidation(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 15, 0, 0, time.UTC)
	validDiagnostic := Diagnostic{
		ID: "diag-1", Code: CodeManagedStaleTemp, Subsystem: "nginx",
		Severity: SeverityWarning, Ownership: OwnershipNurProxy,
		ResourceFingerprint: "fingerprint", FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
	validCapability := Capability{Stage: 1, Actions: []Action{ActionRemoveManagedTemp}}
	validRequest := RepairRequest{OperationID: "op-1", DiagnosticID: "diag-1", Action: ActionRemoveManagedTemp}
	validReport := OperationReport{
		OperationID: "op-1", DiagnosticID: "diag-1", Action: ActionRemoveManagedTemp,
		Source: RequestSourceAutomatic, State: OperationStateApplying, StartedAt: now,
	}
	tests := []struct {
		name string
		err  error
	}{
		{"valid diagnostic with no proposed action", validDiagnostic.Validate()},
		{"valid capability", validCapability.Validate()},
		{"valid request", validRequest.Validate()},
		{"valid operation report", validReport.Validate()},
	}
	for _, tt := range tests {
		if tt.err != nil {
			t.Errorf("%s: %v", tt.name, tt.err)
		}
	}

	invalid := []struct {
		name string
		err  func() error
	}{
		{"diagnostic empty ID", func() error { v := validDiagnostic; v.ID = ""; return v.Validate() }},
		{"diagnostic empty code", func() error { v := validDiagnostic; v.Code = ""; return v.Validate() }},
		{"diagnostic unknown severity", func() error { v := validDiagnostic; v.Severity = "urgent"; return v.Validate() }},
		{"diagnostic unknown ownership", func() error { v := validDiagnostic; v.Ownership = "shared"; return v.Validate() }},
		{"diagnostic zero occurrences", func() error { v := validDiagnostic; v.Occurrences = 0; return v.Validate() }},
		{"diagnostic unknown proposed action", func() error { v := validDiagnostic; v.ProposedAction = "shell"; return v.Validate() }},
		{"capability zero stage", func() error { v := validCapability; v.Stage = 0; return v.Validate() }},
		{"capability unknown action", func() error { v := validCapability; v.Actions = []Action{"shell"}; return v.Validate() }},
		{"capability duplicate action", func() error {
			v := validCapability
			v.Actions = []Action{ActionRemoveManagedTemp, ActionRemoveManagedTemp}
			return v.Validate()
		}},
		{"request empty operation ID", func() error { v := validRequest; v.OperationID = ""; return v.Validate() }},
		{"request empty diagnostic ID", func() error { v := validRequest; v.DiagnosticID = ""; return v.Validate() }},
		{"request empty action", func() error { v := validRequest; v.Action = ""; return v.Validate() }},
		{"request unknown action", func() error { v := validRequest; v.Action = "shell"; return v.Validate() }},
		{"report empty operation ID", func() error { v := validReport; v.OperationID = ""; return v.Validate() }},
		{"report empty diagnostic ID", func() error { v := validReport; v.DiagnosticID = ""; return v.Validate() }},
		{"report empty action", func() error { v := validReport; v.Action = ""; return v.Validate() }},
		{"report unknown source", func() error { v := validReport; v.Source = "api"; return v.Validate() }},
		{"report empty state", func() error { v := validReport; v.State = ""; return v.Validate() }},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.err(); err == nil {
				t.Fatal("invalid shape was accepted")
			}
		})
	}
}

func TestRepairRequestJSONRejectsMissingEmptyAndUnknownAction(t *testing.T) {
	for _, action := range []string{"missing", "empty", "unknown"} {
		t.Run(action, func(t *testing.T) {
			raw := `{"operation_id":"op-1","diagnostic_id":"diag-1"}`
			if action == "empty" {
				raw = `{"operation_id":"op-1","diagnostic_id":"diag-1","action":""}`
			}
			if action == "unknown" {
				raw = `{"operation_id":"op-1","diagnostic_id":"diag-1","action":"shell"}`
			}
			var request RepairRequest
			if err := json.Unmarshal([]byte(raw), &request); err == nil {
				t.Fatal("invalid repair request was accepted")
			}
		})
	}
}

func TestDecodeStrictRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	type payload struct {
		ID string `json:"id"`
	}
	for i, raw := range []string{`{"id":"one","command":"whoami"}`, `{"id":"one"} {"id":"two"}`} {
		var got payload
		if err := DecodeStrict([]byte(raw), &got); err == nil {
			t.Errorf("case %d accepted strict-invalid JSON", i)
		}
	}
	var got payload
	if err := DecodeStrict([]byte(`{"id":"one"}`), &got); err != nil || got.ID != "one" {
		t.Fatal(fmt.Errorf("valid strict JSON: got %#v: %w", got, err))
	}
}
