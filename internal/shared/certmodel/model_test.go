package certmodel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validExport() CertificateExport {
	return CertificateExport{
		ID: "exp-1", Name: "mail certificate", CertificateHost: "mail.example.com",
		AgentID: "agent-1", Enabled: true, Mode: ExportModeSymlink,
		Destinations: []Destination{
			{Kind: DestinationCert, Path: "/etc/mail/tls/cert.pem"},
			{Kind: DestinationPrivateKey, Path: "/etc/mail/tls/privkey.pem"},
		},
		Permissions: PermissionPolicy{Owner: "root", Group: "mail", PublicMode: "0644", PrivateKeyMode: "0640"},
		Action:      PostDeployAction{Kind: ActionNone},
	}
}

func TestCertificateExportRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name string
		edit func(*CertificateExport)
	}{
		{"non canonical host", func(e *CertificateExport) { e.CertificateHost = "MAIL.Example.com." }},
		{"relative destination", func(e *CertificateExport) { e.Destinations[0].Path = "etc/cert.pem" }},
		{"unclean destination", func(e *CertificateExport) { e.Destinations[0].Path = "/etc/mail/../cert.pem" }},
		{"duplicate destination kind", func(e *CertificateExport) { e.Destinations[1].Kind = DestinationCert }},
		{"duplicate destination path", func(e *CertificateExport) { e.Destinations[1].Path = e.Destinations[0].Path }},
		{"bad public mode", func(e *CertificateExport) { e.Permissions.PublicMode = "07777" }},
		{"control character", func(e *CertificateExport) { e.Name = "mail\ncert" }},
		{"relative executable", func(e *CertificateExport) {
			e.Action = PostDeployAction{Kind: ActionCommand, Argv: []string{"bin/reload"}, TimeoutSeconds: 10}
		}},
		{"mixed systemd command", func(e *CertificateExport) {
			e.Action = PostDeployAction{Kind: ActionSystemd, SystemdService: "postfix.service", Argv: []string{"/bin/true"}, TimeoutSeconds: 10}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			export := validExport()
			tt.edit(&export)
			if err := export.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
		})
	}
}

func TestStrictDecoderRejectsShellCommandField(t *testing.T) {
	raw, err := json.Marshal(validExport())
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"action":{"kind":"none"}`, `"action":{"kind":"command","command":"systemctl reload postfix"}`, 1))
	var export CertificateExport
	if err := DecodeStrict(raw, &export); err == nil {
		t.Fatal("shell command field accepted")
	}
}

func TestClosedEnumsAndStrictDecoder(t *testing.T) {
	var export CertificateExport
	if err := DecodeStrict([]byte(`{"id":"exp-1","unknown":true}`), &export); err == nil {
		t.Fatal("unknown field accepted")
	}
	export = validExport()
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"symlink"`, `"bind_mount"`, 1))
	if err := DecodeStrict(raw, &export); err == nil {
		t.Fatal("unknown enum accepted")
	}
}

func TestExportAggregateBoundsAndDuplicates(t *testing.T) {
	base := validExport()
	inv := ExportInventory{Revision: 1, ChunkIndex: 0, ChunkCount: 1, Exports: []CertificateExport{base, base}, Keep: []string{base.ID}}
	if err := inv.Validate(); err == nil {
		t.Fatal("duplicate export ID accepted")
	}
	inv = ExportInventory{Revision: 1, ChunkIndex: 0, ChunkCount: 1, Exports: []CertificateExport{base}, Keep: []string{base.ID, base.ID}}
	if err := inv.Validate(); err == nil {
		t.Fatal("duplicate keep ID accepted")
	}
	inv = ExportInventory{Revision: 1, ChunkIndex: 0, ChunkCount: MaxSnapshotChunks + 1}
	if err := inv.Validate(); err == nil {
		t.Fatal("too many chunks accepted")
	}
	inv = ExportInventory{Revision: 1, ChunkIndex: 0, ChunkCount: 1, ChunkBytes: MaxChunkBytes + 1}
	if err := inv.Validate(); err == nil {
		t.Fatal("oversized chunk accepted")
	}
	tooMany := make([]CertificateExport, MaxExportsPerSnapshot+1)
	inv = ExportInventory{Revision: 1, ChunkIndex: 0, ChunkCount: 1, Exports: tooMany}
	if err := inv.Validate(); err == nil {
		t.Fatal("too many exports accepted")
	}
}

func TestInventoryChunkSetRejectsIncompleteReorderedOrMismatchedSnapshots(t *testing.T) {
	valid := []ExportInventory{
		{Revision: 7, ChunkIndex: 0, ChunkCount: 2, ChunkBytes: 10, AssembledBytes: 20},
		{Revision: 7, ChunkIndex: 1, ChunkCount: 2, ChunkBytes: 10, AssembledBytes: 20},
	}
	if err := ValidateInventoryChunks(valid); err != nil {
		t.Fatalf("valid chunks rejected: %v", err)
	}
	for name, chunks := range map[string][]ExportInventory{
		"incomplete":  valid[:1],
		"reordered":   {valid[1], valid[0]},
		"revision":    {valid[0], {Revision: 8, ChunkIndex: 1, ChunkCount: 2, ChunkBytes: 10, AssembledBytes: 20}},
		"total bytes": {valid[0], {Revision: 7, ChunkIndex: 1, ChunkCount: 2, ChunkBytes: 10, AssembledBytes: 21}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateInventoryChunks(chunks); err == nil {
				t.Fatal("invalid chunk set accepted")
			}
		})
	}
}

func TestPlanEnvelopesValidateNestedPayload(t *testing.T) {
	now := time.Now().UTC()
	request := ExportPlanRequestEnvelope{Request: ExportPlanRequest{RequestID: "plan-1", Export: validExport(), RequestedAt: now}}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	request.Request.Export.Destinations[0].Path = "relative.pem"
	if err := request.Validate(); err == nil {
		t.Fatal("invalid nested request accepted")
	}
}

func TestBundleBoundsAndHostUniqueness(t *testing.T) {
	bundles := []CertificateMaterial{{Host: "mail.example.com", CertPEM: "cert", KeyPEM: "key"}, {Host: "mail.example.com", CertPEM: "cert", KeyPEM: "key"}}
	if err := ValidateCertificateMaterials(bundles); err == nil {
		t.Fatal("duplicate host accepted")
	}
	bundles = []CertificateMaterial{{Host: "mail.example.com", CertPEM: strings.Repeat("x", MaxPEMBytes+1), KeyPEM: "key"}}
	if err := ValidateCertificateMaterials(bundles); err == nil {
		t.Fatal("oversized PEM accepted")
	}
}

func TestPlanResultRejectsStaleOrUnboundTokens(t *testing.T) {
	now := time.Date(2026, 8, 29, 5, 0, 0, 0, time.UTC)
	result := ExportPlanResult{
		RequestID: "plan-1", ExportID: "exp-1", SpecHash: strings.Repeat("a", 64),
		CapabilityRevision: "cap-1", FreshnessToken: "opaque-token-123456", ExpiresAt: now.Add(time.Minute),
		ResolvedDestinations: []ResolvedDestination{{Kind: DestinationCert, Path: "/etc/mail/cert.pem", UID: 0, GID: 0, Mode: "0644"}},
		ResolvedAction:       ResolvedAction{Kind: ActionNone},
	}
	if err := result.ValidateAt(now); err != nil {
		t.Fatalf("valid result: %v", err)
	}
	if err := result.ValidateAt(now.Add(2 * time.Minute)); err == nil {
		t.Fatal("stale token accepted")
	}
	result.SpecHash = strings.Repeat("b", 63)
	if err := result.ValidateAt(now); err == nil {
		t.Fatal("invalid spec hash accepted")
	}
}

func TestCapabilityNegotiationFailsClosedForLegacyPeers(t *testing.T) {
	if SupportsExports(nil) {
		t.Fatal("legacy peer unexpectedly supports exports")
	}
	legacy := AgentCapabilities{ContractVersion: 0}
	if SupportsExports(&legacy) {
		t.Fatal("version zero unexpectedly supports exports")
	}
	current := AgentCapabilities{ContractVersion: CurrentContractVersion, CapabilityRevision: "cap-1", Features: []Capability{CapabilityCertificateExports, CapabilityChunkedInventory}}
	if err := current.Validate(); err != nil {
		t.Fatal(err)
	}
	if !SupportsExports(&current) {
		t.Fatal("current peer not negotiated")
	}
}

func TestStatusAndHistoryNeverSerializePrivateMaterial(t *testing.T) {
	values := []any{
		ExportStatus{ExportID: "exp-1", Health: HealthHealthy, DesiredFingerprint: strings.Repeat("a", 64), AppliedFingerprint: strings.Repeat("a", 64)},
		ExportDeployment{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: strings.Repeat("a", 64), Phase: DeploymentSucceeded, Rollback: RollbackNotNeeded},
		CleanupAcknowledgement{ExportID: "exp-1", Revision: 2, DesiredFingerprint: strings.Repeat("a", 64), Phase: CleanupCompleted, Outcome: CleanupRemoved, Rollback: RollbackNotNeeded},
	}
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(raw))
		for _, forbidden := range []string{"key_pem", "private_key", "password", "cert_pem"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%T serialized %q: %s", value, forbidden, raw)
			}
		}
	}
}

func TestActionArgvAndTimeoutBounds(t *testing.T) {
	export := validExport()
	export.Action = PostDeployAction{Kind: ActionCommand, Argv: make([]string, MaxArgvEntries+1), TimeoutSeconds: 10}
	if err := export.Validate(); err == nil {
		t.Fatal("oversized argv accepted")
	}
	export.Action = PostDeployAction{Kind: ActionCommand, Argv: []string{"/bin/true"}, TimeoutSeconds: MaxActionTimeoutSeconds + 1}
	if err := export.Validate(); err == nil {
		t.Fatal("oversized timeout accepted")
	}
	export.Action = PostDeployAction{Kind: ActionCommand, Argv: []string{"/bin/true", strings.Repeat("x", MaxArgvBytes)}, TimeoutSeconds: 10}
	if err := export.Validate(); err == nil {
		t.Fatal("oversized aggregate argv accepted")
	}
}

func TestCleanupAcknowledgementCarriesReplayAndRollbackState(t *testing.T) {
	ack := CleanupAcknowledgement{ExportID: "exp-1", Revision: 2, DesiredFingerprint: strings.Repeat("a", 64), Phase: CleanupCompleted, Outcome: CleanupRemoved, Rollback: RollbackNotNeeded}
	if err := ack.Validate(); err != nil {
		t.Fatal(err)
	}
	ack.DesiredFingerprint = ""
	if err := ack.Validate(); err == nil {
		t.Fatal("cleanup acknowledgement without desired fingerprint accepted")
	}
}

func TestCleanupIntentRetainsCertificateIdentity(t *testing.T) {
	intent := CleanupIntent{ExportID: "exp-1", Revision: 2, CertificateHost: "mail.example.com", DesiredFingerprint: strings.Repeat("a", 64), Mode: ExportModeSymlink, Destinations: []Destination{{Kind: DestinationCert, Path: "/etc/mail/cert.pem"}}}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	intent.CertificateHost = "MAIL.example.com"
	if err := intent.Validate(); err == nil {
		t.Fatal("non-canonical cleanup host accepted")
	}
}
