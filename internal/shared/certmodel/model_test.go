package certmodel

import (
	"encoding/json"
	"fmt"
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
		{"traversal export ID", func(e *CertificateExport) { e.ID = "../../mail" }},
		{"slash export ID", func(e *CertificateExport) { e.ID = "mail/cert" }},
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

func TestInventorySizesAreDerivedFromSerializedPayload(t *testing.T) {
	chunk := ExportInventory{Revision: 9, ChunkIndex: 0, ChunkCount: 1, Keep: []string{"exp-1"}}
	serializedBytes, err := InventorySerializedBytes(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if serializedBytes == 0 {
		t.Fatal("serialized inventory size is zero")
	}
	if err := chunk.Validate(); err != nil {
		t.Fatal(err)
	}
	var decoded ExportInventory
	if err := DecodeStrict([]byte(`{"revision":9,"chunk_index":0,"chunk_count":1,"chunk_bytes":1}`), &decoded); err == nil {
		t.Fatal("self-reported chunk size field accepted")
	}
}

func TestCertificateMaterialsUseActualSerializedBound(t *testing.T) {
	material := CertificateMaterial{Host: "mail.example.com", CertPEM: strings.Repeat("c", MaxPEMBytes), KeyPEM: strings.Repeat("k", MaxPEMBytes)}
	if err := ValidateCertificateMaterials([]CertificateMaterial{material}); err != nil {
		t.Fatalf("one maximum-sized bundle should fit one wire chunk: %v", err)
	}
	two := []CertificateMaterial{material, {Host: "mail2.example.com", CertPEM: material.CertPEM, KeyPEM: material.KeyPEM}}
	if err := ValidateCertificateMaterials(two); err == nil {
		t.Fatal("certificate bundles above one serialized wire chunk accepted")
	}
	many := make([]CertificateMaterial, 5)
	for i := range many {
		many[i] = CertificateMaterial{Host: fmt.Sprintf("mail%d.example.com", i), CertPEM: strings.Repeat("c", MaxPEMBytes), KeyPEM: strings.Repeat("k", MaxPEMBytes)}
	}
	if err := ValidateCertificateMaterials(many); err == nil {
		t.Fatal("serialized certificate material above assembled bound accepted")
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
	tooMany := make([]CertificateExport, MaxExportsPerSnapshot+1)
	inv = ExportInventory{Revision: 1, ChunkIndex: 0, ChunkCount: 1, Exports: tooMany}
	if err := inv.Validate(); err == nil {
		t.Fatal("too many exports accepted")
	}
}

func TestInventoryChunkSetRejectsIncompleteReorderedOrMismatchedSnapshots(t *testing.T) {
	valid := []ExportInventory{
		{Revision: 7, ChunkIndex: 0, ChunkCount: 2},
		{Revision: 7, ChunkIndex: 1, ChunkCount: 2},
	}
	if err := ValidateInventoryChunks(valid); err != nil {
		t.Fatalf("valid chunks rejected: %v", err)
	}
	for name, chunks := range map[string][]ExportInventory{
		"incomplete":  valid[:1],
		"reordered":   {valid[1], valid[0]},
		"revision":    {valid[0], {Revision: 8, ChunkIndex: 1, ChunkCount: 2}},
		"chunk count": {valid[0], {Revision: 7, ChunkIndex: 1, ChunkCount: 3}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateInventoryChunks(chunks); err == nil {
				t.Fatal("invalid chunk set accepted")
			}
		})
	}
}

func TestInventoryChunkSetEnforcesAggregateCollectionLimits(t *testing.T) {
	makeExport := func(index int) CertificateExport {
		export := validExport()
		export.ID = fmt.Sprintf("exp-%03d", index)
		export.Name = fmt.Sprintf("export %d", index)
		export.CertificateHost = fmt.Sprintf("mail-%d.example.com", index)
		for destinationIndex := range export.Destinations {
			export.Destinations[destinationIndex].Path = fmt.Sprintf("/etc/mail/%d/%s.pem", index, export.Destinations[destinationIndex].Kind)
		}
		return export
	}
	exports := make([]CertificateExport, MaxExportsPerSnapshot+1)
	for index := range exports {
		exports[index] = makeExport(index)
	}
	chunks := []ExportInventory{
		{Revision: 8, ChunkIndex: 0, ChunkCount: 2, Exports: exports[:64]},
		{Revision: 8, ChunkIndex: 1, ChunkCount: 2, Exports: exports[64:]},
	}
	if err := ValidateInventoryChunks(chunks); err == nil {
		t.Fatal("aggregate export count above snapshot limit accepted")
	}
	keep := make([]string, MaxExportsPerSnapshot+1)
	for index := range keep {
		keep[index] = fmt.Sprintf("exp-%03d", index)
	}
	chunks = []ExportInventory{
		{Revision: 8, ChunkIndex: 0, ChunkCount: 2, Keep: keep[:64]},
		{Revision: 8, ChunkIndex: 1, ChunkCount: 2, Keep: keep[64:]},
	}
	if err := ValidateInventoryChunks(chunks); err == nil {
		t.Fatal("aggregate keep count above snapshot limit accepted")
	}
	cleanups := make([]CleanupIntent, MaxExportsPerSnapshot+1)
	for index := range cleanups {
		cleanups[index] = CleanupIntent{ExportID: fmt.Sprintf("old-%03d", index), Revision: 8, CertificateHost: fmt.Sprintf("old-%d.example.com", index), DesiredFingerprint: strings.Repeat("a", 64), Mode: ExportModeSymlink, Destinations: []Destination{{Kind: DestinationCert, Path: fmt.Sprintf("/etc/old/%d/cert.pem", index)}}}
	}
	chunks = []ExportInventory{
		{Revision: 8, ChunkIndex: 0, ChunkCount: 2, Cleanup: cleanups[:64]},
		{Revision: 8, ChunkIndex: 1, ChunkCount: 2, Cleanup: cleanups[64:]},
	}
	if err := ValidateInventoryChunks(chunks); err == nil {
		t.Fatal("aggregate cleanup count above snapshot limit accepted")
	}
	chunks = []ExportInventory{
		{Revision: 8, ChunkIndex: 0, ChunkCount: 2, Exports: exports[:65]},
		{Revision: 8, ChunkIndex: 1, ChunkCount: 2, Cleanup: cleanups[:64]},
	}
	if err := ValidateInventoryChunks(chunks); err == nil {
		t.Fatal("aggregate desired plus cleanup count above snapshot limit accepted")
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

func TestPlanResultRequiresUniqueDestinationKindsAndPaths(t *testing.T) {
	now := time.Date(2026, 8, 29, 5, 0, 0, 0, time.UTC)
	base := ExportPlanResult{RequestID: "plan-1", ExportID: "exp-1", SpecHash: strings.Repeat("a", 64), CapabilityRevision: "cap-1", FreshnessToken: "opaque-token-123456", ExpiresAt: now.Add(time.Minute), ResolvedAction: ResolvedAction{Kind: ActionNone}}
	if err := base.ValidateAt(now); err == nil {
		t.Fatal("plan without destinations accepted")
	}
	base.ResolvedDestinations = []ResolvedDestination{
		{Kind: DestinationCert, Path: "/etc/mail/cert.pem", UID: 0, GID: 0, Mode: "0644"},
		{Kind: DestinationCert, Path: "/etc/mail/other.pem", UID: 0, GID: 0, Mode: "0644"},
	}
	if err := base.ValidateAt(now); err == nil {
		t.Fatal("plan with duplicate destination kind accepted")
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
		ExportDeployment{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: strings.Repeat("a", 64), AppliedFingerprint: strings.Repeat("a", 64), Phase: DeploymentSucceeded, Rollback: RollbackNotNeeded},
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

func TestExportStatusHealthMatrix(t *testing.T) {
	desired := strings.Repeat("a", 64)
	applied := strings.Repeat("b", 64)
	valid := []ExportStatus{
		{ExportID: "exp-1", Health: HealthPending, DesiredFingerprint: desired},
		{ExportID: "exp-1", Health: HealthHealthy, DesiredFingerprint: desired, AppliedFingerprint: desired},
		{ExportID: "exp-1", Health: HealthDegraded, DesiredFingerprint: desired, AppliedFingerprint: applied, LastErrorCode: "hook_failed"},
		{ExportID: "exp-1", Health: HealthFailed, DesiredFingerprint: desired, AppliedFingerprint: applied, LastErrorCode: "rollback_failed"},
		{ExportID: "exp-1", Health: HealthDisabled, AppliedFingerprint: applied},
	}
	for _, status := range valid {
		if err := status.Validate(); err != nil {
			t.Fatalf("valid status rejected: %#v: %v", status, err)
		}
	}
	invalid := []ExportStatus{
		{ExportID: "exp-1", Health: HealthPending, LastErrorCode: "unexpected"},
		{ExportID: "exp-1", Health: HealthHealthy},
		{ExportID: "exp-1", Health: HealthHealthy, DesiredFingerprint: desired, AppliedFingerprint: applied},
		{ExportID: "exp-1", Health: HealthHealthy, DesiredFingerprint: desired, AppliedFingerprint: desired, LastErrorCode: "unexpected"},
		{ExportID: "exp-1", Health: HealthDegraded, DesiredFingerprint: desired, AppliedFingerprint: applied},
		{ExportID: "exp-1", Health: HealthFailed, DesiredFingerprint: desired},
		{ExportID: "exp-1", Health: HealthDisabled, LastErrorCode: "unexpected"},
	}
	for _, status := range invalid {
		if err := status.Validate(); err == nil {
			t.Fatalf("invalid status accepted: %#v", status)
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

func TestCleanupInventoryRejectsContradictions(t *testing.T) {
	active := validExport()
	cleanup := CleanupIntent{ExportID: "old-1", Revision: 2, CertificateHost: "mail.example.com", DesiredFingerprint: strings.Repeat("a", 64), Mode: ExportModeSymlink, Destinations: []Destination{{Kind: DestinationCert, Path: "/etc/old/cert.pem"}}}
	cases := map[string]func(*ExportInventory){
		"empty cleanup": func(i *ExportInventory) { i.Cleanup[0].Destinations = nil },
		"duplicate kind": func(i *ExportInventory) {
			i.Cleanup[0].Destinations = append(i.Cleanup[0].Destinations, Destination{Kind: DestinationCert, Path: "/etc/old/other.pem"})
		},
		"active path":     func(i *ExportInventory) { i.Cleanup[0].Destinations[0].Path = active.Destinations[0].Path },
		"keep cleanup ID": func(i *ExportInventory) { i.Keep = append(i.Keep, cleanup.ExportID) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			inventory := ExportInventory{Revision: 3, ChunkIndex: 0, ChunkCount: 1, Exports: []CertificateExport{active}, Keep: []string{active.ID}, Cleanup: []CleanupIntent{cleanup}}
			mutate(&inventory)
			if err := inventory.validatePayload(); err == nil {
				t.Fatal("contradictory inventory accepted")
			}
		})
	}
}

func TestDeploymentStateMatrix(t *testing.T) {
	fp := strings.Repeat("a", 64)
	valid := []ExportDeployment{
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentApplying, Rollback: RollbackNotNeeded},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, AppliedFingerprint: fp, Phase: DeploymentSucceeded, Rollback: RollbackNotNeeded},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentRollingBack, Rollback: RollbackPending, ErrorCode: "hook_failed"},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, AppliedFingerprint: strings.Repeat("b", 64), Phase: DeploymentRolledBack, Rollback: RollbackSucceeded, ErrorCode: "hook_failed"},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentFailed, Rollback: RollbackFailed, ErrorCode: "rollback_failed"},
	}
	for _, deployment := range valid {
		if err := deployment.Validate(); err != nil {
			t.Fatalf("valid state rejected: %#v: %v", deployment, err)
		}
	}
	invalid := []ExportDeployment{
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentSucceeded, Rollback: RollbackNotNeeded},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, AppliedFingerprint: fp, Phase: DeploymentSucceeded, Rollback: RollbackNotNeeded, ErrorCode: "unexpected"},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentApplying, Rollback: RollbackFailed},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentFailed, Rollback: RollbackFailed},
		{DeploymentID: "dep-1", ExportID: "exp-1", DesiredFingerprint: fp, Phase: DeploymentRolledBack, Rollback: RollbackSucceeded, ErrorCode: "hook_failed"},
	}
	for _, deployment := range invalid {
		if err := deployment.Validate(); err == nil {
			t.Fatalf("invalid state accepted: %#v", deployment)
		}
	}
}

func TestCleanupStateMatrix(t *testing.T) {
	fp := strings.Repeat("a", 64)
	valid := []CleanupAcknowledgement{
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupPending, Outcome: CleanupOutcomePending, Rollback: RollbackNotNeeded},
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupCompleted, Outcome: CleanupRemoved, Rollback: RollbackNotNeeded},
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupPhaseFailed, Outcome: CleanupFailed, Rollback: RollbackFailed, ErrorCode: "rollback_failed"},
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupPhaseFailed, Outcome: CleanupFailed, Rollback: RollbackSucceeded, ErrorCode: "cleanup_failed"},
	}
	for _, ack := range valid {
		if err := ack.Validate(); err != nil {
			t.Fatalf("valid state rejected: %#v: %v", ack, err)
		}
	}
	invalid := []CleanupAcknowledgement{
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupPending, Outcome: CleanupRemoved, Rollback: RollbackNotNeeded},
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupCompleted, Outcome: CleanupFailed, Rollback: RollbackNotNeeded},
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupPhaseFailed, Outcome: CleanupFailed, Rollback: RollbackFailed},
		{ExportID: "exp-1", Revision: 2, DesiredFingerprint: fp, Phase: CleanupCompleted, Outcome: CleanupRemoved, Rollback: RollbackSucceeded},
	}
	for _, ack := range invalid {
		if err := ack.Validate(); err == nil {
			t.Fatalf("invalid state accepted: %#v", ack)
		}
	}
}
