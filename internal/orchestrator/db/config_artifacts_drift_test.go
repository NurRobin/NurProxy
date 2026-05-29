package db

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestReconcileArtifactChecksum_matchingNoOp verifies that a heartbeat checksum
// matching the accepted state is a no-op on a live artifact: no drift, no
// transition.
func TestReconcileArtifactChecksum_matchingNoOp(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	art := createTestArtifact(t, d, "art-1", "agent-1")

	drifted, changed, err := d.ReconcileArtifactChecksum("art-1", art.Checksum)
	if err != nil {
		t.Fatalf("ReconcileArtifactChecksum: %v", err)
	}
	if drifted || changed {
		t.Errorf("matching checksum should be a no-op: drifted=%v changed=%v", drifted, changed)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("state changed on matching checksum: %+v", got)
	}
}

// TestReconcileArtifactChecksum_divergenceFlagsDrift verifies a differing
// checksum flags the artifact drifted (transition reported) and preserves the
// stored/accepted content (never overwritten — invariant #3).
func TestReconcileArtifactChecksum_divergenceFlagsDrift(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	drifted, changed, err := d.ReconcileArtifactChecksum("art-1", "deadbeef")
	if err != nil {
		t.Fatalf("ReconcileArtifactChecksum: %v", err)
	}
	if !drifted || !changed {
		t.Errorf("divergence should flag drift: drifted=%v changed=%v", drifted, changed)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if !got.Drifted || got.ApplyState != models.ArtifactStateDrifted {
		t.Errorf("expected drifted state, got %+v", got)
	}
	if got.Content != `{"handle":[]}` {
		t.Errorf("accepted content was overwritten on drift: %q", got.Content)
	}
}

// TestReconcileArtifactChecksum_repeatedDivergenceNotReported verifies that a
// second identical-divergence heartbeat does NOT report a transition (already
// drifted), so audit isn't spammed on every beat.
func TestReconcileArtifactChecksum_repeatedDivergenceNotReported(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")

	if _, changed, _ := d.ReconcileArtifactChecksum("art-1", "deadbeef"); !changed {
		t.Fatal("first divergence should report a transition")
	}
	drifted, changed, err := d.ReconcileArtifactChecksum("art-1", "deadbeef")
	if err != nil {
		t.Fatalf("ReconcileArtifactChecksum: %v", err)
	}
	if !drifted {
		t.Error("still expected drifted=true")
	}
	if changed {
		t.Error("repeated identical divergence should not report a new transition")
	}
}

// TestReconcileArtifactChecksum_backInAgreementClearsDrift verifies that a
// heartbeat whose checksum matches the accepted state again clears a prior drift
// (host reverted by hand), reporting the transition.
func TestReconcileArtifactChecksum_backInAgreementClearsDrift(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	art := createTestArtifact(t, d, "art-1", "agent-1")

	if err := d.MarkConfigArtifactDrifted("art-1"); err != nil {
		t.Fatalf("MarkConfigArtifactDrifted: %v", err)
	}
	drifted, changed, err := d.ReconcileArtifactChecksum("art-1", art.Checksum)
	if err != nil {
		t.Fatalf("ReconcileArtifactChecksum: %v", err)
	}
	if drifted || !changed {
		t.Errorf("agreement should clear drift: drifted=%v changed=%v", drifted, changed)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("drift not cleared: %+v", got)
	}
}

// TestReconcileArtifactChecksum_applyFailedUntouched verifies that an
// apply_failed artifact is not reinterpreted by a heartbeat checksum: the failure
// owns the state until a fresh apply resolves it.
func TestReconcileArtifactChecksum_applyFailedUntouched(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")
	if err := d.SetConfigArtifactApplyState("art-1", models.ArtifactStateApplyFailed, "nginx -t failed"); err != nil {
		t.Fatalf("SetConfigArtifactApplyState: %v", err)
	}

	_, changed, err := d.ReconcileArtifactChecksum("art-1", "whatever")
	if err != nil {
		t.Fatalf("ReconcileArtifactChecksum: %v", err)
	}
	if changed {
		t.Error("apply_failed artifact should not transition on a heartbeat checksum")
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.ApplyState != models.ArtifactStateApplyFailed {
		t.Errorf("apply_failed state was clobbered: %q", got.ApplyState)
	}
}

func TestReconcileArtifactChecksum_missingArtifact(t *testing.T) {
	d := testDB(t)
	if _, _, err := d.ReconcileArtifactChecksum("nope", "x"); err == nil {
		t.Fatal("expected not-found error for missing artifact")
	}
}

// TestAcceptDrift_onDiskBecomesNewLiveVersion is the Accept transition (§11): the
// reviewed on-disk content becomes a new manual version and the live state; drift
// clears.
func TestAcceptDrift_onDiskBecomesNewLiveVersion(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")
	if err := d.MarkConfigArtifactDrifted("art-1"); err != nil {
		t.Fatalf("MarkConfigArtifactDrifted: %v", err)
	}

	onDisk := `{"handle":["edited-by-operator"]}`
	ver, err := d.AppendConfigArtifactVersion("art-1", onDisk, models.ArtifactSourceManual, "operator", "accept drift")
	if err != nil {
		t.Fatalf("accept append: %v", err)
	}
	if ver.Version != 2 {
		t.Errorf("accept version = %d, want 2", ver.Version)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.Drifted || got.ApplyState != models.ArtifactStateLive {
		t.Errorf("accept did not clear drift: %+v", got)
	}
	if got.Content != onDisk || got.Source != models.ArtifactSourceManual {
		t.Errorf("accept did not promote on-disk content: %+v", got)
	}
	if got.LiveVersion != 2 {
		t.Errorf("LiveVersion = %d, want 2", got.LiveVersion)
	}
}

// TestRejectDrift_clearsDriftPreservesAcceptedContent is the Reject transition
// (§11): drift clears WITHOUT a new version; the accepted content stays as-is
// (the caller re-applies it to disk).
func TestRejectDrift_clearsDriftPreservesAcceptedContent(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1") // content {"handle":[]}
	if err := d.MarkConfigArtifactDrifted("art-1"); err != nil {
		t.Fatalf("MarkConfigArtifactDrifted: %v", err)
	}

	art, err := d.RejectConfigArtifactDrift("art-1")
	if err != nil {
		t.Fatalf("RejectConfigArtifactDrift: %v", err)
	}
	if art.Drifted || art.ApplyState != models.ArtifactStateLive {
		t.Errorf("reject did not clear drift: %+v", art)
	}
	if art.Content != `{"handle":[]}` {
		t.Errorf("reject changed accepted content: %q", art.Content)
	}
	if art.LiveVersion != 1 {
		t.Errorf("reject wrote a new version (LiveVersion=%d), want 1", art.LiveVersion)
	}
	versions, _ := d.ListConfigArtifactVersions("art-1")
	if len(versions) != 1 {
		t.Errorf("reject grew history to %d versions, want 1", len(versions))
	}
}

func TestRejectDrift_missingArtifact(t *testing.T) {
	d := testDB(t)
	if _, err := d.RejectConfigArtifactDrift("nope"); err == nil {
		t.Fatal("expected not-found error")
	}
}

// TestRollback_promotesPriorVersionToLive is the Rollback transition (§11):
// rolling back to an earlier version's content writes a new live version with
// that content (history append-only, never rewound).
func TestRollback_promotesPriorVersionToLive(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1") // v1: {"handle":[]}
	if _, err := d.AppendConfigArtifactVersion("art-1", `{"handle":["v2"]}`, models.ArtifactSourceManual, "op", "edit"); err != nil {
		t.Fatalf("append v2: %v", err)
	}

	ver, err := d.RollbackConfigArtifact("art-1", 1, "operator", "rollback to v1")
	if err != nil {
		t.Fatalf("RollbackConfigArtifact: %v", err)
	}
	if ver.Version != 3 {
		t.Errorf("rollback wrote version %d, want 3 (append-only)", ver.Version)
	}
	got, _ := d.GetConfigArtifact("art-1")
	if got.Content != `{"handle":[]}` {
		t.Errorf("rollback content = %q, want v1 content", got.Content)
	}
	if got.LiveVersion != 3 {
		t.Errorf("LiveVersion = %d, want 3", got.LiveVersion)
	}
}

// TestRollback_toCurrentLiveIsNoOp verifies rolling back to content semantically
// equal to the current live state writes no phantom version (Caddy semantic gate).
func TestRollback_toCurrentLiveIsNoOp(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1") // v1: {"handle":[]}

	ver, err := d.RollbackConfigArtifact("art-1", 1, "operator", "rollback to v1 (no-op)")
	if err != nil {
		t.Fatalf("RollbackConfigArtifact: %v", err)
	}
	if ver.Version != 1 {
		t.Errorf("no-op rollback wrote version %d, want 1", ver.Version)
	}
}

func TestRollback_missingVersion(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")
	createTestArtifact(t, d, "art-1", "agent-1")
	if _, err := d.RollbackConfigArtifact("art-1", 99, "op", "nope"); err == nil {
		t.Fatal("expected not-found error for missing version")
	}
}

// TestSetAgentAutoReconcileConfig_roundTrips verifies the opt-in policy persists
// and round-trips through the agent row.
func TestSetAgentAutoReconcileConfig_roundTrips(t *testing.T) {
	d := testDB(t)
	createTestAgentRow(t, d, "agent-1")

	got, err := d.GetAgent("agent-1")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.AutoReconcileConfig {
		t.Error("auto-reconcile should default to false")
	}

	if err := d.SetAgentAutoReconcileConfig("agent-1", true); err != nil {
		t.Fatalf("SetAgentAutoReconcileConfig: %v", err)
	}
	got, _ = d.GetAgent("agent-1")
	if !got.AutoReconcileConfig {
		t.Error("auto-reconcile not persisted as true")
	}

	if err := d.SetAgentAutoReconcileConfig("agent-1", false); err != nil {
		t.Fatalf("SetAgentAutoReconcileConfig false: %v", err)
	}
	got, _ = d.GetAgent("agent-1")
	if got.AutoReconcileConfig {
		t.Error("auto-reconcile not cleared")
	}
}

func TestSetAgentAutoReconcileConfig_missingAgent(t *testing.T) {
	d := testDB(t)
	if err := d.SetAgentAutoReconcileConfig("nope", true); err == nil {
		t.Fatal("expected not-found error")
	}
}
