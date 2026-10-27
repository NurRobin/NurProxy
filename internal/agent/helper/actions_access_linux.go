//go:build linux

package helper

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

type managedAccessFacts struct {
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	Directory bool   `json:"directory"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Mode      uint32 `json:"mode"`
}

type managedAccessHost interface {
	Inspect() (managedAccessFacts, error)
	Repair(uint32, uint32, uint32) error
	Restore(managedAccessFacts) error
}

type managedAccessAction struct {
	backend  string
	agentGID uint32
	journal  *Journal
	host     managedAccessHost
}

func newManagedAccessAction(backend string, agentGID uint32, journal *Journal, host managedAccessHost) (*managedAccessAction, error) {
	if (backend != "nginx" && backend != "apache" && backend != "caddy") || agentGID == 0 || journal == nil || host == nil {
		return nil, fmt.Errorf("managed access action is not safely configured")
	}
	return &managedAccessAction{backend: backend, agentGID: agentGID, journal: journal, host: host}, nil
}

func (a *managedAccessAction) Plan(_ context.Context, request helperprotocol.PlanActionRequest) (PlanMaterial, error) {
	if request.Action != helperprotocol.ActionRepairManagedPathAccess || request.LogicalTarget != helperprotocol.LogicalTargetManagedPath {
		return PlanMaterial{}, fmt.Errorf("managed access request does not match compiled action")
	}
	facts, err := a.inspectRepairable()
	if err != nil {
		return PlanMaterial{}, err
	}
	digest, err := helperprotocol.Digest(facts)
	if err != nil {
		return PlanMaterial{}, err
	}
	return PlanMaterial{
		Steps: []helperprotocol.PlanStep{
			{Kind: "snapshot", Summary: "Snapshot owner, group and mode of the exclusive helper staging directory"},
			{Kind: "permissions", Summary: "Restore root:nurproxy 0770 on the exclusive helper staging directory"},
			{Kind: "post_validate", Summary: "Verify no shared backend directory permissions changed"},
		},
		ExecutionPlanHash: digest,
		ResourceFingerprint: recoverypolicy.HardDiagnosticFingerprint(
			recoverymodel.CodePermissionDenied, a.backend, "permission_denied", nil),
		RollbackCoverage: helperprotocol.RollbackCoveragePartial,
	}, nil
}

func (a *managedAccessAction) Rediscover(_ context.Context, _ helperprotocol.HelperPlan) (string, string, error) {
	facts, err := a.inspectRepairable()
	if err != nil {
		return "", "", err
	}
	digest, err := helperprotocol.Digest(facts)
	return digest, recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodePermissionDenied, a.backend, "permission_denied", nil), err
}

func (a *managedAccessAction) Prepare(_ context.Context, operationID string, plan helperprotocol.HelperPlan) (PreparedAction, error) {
	facts, err := a.inspectRepairable()
	if err != nil {
		return PreparedAction{}, err
	}
	digest, err := helperprotocol.Digest(facts)
	if err != nil || (plan.ExecutionPlanHash != "" && digest != plan.ExecutionPlanHash) {
		return PreparedAction{}, fmt.Errorf("managed access facts changed before snapshot")
	}
	snapshotDigest, err := a.journal.StoreSnapshot(operationID, facts)
	if err != nil {
		return PreparedAction{}, err
	}
	return PreparedAction{SnapshotDigest: snapshotDigest, RollbackCoverage: helperprotocol.RollbackCoveragePartial}, nil
}

func (a *managedAccessAction) Execute(_ context.Context, operationID string, plan helperprotocol.HelperPlan, prepared PreparedAction) (ActionResult, error) {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return ActionResult{}, err
	}
	current, err := a.inspectRepairable()
	currentDigest, digestErr := helperprotocol.Digest(current)
	snapshotDigest, snapshotErr := helperprotocol.Digest(snapshot)
	if err != nil || digestErr != nil || snapshotErr != nil || currentDigest != snapshotDigest ||
		(plan.ExecutionPlanHash != "" && currentDigest != plan.ExecutionPlanHash) {
		return ActionResult{}, fmt.Errorf("managed access facts changed after snapshot")
	}
	if err := a.host.Repair(0, a.agentGID, 0o770); err != nil {
		return ActionResult{Mutated: true}, err
	}
	post, err := a.host.Inspect()
	if err != nil || post.Path != agentHelperStageDir || !post.Exists || !post.Directory || post.UID != 0 || post.GID != a.agentGID || post.Mode != 0o770 {
		return ActionResult{Mutated: true}, fmt.Errorf("exclusive staging access postcondition could not be proven")
	}
	return ActionResult{Mutated: true, Validated: true, SanitizedResult: "Exclusive helper staging permissions restored"}, nil
}

func (a *managedAccessAction) Rollback(_ context.Context, operationID string, _ helperprotocol.HelperPlan, prepared PreparedAction) error {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return err
	}
	current, err := a.host.Inspect()
	if err != nil || current.Path != agentHelperStageDir || current.UID != 0 || current.GID != a.agentGID || current.Mode != 0o770 {
		return fmt.Errorf("managed access rollback target changed")
	}
	return a.host.Restore(snapshot)
}

func (a *managedAccessAction) inspectRepairable() (managedAccessFacts, error) {
	facts, err := a.host.Inspect()
	if err != nil {
		return managedAccessFacts{}, err
	}
	if facts.Path != agentHelperStageDir || !facts.Exists || !facts.Directory {
		return managedAccessFacts{}, fmt.Errorf("managed access target is not the exclusive helper staging directory")
	}
	if facts.UID == 0 && facts.GID == a.agentGID && facts.Mode == 0o770 {
		return managedAccessFacts{}, fmt.Errorf("exclusive helper staging access is already correct")
	}
	return facts, nil
}

func (a *managedAccessAction) loadSnapshot(operationID string, prepared PreparedAction) (managedAccessFacts, error) {
	payload, err := a.journal.LoadSnapshot(operationID, prepared.SnapshotDigest)
	if err != nil {
		return managedAccessFacts{}, err
	}
	snapshot, err := helperprotocol.Decode[managedAccessFacts](payload)
	if err != nil || snapshot.Path != agentHelperStageDir || !snapshot.Exists || !snapshot.Directory {
		return managedAccessFacts{}, fmt.Errorf("managed access snapshot is invalid")
	}
	return snapshot, nil
}

type systemManagedAccessHost struct{}

func (systemManagedAccessHost) Inspect() (managedAccessFacts, error) {
	facts := managedAccessFacts{Path: agentHelperStageDir}
	parent := filepath.Dir(agentHelperStageDir)
	if err := validateTrustedDirectory(parent, 0); err != nil {
		return facts, fmt.Errorf("managed staging parent is not root controlled: %w", err)
	}
	info, err := os.Lstat(agentHelperStageDir)
	if err != nil {
		return facts, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return facts, fmt.Errorf("managed staging identity is invalid")
	}
	facts.Exists, facts.Directory = true, true
	facts.UID, facts.GID, facts.Mode = stat.Uid, stat.Gid, uint32(info.Mode().Perm())
	return facts, nil
}

func (systemManagedAccessHost) Repair(uid, gid uint32, mode uint32) error {
	if uid != 0 || gid == 0 || mode != 0o770 {
		return fmt.Errorf("managed access repair arguments are invalid")
	}
	if _, err := (systemManagedAccessHost{}).Inspect(); err != nil {
		return err
	}
	if err := os.Chown(agentHelperStageDir, int(uid), int(gid)); err != nil {
		return err
	}
	if err := os.Chmod(agentHelperStageDir, os.FileMode(mode)); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(agentHelperStageDir))
}

func (systemManagedAccessHost) Restore(snapshot managedAccessFacts) error {
	if snapshot.Path != agentHelperStageDir || !snapshot.Exists || !snapshot.Directory {
		return fmt.Errorf("managed access restore snapshot is invalid")
	}
	if err := os.Chown(agentHelperStageDir, int(snapshot.UID), int(snapshot.GID)); err != nil {
		return err
	}
	if err := os.Chmod(agentHelperStageDir, os.FileMode(snapshot.Mode)); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(agentHelperStageDir))
}
