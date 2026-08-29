//go:build linux

package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

const (
	agentUnitName       = "nurproxy-agent.service"
	agentSandboxDropIn  = "/etc/systemd/system/nurproxy-agent.service.d/50-nurproxy-recovery-paths.conf"
	agentStateDir       = "/var/lib/nurproxy-agent/state"
	agentHelperStageDir = "/var/lib/nurproxy-agent/helper-staging"
)

var agentSandboxContent = []byte(proxy.StampManagedArtifact("[Service]\nReadWritePaths=" + agentStateDir + " " + agentHelperStageDir + "\n"))

type agentSandboxFacts struct {
	Unit            string `json:"unit"`
	LoadState       string `json:"load_state"`
	Active          bool   `json:"active"`
	StateWritable   bool   `json:"state_writable"`
	StagingWritable bool   `json:"staging_writable"`
	DropInExists    bool   `json:"drop_in_exists"`
	DropInDigest    string `json:"drop_in_digest"`
	DropInMode      uint32 `json:"drop_in_mode"`
	DropInUID       uint32 `json:"drop_in_uid"`
	DropInGID       uint32 `json:"drop_in_gid"`
	DropInContent   []byte `json:"drop_in_content"`
}

type agentSandboxHost interface {
	Inspect(context.Context) (agentSandboxFacts, error)
	Install(context.Context) error
	Restore(context.Context, agentSandboxFacts) error
}

type agentSandboxAction struct {
	backend string
	journal *Journal
	host    agentSandboxHost
}

func newAgentSandboxAction(backend string, journal *Journal, host agentSandboxHost) (*agentSandboxAction, error) {
	if (backend != "nginx" && backend != "apache" && backend != "caddy") || journal == nil || host == nil {
		return nil, fmt.Errorf("agent sandbox action is not safely configured")
	}
	return &agentSandboxAction{backend: backend, journal: journal, host: host}, nil
}

func (a *agentSandboxAction) Plan(ctx context.Context, request helperprotocol.PlanActionRequest) (PlanMaterial, error) {
	if request.Action != helperprotocol.ActionRepairAgentSandboxPaths || request.LogicalTarget != helperprotocol.LogicalTargetAgentUnit {
		return PlanMaterial{}, fmt.Errorf("sandbox request does not match compiled action")
	}
	facts, err := a.inspectRepairable(ctx)
	if err != nil {
		return PlanMaterial{}, err
	}
	executionHash, err := sandboxFactsDigest(facts)
	if err != nil {
		return PlanMaterial{}, err
	}
	return PlanMaterial{
		Steps: []helperprotocol.PlanStep{
			{Kind: "snapshot", Summary: "Snapshot the exact NurProxy agent systemd drop-in and unit state"},
			{Kind: "write", Summary: "Install the exact state and helper-staging write paths"},
			{Kind: "restart", Summary: "Reload systemd and restart nurproxy-agent.service"},
			{Kind: "post_validate", Summary: "Verify the effective unit exposes only the required managed paths"},
		},
		ExecutionPlanHash: executionHash,
		ResourceFingerprint: recoverypolicy.HardDiagnosticFingerprint(
			recoverymodel.CodeSystemdSandboxDenied, a.backend, "systemd_sandbox", nil),
		RollbackCoverage: helperprotocol.RollbackCoveragePartial,
	}, nil
}

func (a *agentSandboxAction) Rediscover(ctx context.Context, _ helperprotocol.HelperPlan) (string, string, error) {
	facts, err := a.inspectRepairable(ctx)
	if err != nil {
		return "", "", err
	}
	digest, err := sandboxFactsDigest(facts)
	return digest, recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeSystemdSandboxDenied, a.backend, "systemd_sandbox", nil), err
}

func (a *agentSandboxAction) Prepare(ctx context.Context, operationID string, plan helperprotocol.HelperPlan) (PreparedAction, error) {
	facts, err := a.inspectRepairable(ctx)
	if err != nil {
		return PreparedAction{}, err
	}
	digest, err := sandboxFactsDigest(facts)
	if err != nil || (plan.ExecutionPlanHash != "" && digest != plan.ExecutionPlanHash) {
		return PreparedAction{}, fmt.Errorf("agent sandbox facts changed before snapshot")
	}
	snapshotDigest, err := a.journal.StoreSnapshot(operationID, facts)
	if err != nil {
		return PreparedAction{}, err
	}
	return PreparedAction{SnapshotDigest: snapshotDigest, RollbackCoverage: helperprotocol.RollbackCoveragePartial}, nil
}

func (a *agentSandboxAction) Execute(ctx context.Context, operationID string, plan helperprotocol.HelperPlan, prepared PreparedAction) (ActionResult, error) {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return ActionResult{}, err
	}
	current, err := a.inspectRepairable(ctx)
	currentDigest, digestErr := sandboxFactsDigest(current)
	snapshotDigest, snapshotDigestErr := sandboxFactsDigest(snapshot)
	if err != nil || digestErr != nil || snapshotDigestErr != nil || currentDigest != snapshotDigest ||
		(plan.ExecutionPlanHash != "" && currentDigest != plan.ExecutionPlanHash) {
		return ActionResult{}, fmt.Errorf("agent sandbox facts changed after snapshot")
	}
	if err := a.host.Install(ctx); err != nil {
		return ActionResult{Mutated: true}, err
	}
	post, err := a.host.Inspect(ctx)
	if err != nil || !post.Active || post.LoadState != "loaded" || !post.StateWritable || !post.StagingWritable || !post.DropInExists || post.DropInDigest != sandboxManagedDigest() {
		return ActionResult{Mutated: true}, fmt.Errorf("agent sandbox postcondition could not be proven")
	}
	return ActionResult{Mutated: true, Validated: true, SanitizedResult: "NurProxy agent sandbox paths installed and unit restarted"}, nil
}

func (a *agentSandboxAction) Rollback(ctx context.Context, operationID string, _ helperprotocol.HelperPlan, prepared PreparedAction) error {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return err
	}
	return a.host.Restore(ctx, snapshot)
}

func (a *agentSandboxAction) inspectRepairable(ctx context.Context) (agentSandboxFacts, error) {
	facts, err := a.host.Inspect(ctx)
	if err != nil {
		return agentSandboxFacts{}, err
	}
	if facts.Unit != agentUnitName || facts.LoadState != "loaded" || !facts.Active {
		return agentSandboxFacts{}, fmt.Errorf("installed agent unit is not uniquely active")
	}
	if facts.DropInExists && facts.DropInDigest != sandboxManagedDigest() {
		return agentSandboxFacts{}, fmt.Errorf("sandbox drop-in is not exact NurProxy provenance")
	}
	if facts.DropInExists && (!facts.StateWritable || !facts.StagingWritable) {
		return agentSandboxFacts{}, fmt.Errorf("effective unit conflicts with the NurProxy sandbox drop-in")
	}
	if facts.StateWritable && facts.StagingWritable {
		return agentSandboxFacts{}, fmt.Errorf("agent sandbox already exposes required paths")
	}
	return facts, nil
}

func (a *agentSandboxAction) loadSnapshot(operationID string, prepared PreparedAction) (agentSandboxFacts, error) {
	payload, err := a.journal.LoadSnapshot(operationID, prepared.SnapshotDigest)
	if err != nil {
		return agentSandboxFacts{}, err
	}
	snapshot, err := helperprotocol.Decode[agentSandboxFacts](payload)
	if err != nil || snapshot.Unit != agentUnitName {
		return agentSandboxFacts{}, fmt.Errorf("agent sandbox snapshot is invalid")
	}
	return snapshot, nil
}

func sandboxFactsDigest(facts agentSandboxFacts) (string, error) {
	copy := facts
	copy.DropInContent = nil
	return helperprotocol.Digest(copy)
}

func sandboxManagedDigest() string {
	digest := sha256.Sum256(agentSandboxContent)
	return hex.EncodeToString(digest[:])
}

type systemAgentSandboxHost struct {
	systemctl string
}

func (h systemAgentSandboxHost) Inspect(ctx context.Context) (agentSandboxFacts, error) {
	facts := agentSandboxFacts{Unit: agentUnitName, DropInContent: []byte{}}
	output, err := runBounded(ctx, h.systemctl, "show", agentUnitName, "--property=LoadState", "--property=ActiveState", "--property=ReadWritePaths")
	if err != nil {
		return facts, err
	}
	properties := parseSystemdProperties(output)
	facts.LoadState, facts.Active = properties["LoadState"], properties["ActiveState"] == "active"
	for _, token := range strings.Fields(properties["ReadWritePaths"]) {
		path := strings.TrimLeft(token, "-+")
		facts.StateWritable = facts.StateWritable || path == agentStateDir
		facts.StagingWritable = facts.StagingWritable || path == agentHelperStageDir
	}
	info, err := os.Lstat(agentSandboxDropIn)
	if errors.Is(err, os.ErrNotExist) {
		return facts, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > MaxRootConfigBytes {
		return facts, fmt.Errorf("sandbox drop-in identity is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return facts, fmt.Errorf("sandbox drop-in ownership is invalid")
	}
	content, err := readNoFollowFile(agentSandboxDropIn, info.Size())
	if err != nil {
		return facts, err
	}
	digest := sha256.Sum256(content)
	facts.DropInExists, facts.DropInContent = true, content
	facts.DropInDigest, facts.DropInMode = hex.EncodeToString(digest[:]), uint32(info.Mode().Perm())
	facts.DropInUID, facts.DropInGID = stat.Uid, stat.Gid
	return facts, nil
}

func (h systemAgentSandboxHost) Install(ctx context.Context) error {
	if err := writeSandboxDropIn(agentSandboxContent, 0o644); err != nil {
		return err
	}
	if _, err := runBounded(ctx, h.systemctl, "daemon-reload"); err != nil {
		return err
	}
	_, err := runBounded(ctx, h.systemctl, "restart", agentUnitName)
	return err
}

func (h systemAgentSandboxHost) Restore(ctx context.Context, snapshot agentSandboxFacts) error {
	current, err := h.Inspect(ctx)
	if err != nil || !current.DropInExists || current.DropInDigest != sandboxManagedDigest() {
		return fmt.Errorf("sandbox rollback target is not exact NurProxy provenance")
	}
	if snapshot.DropInExists {
		if err := writeSandboxDropIn(snapshot.DropInContent, os.FileMode(snapshot.DropInMode)); err != nil {
			return err
		}
		if err := os.Chown(agentSandboxDropIn, int(snapshot.DropInUID), int(snapshot.DropInGID)); err != nil {
			return err
		}
	} else if err := os.Remove(agentSandboxDropIn); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(agentSandboxDropIn)); err != nil {
		return err
	}
	if _, err := runBounded(ctx, h.systemctl, "daemon-reload"); err != nil {
		return err
	}
	_, err = runBounded(ctx, h.systemctl, "restart", agentUnitName)
	return err
}

func writeSandboxDropIn(content []byte, mode os.FileMode) error {
	directory := filepath.Dir(agentSandboxDropIn)
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(directory)
		if err := validateTrustedDirectory(parent, 0); err != nil {
			return err
		}
		if err := os.Mkdir(directory, 0o755); err != nil {
			return err
		}
		if err := syncDirectory(parent); err != nil {
			return err
		}
	}
	if err := validateTrustedDirectory(directory, 0); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".nurproxy-sandbox-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(mode.Perm()); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, agentSandboxDropIn); err != nil {
		return err
	}
	return syncDirectory(directory)
}
