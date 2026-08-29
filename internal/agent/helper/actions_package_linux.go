//go:build linux

package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

const maxPackageTransactionEntries = 64

type packageTransaction struct {
	Manager    string   `json:"manager"`
	Package    string   `json:"package"`
	Packages   []string `json:"packages"`
	Removals   []string `json:"removals"`
	Downgrade  bool     `json:"downgrade"`
	Repository bool     `json:"repository_change"`
	Digest     string   `json:"simulation_digest"`
}

func (t packageTransaction) Validate() error {
	if !trustedExecutableLocation(t.Manager) || !validPackageName(t.Package) || !validDigest(t.Digest) ||
		len(t.Packages) == 0 || len(t.Packages) > maxPackageTransactionEntries || len(t.Removals) > 0 || t.Downgrade || t.Repository {
		return fmt.Errorf("unsafe or invalid package transaction")
	}
	seen := make(map[string]struct{}, len(t.Packages))
	for _, name := range t.Packages {
		if !validPackageName(name) {
			return fmt.Errorf("invalid package transaction entry")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate package transaction entry")
		}
		seen[name] = struct{}{}
	}
	if _, ok := seen[t.Package]; !ok {
		return fmt.Errorf("simulation does not install the pinned package")
	}
	return nil
}

type packageSnapshot struct {
	Transaction packageTransaction `json:"transaction"`
}

type packageHost interface {
	Simulate(context.Context, PackageTargetConfig) (packageTransaction, error)
	Install(context.Context, PackageTargetConfig) error
	BinaryReady(ProxyTargetConfig) bool
}

type packageInstallAction struct {
	proxyTarget   ProxyTargetConfig
	packageTarget PackageTargetConfig
	journal       *Journal
	host          packageHost
}

func newPackageInstallAction(proxyTarget ProxyTargetConfig, packageTarget PackageTargetConfig, journal *Journal, host packageHost) (*packageInstallAction, error) {
	if err := proxyTarget.Validate(); err != nil || packageTarget.Validate(proxyTarget.Kind) != nil || journal == nil || host == nil {
		return nil, fmt.Errorf("package action is not safely configured")
	}
	return &packageInstallAction{proxyTarget: proxyTarget, packageTarget: packageTarget, journal: journal, host: host}, nil
}

func (a *packageInstallAction) Plan(ctx context.Context, request helperprotocol.PlanActionRequest) (PlanMaterial, error) {
	if request.Action != helperprotocol.ActionInstallSupportedPackage || request.LogicalTarget != helperprotocol.LogicalTargetProxyPackage {
		return PlanMaterial{}, fmt.Errorf("package request does not match compiled handler")
	}
	if a.host.BinaryReady(a.proxyTarget) {
		return PlanMaterial{}, fmt.Errorf("pinned proxy binary is already installed")
	}
	transaction, err := a.safeSimulation(ctx)
	if err != nil {
		return PlanMaterial{}, err
	}
	executionHash, err := helperprotocol.Digest(transaction)
	if err != nil {
		return PlanMaterial{}, err
	}
	return PlanMaterial{
		Steps: []helperprotocol.PlanStep{
			{Kind: "simulate", Summary: fmt.Sprintf("Re-run %s simulation for %s with no removals or downgrades", a.packageTarget.Manager, a.packageTarget.Package)},
			{Kind: "install", Summary: truncateUTF8(fmt.Sprintf("Install %s transaction: %s", a.packageTarget.Package, strings.Join(transaction.Packages, ", ")), 512)},
		},
		ExecutionPlanHash: executionHash,
		ResourceFingerprint: recoverypolicy.HardDiagnosticFingerprint(
			recoverymodel.CodeProxyBinaryMissing, a.proxyTarget.Kind, "binary_missing", nil,
		),
		RollbackCoverage: helperprotocol.RollbackCoveragePartial,
	}, nil
}

func (a *packageInstallAction) Rediscover(ctx context.Context, plan helperprotocol.HelperPlan) (string, string, error) {
	if plan.Action != helperprotocol.ActionInstallSupportedPackage || a.host.BinaryReady(a.proxyTarget) {
		return "", "", fmt.Errorf("package install precondition changed")
	}
	transaction, err := a.safeSimulation(ctx)
	if err != nil {
		return "", "", err
	}
	executionHash, err := helperprotocol.Digest(transaction)
	return executionHash, recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeProxyBinaryMissing, a.proxyTarget.Kind, "binary_missing", nil), err
}

func (a *packageInstallAction) Prepare(ctx context.Context, operationID string, plan helperprotocol.HelperPlan) (PreparedAction, error) {
	transaction, err := a.safeSimulation(ctx)
	if err != nil {
		return PreparedAction{}, err
	}
	executionHash, err := helperprotocol.Digest(transaction)
	if err != nil || (plan.ExecutionPlanHash != "" && executionHash != plan.ExecutionPlanHash) {
		return PreparedAction{}, fmt.Errorf("package transaction changed before snapshot")
	}
	digest, err := a.journal.StoreSnapshot(operationID, packageSnapshot{Transaction: transaction})
	if err != nil {
		return PreparedAction{}, err
	}
	return PreparedAction{SnapshotDigest: digest, RollbackCoverage: helperprotocol.RollbackCoveragePartial}, nil
}

func (a *packageInstallAction) Execute(ctx context.Context, operationID string, _ helperprotocol.HelperPlan, prepared PreparedAction) (ActionResult, error) {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return ActionResult{}, err
	}
	transaction, err := a.safeSimulation(ctx)
	if err != nil || !equalPackageTransaction(transaction, snapshot.Transaction) {
		return ActionResult{}, fmt.Errorf("package transaction changed after authorization")
	}
	if err := a.host.Install(ctx, a.packageTarget); err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("package installation failed: %w", err)
	}
	if !a.host.BinaryReady(a.proxyTarget) {
		return ActionResult{Mutated: true}, fmt.Errorf("pinned proxy binary is not trusted after package installation")
	}
	return ActionResult{Mutated: true, Validated: true, SanitizedResult: fmt.Sprintf("installed %s through the authorized transaction", a.packageTarget.Package)}, nil
}

func (a *packageInstallAction) Rollback(context.Context, string, helperprotocol.HelperPlan, PreparedAction) error {
	return fmt.Errorf("package-manager side effects are not fully reversible")
}

func (a *packageInstallAction) safeSimulation(ctx context.Context) (packageTransaction, error) {
	transaction, err := a.host.Simulate(ctx, a.packageTarget)
	if transaction.Packages == nil {
		transaction.Packages = []string{}
	}
	if transaction.Removals == nil {
		transaction.Removals = []string{}
	}
	if err != nil || transaction.Validate() != nil || transaction.Manager != a.packageTarget.Manager || transaction.Package != a.packageTarget.Package {
		return packageTransaction{}, fmt.Errorf("package simulation is unsafe or unavailable")
	}
	return transaction, nil
}

func (a *packageInstallAction) loadSnapshot(operationID string, prepared PreparedAction) (packageSnapshot, error) {
	payload, err := a.journal.LoadSnapshot(operationID, prepared.SnapshotDigest)
	if err != nil {
		return packageSnapshot{}, err
	}
	snapshot, err := helperprotocol.Decode[packageSnapshot](payload)
	if err != nil {
		return packageSnapshot{}, fmt.Errorf("decode privileged package snapshot: %w", err)
	}
	if err := snapshot.Transaction.Validate(); err != nil {
		return packageSnapshot{}, fmt.Errorf("privileged package snapshot is invalid: %w", err)
	}
	return snapshot, nil
}

func equalPackageTransaction(left, right packageTransaction) bool {
	leftDigest, leftErr := helperprotocol.Digest(left)
	rightDigest, rightErr := helperprotocol.Digest(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

type systemPackageHost struct{}

func (systemPackageHost) Simulate(ctx context.Context, target PackageTargetConfig) (packageTransaction, error) {
	if _, err := trustedRegularFileDigest(target.Manager, maxTrustedBinaryBytes); err != nil {
		return packageTransaction{}, err
	}
	if target.Manager != "/usr/bin/apt-get" {
		return packageTransaction{}, fmt.Errorf("unsupported package manager")
	}
	out, err := runBounded(ctx, target.Manager, "-s", "--no-remove", "--reinstall", "-o", "Dpkg::Options::=--force-confold", "install", target.Package)
	if err != nil {
		return packageTransaction{}, err
	}
	return parseAPTSimulation(target, out)
}

func (systemPackageHost) Install(ctx context.Context, target PackageTargetConfig) error {
	if target.Manager != "/usr/bin/apt-get" {
		return fmt.Errorf("unsupported package manager")
	}
	_, err := runBounded(ctx, target.Manager, "-y", "--no-remove", "--reinstall", "-o", "Dpkg::Options::=--force-confold", "install", target.Package)
	return err
}

func (systemPackageHost) BinaryReady(target ProxyTargetConfig) bool {
	_, err := trustedRegularFileDigest(target.Binary, maxTrustedBinaryBytes)
	return err == nil
}

func parseAPTSimulation(target PackageTargetConfig, output string) (packageTransaction, error) {
	normalized := strings.ReplaceAll(output, "\r\n", "\n")
	digest := sha256.Sum256([]byte(normalized))
	transaction := packageTransaction{Manager: target.Manager, Package: target.Package, Digest: hex.EncodeToString(digest[:])}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(normalized, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Inst":
			if len(fields) < 2 || !validPackageName(fields[1]) {
				return packageTransaction{}, fmt.Errorf("invalid apt install entry")
			}
			if _, exists := seen[fields[1]]; !exists {
				seen[fields[1]] = struct{}{}
				transaction.Packages = append(transaction.Packages, fields[1])
			}
		case "Remv", "Purg":
			if len(fields) > 1 {
				transaction.Removals = append(transaction.Removals, fields[1])
			}
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "downgrad") {
			transaction.Downgrade = true
		}
		if strings.Contains(lower, "repository") && strings.Contains(lower, "add") {
			transaction.Repository = true
		}
	}
	sort.Strings(transaction.Packages)
	sort.Strings(transaction.Removals)
	if err := transaction.Validate(); err != nil {
		return packageTransaction{}, err
	}
	return transaction, nil
}

func validPackageName(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("+.-", r) {
			return false
		}
	}
	return true
}
