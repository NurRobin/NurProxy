//go:build linux

package helper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

type fakePackageHost struct {
	transaction packageTransaction
	ready       bool
	installed   int
}

func (h *fakePackageHost) Simulate(context.Context, PackageTargetConfig) (packageTransaction, error) {
	return h.transaction, nil
}

func (h *fakePackageHost) Install(context.Context, PackageTargetConfig) error {
	h.installed++
	h.ready = true
	return nil
}

func (h *fakePackageHost) BinaryReady(ProxyTargetConfig) bool { return h.ready }

func newPackageActionTest(t *testing.T) (*packageInstallAction, *fakePackageHost) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(filepath.Join(root, "journal"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	proxyTarget := ProxyTargetConfig{Kind: "nginx", Binary: "/usr/sbin/nginx", Unit: "nginx.service", SystemctlBinary: "/usr/bin/systemctl", ConfigRoots: []string{"/etc/nginx"}}
	packageTarget := PackageTargetConfig{Manager: "/usr/bin/apt-get", Package: "nginx"}
	host := &fakePackageHost{transaction: packageTransaction{Manager: packageTarget.Manager, Package: packageTarget.Package, Packages: []string{"nginx", "nginx-common"}, Digest: repeatedDigest("c")}}
	handler, err := newPackageInstallAction(proxyTarget, packageTarget, journal, host)
	if err != nil {
		t.Fatal(err)
	}
	return handler, host
}

func TestPackageInstallActionBindsSimulationAndDiagnostic(t *testing.T) {
	handler, _ := newPackageActionTest(t)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionInstallSupportedPackage, LogicalTarget: helperprotocol.LogicalTargetProxyPackage, DiagnosticReference: "diagnostic-1"}
	material, err := handler.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeProxyBinaryMissing, "nginx", "binary_missing", nil)
	if material.ResourceFingerprint != want || material.RollbackCoverage != helperprotocol.RollbackCoveragePartial || len(material.Steps) != 2 {
		t.Fatalf("unexpected package plan: %+v", material)
	}
}

func TestPackageInstallActionRejectsUnsafeSimulation(t *testing.T) {
	handler, host := newPackageActionTest(t)
	host.transaction.Removals = []string{"operator-package"}
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionInstallSupportedPackage, LogicalTarget: helperprotocol.LogicalTargetProxyPackage, DiagnosticReference: "diagnostic-1"}
	if _, err := handler.Plan(context.Background(), request); err == nil {
		t.Fatal("package plan with removals accepted")
	}
}

func TestPackageInstallActionRepeatsSimulationBeforeInstall(t *testing.T) {
	handler, host := newPackageActionTest(t)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionInstallSupportedPackage, LogicalTarget: helperprotocol.LogicalTargetProxyPackage, DiagnosticReference: "diagnostic-1"}
	material, err := handler.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.HelperPlan{Action: request.Action, ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
	prepared, err := handler.Prepare(context.Background(), "operation-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := handler.Execute(context.Background(), "operation-1", plan, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if host.installed != 1 || !result.Mutated || !result.Validated {
		t.Fatalf("package install did not complete: result=%+v installs=%d", result, host.installed)
	}
}

func TestPackageInstallActionRefusesChangedTransaction(t *testing.T) {
	handler, host := newPackageActionTest(t)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionInstallSupportedPackage, LogicalTarget: helperprotocol.LogicalTargetProxyPackage, DiagnosticReference: "diagnostic-1"}
	material, err := handler.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.HelperPlan{Action: request.Action, ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
	prepared, err := handler.Prepare(context.Background(), "operation-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	host.transaction.Digest = repeatedDigest("d")
	result, err := handler.Execute(context.Background(), "operation-1", plan, prepared)
	if err == nil || result.Mutated || host.installed != 0 {
		t.Fatalf("changed transaction executed: result=%+v err=%v installs=%d", result, err, host.installed)
	}
}

func TestParseAPTSimulationRejectsRemovalAndCapturesExactInstallSet(t *testing.T) {
	target := PackageTargetConfig{Manager: "/usr/bin/apt-get", Package: "nginx"}
	transaction, err := parseAPTSimulation(target, "Inst nginx-common (1.24 repo [amd64])\nInst nginx (1.24 repo [amd64])\nConf nginx\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(transaction.Packages) != 2 || transaction.Packages[0] != "nginx" || transaction.Packages[1] != "nginx-common" {
		t.Fatalf("unexpected transaction: %+v", transaction)
	}
	if _, err := parseAPTSimulation(target, "Inst nginx (1.24 repo [amd64])\nRemv operator-package [1.0]\n"); err == nil {
		t.Fatal("apt removal was accepted")
	}
}
