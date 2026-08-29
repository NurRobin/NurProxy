//go:build linux

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

type fakeProxyServiceHost struct {
	facts       proxyServiceFacts
	inspectErr  error
	validateErr error
	mutateErr   error
	mutations   []proxyServiceMutation
	validations int
}

func (h *fakeProxyServiceHost) Inspect(context.Context, ProxyTargetConfig) (proxyServiceFacts, error) {
	return h.facts, h.inspectErr
}

func (h *fakeProxyServiceHost) Validate(context.Context, ProxyTargetConfig) error {
	h.validations++
	return h.validateErr
}

func (h *fakeProxyServiceHost) Mutate(_ context.Context, _ ProxyTargetConfig, mutation proxyServiceMutation) error {
	h.mutations = append(h.mutations, mutation)
	if h.mutateErr != nil {
		return h.mutateErr
	}
	switch mutation {
	case proxyServiceStart, proxyServiceRestart, proxyServiceReload:
		h.facts.Active = true
	case proxyServiceStop:
		h.facts.Active = false
	}
	return nil
}

func newProxyActionTest(t *testing.T, action helperprotocol.Action, active bool) (*proxyServiceAction, *fakeProxyServiceHost, *Journal) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(filepath.Join(root, "journal"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	target := ProxyTargetConfig{Kind: "nginx", Binary: "/usr/sbin/nginx", Unit: "nginx.service", SystemctlBinary: "/usr/bin/systemctl", ConfigRoots: []string{"/etc/nginx"}}
	host := &fakeProxyServiceHost{facts: proxyServiceFacts{
		Kind: "nginx", BinaryPath: "/usr/sbin/nginx", BinaryDigest: repeatedDigest("a"), Unit: "nginx.service",
		LoadState: "loaded", Active: active, ConfigDigest: repeatedDigest("b"),
	}}
	handler, err := newProxyServiceAction(action, target, journal, host)
	if err != nil {
		t.Fatal(err)
	}
	return handler, host, journal
}

func TestProxyServiceActionPlansFromLocalFactsAndSharedDiagnosticIdentity(t *testing.T) {
	handler, _, _ := newProxyActionTest(t, helperprotocol.ActionValidateReloadProxy, true)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionValidateReloadProxy, LogicalTarget: helperprotocol.LogicalTargetDetectedProxy, DiagnosticReference: "diagnostic-1"}
	material, err := handler.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint := recoverypolicy.HardDiagnosticFingerprint(recoverymodel.CodeProxyReloadFailed, "nginx", "reload_failed", nil)
	if material.ResourceFingerprint != wantFingerprint || material.RollbackCoverage != helperprotocol.RollbackCoveragePartial {
		t.Fatalf("unexpected material: %+v", material)
	}
	if len(material.Steps) != 3 || material.ExecutionPlanHash == "" {
		t.Fatalf("plan is not concrete: %+v", material)
	}
}

func TestProxyServiceActionRediscoveryDetectsChangedServiceState(t *testing.T) {
	handler, host, _ := newProxyActionTest(t, helperprotocol.ActionStartProxy, false)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionStartProxy, LogicalTarget: helperprotocol.LogicalTargetDetectedProxy, DiagnosticReference: "diagnostic-1"}
	material, err := handler.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.HelperPlan{Action: request.Action}
	host.facts.Active = true
	executionHash, _, err := handler.Rediscover(context.Background(), plan)
	if err == nil && executionHash == material.ExecutionPlanHash {
		t.Fatal("service state change did not stale the plan")
	}
}

func TestProxyServiceReloadValidatesImmediatelyBeforeAndAfterMutation(t *testing.T) {
	handler, host, _ := newProxyActionTest(t, helperprotocol.ActionValidateReloadProxy, true)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionValidateReloadProxy, LogicalTarget: helperprotocol.LogicalTargetDetectedProxy, DiagnosticReference: "diagnostic-1"}
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
	if !result.Mutated || !result.Validated || host.validations != 2 || len(host.mutations) != 1 || host.mutations[0] != proxyServiceReload {
		t.Fatalf("unexpected execution: result=%+v validations=%d mutations=%v", result, host.validations, host.mutations)
	}
}

func TestProxyServiceStartRollbackRestoresInactivePreState(t *testing.T) {
	handler, host, _ := newProxyActionTest(t, helperprotocol.ActionStartProxy, false)
	request := helperprotocol.PlanActionRequest{RequestID: "request-1", Action: helperprotocol.ActionStartProxy, LogicalTarget: helperprotocol.LogicalTargetDetectedProxy, DiagnosticReference: "diagnostic-1"}
	material, err := handler.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.HelperPlan{Action: request.Action, ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
	prepared, err := handler.Prepare(context.Background(), "operation-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Execute(context.Background(), "operation-1", plan, prepared); err != nil {
		t.Fatal(err)
	}
	if err := handler.Rollback(context.Background(), "operation-1", plan, prepared); err != nil {
		t.Fatal(err)
	}
	if host.facts.Active || len(host.mutations) != 2 || host.mutations[1] != proxyServiceStop {
		t.Fatalf("pre-state was not restored: active=%v mutations=%v", host.facts.Active, host.mutations)
	}
}

func TestProxyServiceActionFailsBeforeMutationWhenValidationFails(t *testing.T) {
	handler, host, _ := newProxyActionTest(t, helperprotocol.ActionValidateReloadProxy, true)
	host.validateErr = errors.New("invalid configuration")
	plan := helperprotocol.HelperPlan{Action: helperprotocol.ActionValidateReloadProxy, RollbackCoverage: helperprotocol.RollbackCoveragePartial}
	prepared, err := handler.Prepare(context.Background(), "operation-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := handler.Execute(context.Background(), "operation-1", plan, prepared)
	if err == nil || result.Mutated || len(host.mutations) != 0 {
		t.Fatalf("invalid configuration reached mutation: result=%+v err=%v mutations=%v", result, err, host.mutations)
	}
}

func TestTrustedProxyConfigEntryRejectsAgentOwnedButAllowsReadOnlyOperatorFile(t *testing.T) {
	agentUID := uint32(991)
	for _, test := range []struct {
		name  string
		owner uint32
		mode  os.FileMode
		want  bool
	}{
		{name: "root file", owner: 0, mode: 0o644, want: true},
		{name: "read only operator file", owner: 1000, mode: 0o644, want: true},
		{name: "agent owned file", owner: agentUID, mode: 0o400, want: false},
		{name: "group writable operator file", owner: 1000, mode: 0o664, want: false},
		{name: "world writable operator file", owner: 1000, mode: 0o646, want: false},
		{name: "operator symlink", owner: 1000, mode: os.ModeSymlink | 0o777, want: true},
		{name: "agent symlink", owner: agentUID, mode: os.ModeSymlink | 0o777, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := trustedProxyConfigEntry(test.owner, test.mode, agentUID); got != test.want {
				t.Fatalf("trustedProxyConfigEntry(%d, %v, %d) = %v, want %v", test.owner, test.mode, agentUID, got, test.want)
			}
		})
	}
}

func repeatedDigest(value string) string {
	var result string
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
