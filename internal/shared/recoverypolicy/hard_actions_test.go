package recoverypolicy

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestHardActionForDiagnosticIsClosedAndDeterministic(t *testing.T) {
	tests := []struct {
		code   recoverymodel.Code
		scope  recoverymodel.RepairScope
		action helperprotocol.Action
		target helperprotocol.LogicalTarget
		ok     bool
	}{
		{recoverymodel.CodeSystemdSandboxDenied, recoverymodel.RepairScopeAgentSandbox, helperprotocol.ActionRepairAgentSandboxPaths, helperprotocol.LogicalTargetAgentUnit, true},
		{recoverymodel.CodePermissionDenied, recoverymodel.RepairScopeExactProvenancedFile, helperprotocol.ActionRepairManagedPathAccess, helperprotocol.LogicalTargetManagedPath, true},
		{recoverymodel.CodePermissionDenied, recoverymodel.RepairScopeExclusiveManagedDirectory, helperprotocol.ActionRepairManagedPathAccess, helperprotocol.LogicalTargetManagedPath, true},
		{recoverymodel.CodePermissionDenied, recoverymodel.RepairScopeSharedBackendNamespace, "", "", false},
		{recoverymodel.CodeProxyReloadFailed, recoverymodel.RepairScopeDetectedProxyService, helperprotocol.ActionValidateReloadProxy, helperprotocol.LogicalTargetDetectedProxy, true},
		{recoverymodel.CodeProxyNotRunning, recoverymodel.RepairScopeDetectedProxyService, helperprotocol.ActionStartProxy, helperprotocol.LogicalTargetDetectedProxy, true},
		{recoverymodel.CodeProxyBinaryMissing, recoverymodel.RepairScopeSupportedPackage, helperprotocol.ActionInstallSupportedPackage, helperprotocol.LogicalTargetProxyPackage, true},
		{recoverymodel.CodePortConflict, recoverymodel.RepairScopeUnsupportedEnvironment, "", "", false},
	}
	for _, tt := range tests {
		action, target, ok := HardActionForDiagnostic(tt.code, tt.scope)
		if action != tt.action || target != tt.target || ok != tt.ok {
			t.Fatalf("mapping (%q, %q) = (%q, %q, %v)", tt.code, tt.scope, action, target, ok)
		}
	}
}

func TestHardDiagnosticFingerprintIsCanonicalAndOrderIndependent(t *testing.T) {
	first := HardDiagnosticFingerprint(recoverymodel.CodeProxyReloadFailed, "nginx", "reload_failed", []string{"/b", "/a"})
	second := HardDiagnosticFingerprint(recoverymodel.CodeProxyReloadFailed, "nginx", "reload_failed", []string{"/a", "/b"})
	if first != second {
		t.Fatalf("fingerprint depends on path order: %q != %q", first, second)
	}
	if len(first) != 64 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint is not canonical SHA-256: %q", first)
	}
	if first == HardDiagnosticFingerprint(recoverymodel.CodeProxyNotRunning, "nginx", "proxy_not_running", nil) {
		t.Fatal("distinct hard diagnostics share a fingerprint")
	}
}
