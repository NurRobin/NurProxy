package recoverypolicy

import (
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
