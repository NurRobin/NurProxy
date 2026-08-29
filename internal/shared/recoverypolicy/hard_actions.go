package recoverypolicy

import (
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func HardActionForDiagnostic(code recoverymodel.Code, scope recoverymodel.RepairScope) (helperprotocol.Action, helperprotocol.LogicalTarget, bool) {
	switch code {
	case recoverymodel.CodeSystemdSandboxDenied:
		if scope == recoverymodel.RepairScopeAgentSandbox {
			return helperprotocol.ActionRepairAgentSandboxPaths, helperprotocol.LogicalTargetAgentUnit, true
		}
	case recoverymodel.CodePermissionDenied:
		if scope == recoverymodel.RepairScopeExactProvenancedFile || scope == recoverymodel.RepairScopeExclusiveManagedDirectory {
			return helperprotocol.ActionRepairManagedPathAccess, helperprotocol.LogicalTargetManagedPath, true
		}
	case recoverymodel.CodeProxyReloadFailed:
		if scope == recoverymodel.RepairScopeDetectedProxyService {
			return helperprotocol.ActionValidateReloadProxy, helperprotocol.LogicalTargetDetectedProxy, true
		}
	case recoverymodel.CodeProxyNotRunning:
		if scope == recoverymodel.RepairScopeDetectedProxyService {
			return helperprotocol.ActionStartProxy, helperprotocol.LogicalTargetDetectedProxy, true
		}
	case recoverymodel.CodeProxyBinaryMissing:
		if scope == recoverymodel.RepairScopeSupportedPackage {
			return helperprotocol.ActionInstallSupportedPackage, helperprotocol.LogicalTargetProxyPackage, true
		}
	}
	return "", "", false
}
