package recoverypolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func HardDiagnosticFingerprint(code recoverymodel.Code, backend, evidenceClass string, paths []string) string {
	values := []string{string(code), backend, evidenceClass}
	canonicalPaths := append([]string(nil), paths...)
	sort.Strings(canonicalPaths)
	values = append(values, canonicalPaths...)
	h := sha256.New()
	for _, value := range values {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

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
