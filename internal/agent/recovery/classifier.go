package recovery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type DesiredResource struct {
	ArtifactID  string
	Host        string
	Target      proxy.Target
	Source      models.ArtifactSource
	Drifted     bool
	ApplyState  models.ArtifactApplyState
	ValidBundle bool
}

type Context struct {
	AgentID          string
	ProxyInfo        proxy.Info
	ManagedRoots     []string
	AgentDataRoot    string
	DesiredResources []DesiredResource
}

type classification struct {
	code          recoverymodel.Code
	ownership     recoverymodel.Ownership
	action        recoverymodel.Action
	eligible      bool
	hardChange    bool
	evidenceClass string
}

func Classify(ctx Context, err error) recoverymodel.Diagnostic {
	now := time.Now().UTC()
	backend := normalizedBackend(ctx.ProxyInfo.Kind)
	evidence := ""
	var failure *proxy.Failure
	if errors.As(err, &failure) && failure != nil {
		if normalized := normalizedBackend(failure.Backend); normalized != proxy.KindUnknown {
			backend = normalized
		}
		evidence = failure.Output
	}
	if evidence == "" && err != nil {
		evidence = err.Error()
	}
	evidence = recoverymodel.SanitizeEvidence(evidence)

	guarded, resource, markerInManagedLayout := resolveFailureResource(ctx, failure)
	result := classifyFailure(failure, guarded, resource, markerInManagedLayout)
	paths := make([]string, 0, 1)
	fingerprintPaths := make([]string, 0, 1)
	if guarded != nil {
		paths = append(paths, guarded.Path)
		fingerprintPaths = append(fingerprintPaths, guarded.ResolvedPath)
	}
	fingerprint := fingerprint(result.code, backend, result.evidenceClass, fingerprintPaths)
	diagnostic := recoverymodel.Diagnostic{
		Code: result.code, Subsystem: "proxy", Severity: recoverymodel.SeverityError,
		Ownership: result.ownership, Summary: summaryFor(result.code), Evidence: evidence,
		AffectedPaths: paths, ResourceFingerprint: fingerprint, ProposedAction: result.action,
		AutoRepairEligible: result.eligible, HardChange: result.hardChange,
		FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
	diagnostic.ID = recoverymodel.StableDiagnosticID(ctx.AgentID, diagnostic.Code, fingerprint)
	if diagnostic.Validate() != nil {
		return fallbackDiagnostic(ctx.AgentID, backend, now)
	}
	return diagnostic
}

func resolveFailureResource(ctx Context, failure *proxy.Failure) (*GuardedPath, *DesiredResource, bool) {
	if failure == nil || !failure.Located || failure.File == "" {
		return nil, nil, false
	}
	roots := append([]string(nil), ctx.ManagedRoots...)
	if ctx.AgentDataRoot != "" {
		roots = append(roots, ctx.AgentDataRoot)
	}
	guard, err := NewPathGuard(roots...)
	if err != nil {
		return nil, nil, false
	}
	checked, err := guard.Resolve(failure.File)
	if err != nil {
		return nil, nil, false
	}
	markerInManagedLayout := pathResolvesUnderRoots(failure.File, ctx.ManagedRoots)
	for i := range ctx.DesiredResources {
		desired := &ctx.DesiredResources[i]
		if desired.Target.Kind != proxy.TargetKindFile || desired.Target.Path == "" {
			continue
		}
		desiredPath, resolveErr := guard.Resolve(desired.Target.Path)
		if resolveErr != nil {
			continue
		}
		if pathsIdentifySameResource(checked, desiredPath) {
			return &checked, desired, markerInManagedLayout
		}
	}
	return &checked, nil, markerInManagedLayout
}

func pathResolvesUnderRoots(path string, roots []string) bool {
	guard, err := NewPathGuard(roots...)
	if err != nil {
		return false
	}
	_, err = guard.Resolve(path)
	return err == nil
}

func pathsIdentifySameResource(a, b GuardedPath) bool {
	return a.Path == b.Path || a.Path == b.ResolvedPath || a.ResolvedPath == b.Path || a.ResolvedPath == b.ResolvedPath
}

func classifyFailure(failure *proxy.Failure, path *GuardedPath, resource *DesiredResource, markerInManagedLayout bool) classification {
	if failure != nil {
		if failure.BinaryMissing {
			return systemClassification(recoverymodel.CodeProxyBinaryMissing, "binary_missing")
		}
		if failure.Permission {
			return systemClassification(recoverymodel.CodePermissionDenied, "permission_denied")
		}
		if systemdSandboxFailure(failure.Output) {
			return systemClassification(recoverymodel.CodeSystemdSandboxDenied, "systemd_sandbox")
		}
		if portConflictFailure(failure.Output) {
			return systemClassification(recoverymodel.CodePortConflict, "port_conflict")
		}
		if proxyNotRunningFailure(failure.Output) {
			return systemClassification(recoverymodel.CodeProxyNotRunning, "proxy_not_running")
		}
		if failure.Phase == proxy.FailurePhaseReload {
			return systemClassification(recoverymodel.CodeProxyReloadFailed, "reload_failed")
		}
	}

	owner := ownershipFor(path, resource, markerInManagedLayout)
	if owner == recoverymodel.OwnershipOperator {
		return classification{code: recoverymodel.CodeOperatorConfigInvalid, ownership: owner, evidenceClass: "operator_config"}
	}
	if path == nil {
		return unknownClassification()
	}
	if resource == nil {
		if markerInManagedLayout && isManagedTemp(path.Path) {
			return classification{code: recoverymodel.CodeManagedStaleTemp, ownership: recoverymodel.OwnershipNurProxy, action: recoverymodel.ActionRemoveManagedTemp, eligible: true, evidenceClass: "managed_temp"}
		}
		if markerInManagedLayout && isManagedConfig(path.Path) {
			return classification{code: recoverymodel.CodeManagedOrphanConfig, ownership: recoverymodel.OwnershipNurProxy, action: recoverymodel.ActionPruneManagedOrphan, eligible: true, evidenceClass: "managed_orphan"}
		}
		return classification{code: recoverymodel.CodeOperatorConfigInvalid, ownership: recoverymodel.OwnershipOperator, evidenceClass: "operator_config"}
	}
	if owner != recoverymodel.OwnershipNurProxy {
		return unknownClassification()
	}

	cleanResource := resource.Source == models.ArtifactSourceGenerated && !resource.Drifted &&
		(resource.ApplyState == models.ArtifactStateLive || resource.ApplyState == models.ArtifactStateApplyFailed)
	switch {
	case failure != nil && failure.MissingCert:
		return bundleClassification(recoverymodel.CodeManagedCertFileMissing, recoverymodel.ActionRematerializeCertBundle, "cert_missing", cleanResource && resource.ValidBundle)
	case failure != nil && failure.MissingRuntimeKey:
		return bundleClassification(recoverymodel.CodeManagedRuntimeKeyMissing, recoverymodel.ActionRematerializeRuntimeKey, "runtime_key_missing", cleanResource && resource.ValidBundle)
	case failure != nil && failure.RuntimeKeyMismatch:
		return bundleClassification(recoverymodel.CodeManagedRuntimeKeyMismatch, recoverymodel.ActionRematerializeRuntimeKey, "runtime_key_mismatch", cleanResource && resource.ValidBundle)
	default:
		return classification{
			code: recoverymodel.CodeGeneratedConfigInvalid, ownership: recoverymodel.OwnershipNurProxy,
			evidenceClass: "generated_config",
		}
	}
}

func ownershipFor(path *GuardedPath, resource *DesiredResource, markerInManagedLayout bool) recoverymodel.Ownership {
	if path == nil {
		return recoverymodel.OwnershipUnknown
	}
	if resource == nil {
		if markerInManagedLayout && (isManagedConfig(path.Path) || isManagedTemp(path.Path)) {
			return recoverymodel.OwnershipNurProxy
		}
		return recoverymodel.OwnershipOperator
	}
	if resource.Source != models.ArtifactSourceGenerated || resource.Drifted || resource.ApplyState == models.ArtifactStateDrifted {
		return recoverymodel.OwnershipOperator
	}
	return recoverymodel.OwnershipNurProxy
}

func isManagedConfig(path string) bool {
	name := filepath.Base(path)
	return strings.HasPrefix(name, "nurproxy-") && strings.HasSuffix(name, ".conf") && len(name) > len("nurproxy-.conf")
}

func isManagedTemp(path string) bool {
	const suffix = ".conf.nurproxy-tmp"
	name := filepath.Base(path)
	return strings.HasPrefix(name, "nurproxy-") && strings.HasSuffix(name, suffix) && len(name) > len("nurproxy-")+len(suffix)
}

func bundleClassification(code recoverymodel.Code, action recoverymodel.Action, evidenceClass string, eligible bool) classification {
	result := classification{code: code, ownership: recoverymodel.OwnershipNurProxy, evidenceClass: evidenceClass}
	if eligible {
		result.action = action
		result.eligible = true
	}
	return result
}

func systemClassification(code recoverymodel.Code, evidenceClass string) classification {
	return classification{code: code, ownership: recoverymodel.OwnershipSystem, hardChange: true, evidenceClass: evidenceClass}
}

func unknownClassification() classification {
	return classification{code: recoverymodel.CodeUnknownProxyError, ownership: recoverymodel.OwnershipUnknown, evidenceClass: "unknown"}
}

func systemdSandboxFailure(output string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "failed at step namespace spawning ") && strings.HasSuffix(line, ": operation not permitted") {
			return true
		}
	}
	return false
}

func portConflictFailure(output string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nginx: [emerg] bind() to ") && strings.HasSuffix(line, " failed (98: address already in use)") {
			return true
		}
		if strings.HasPrefix(line, "(98)address already in use: ah00072: make_sock: could not bind to address ") {
			return true
		}
	}
	return false
}

func proxyNotRunningFailure(output string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nginx: [error] invalid pid number ") && strings.HasSuffix(line, " in \"/run/nginx.pid\"") {
			return true
		}
		if line == "httpd (no pid file) not running" || line == "apache2 (no pid file) not running" {
			return true
		}
	}
	return false
}

func fingerprint(code recoverymodel.Code, backend proxy.Kind, evidenceClass string, paths []string) string {
	values := []string{string(code), string(backend), evidenceClass}
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
	return "resource_" + hex.EncodeToString(h.Sum(nil))
}

func normalizedBackend(backend proxy.Kind) proxy.Kind {
	switch backend {
	case proxy.KindCaddy, proxy.KindNginx, proxy.KindApache, proxy.KindCustom:
		return backend
	default:
		return proxy.KindUnknown
	}
}

func summaryFor(code recoverymodel.Code) string {
	summaries := map[recoverymodel.Code]string{
		recoverymodel.CodeManagedOrphanConfig:       "NurProxy-managed config is no longer desired",
		recoverymodel.CodeManagedStaleTemp:          "NurProxy-managed temporary config was left behind",
		recoverymodel.CodeManagedCertFileMissing:    "Managed certificate file is missing",
		recoverymodel.CodeManagedRuntimeKeyMissing:  "Managed runtime key is missing",
		recoverymodel.CodeManagedRuntimeKeyMismatch: "Managed runtime key does not match its certificate",
		recoverymodel.CodeGeneratedConfigInvalid:    "Generated proxy config is invalid",
		recoverymodel.CodeOperatorConfigInvalid:     "Operator-managed proxy config is invalid",
		recoverymodel.CodePermissionDenied:          "Proxy operation was denied by host permissions",
		recoverymodel.CodeSystemdSandboxDenied:      "The service sandbox denied the proxy operation",
		recoverymodel.CodeProxyReloadFailed:         "Proxy reload failed",
		recoverymodel.CodeProxyNotRunning:           "Proxy service is not running",
		recoverymodel.CodePortConflict:              "A proxy listener port is already in use",
		recoverymodel.CodeProxyBinaryMissing:        "Proxy binary is missing",
		recoverymodel.CodeUnknownProxyError:         "Proxy operation failed for an unknown reason",
	}
	return summaries[code]
}

func fallbackDiagnostic(agentID string, backend proxy.Kind, now time.Time) recoverymodel.Diagnostic {
	fingerprint := fingerprint(recoverymodel.CodeUnknownProxyError, backend, "invalid_context", nil)
	return recoverymodel.Diagnostic{
		ID:   recoverymodel.StableDiagnosticID(agentID, recoverymodel.CodeUnknownProxyError, fingerprint),
		Code: recoverymodel.CodeUnknownProxyError, Subsystem: "proxy", Severity: recoverymodel.SeverityError,
		Ownership: recoverymodel.OwnershipUnknown, Summary: summaryFor(recoverymodel.CodeUnknownProxyError),
		AffectedPaths: []string{}, ResourceFingerprint: fingerprint,
		FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
}
