package recovery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/apache"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/nginx"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type DesiredResource struct {
	ArtifactID     string
	Host           string
	Target         proxy.Target
	Source         models.ArtifactSource
	Drifted        bool
	ApplyState     models.ArtifactApplyState
	ValidBundle    bool
	CertPath       string
	RuntimeKeyPath string
}

type Context struct {
	AgentID          string
	ProxyInfo        proxy.Info
	ManagedRoots     []string
	AgentDataRoot    string
	DesiredResources []DesiredResource
}

type classification struct {
	code                recoverymodel.Code
	ownership           recoverymodel.Ownership
	ownershipConfidence recoverymodel.OwnershipConfidence
	action              recoverymodel.Action
	autoEligible        bool
	repairEligible      bool
	repairScope         recoverymodel.RepairScope
	refusalCode         string
	hardChange          bool
	evidenceClass       string
	paths               []GuardedPath
}

func Classify(ctx Context, err error) recoverymodel.Diagnostic {
	now := time.Now().UTC()
	backend := normalizedBackend(ctx.ProxyInfo.Kind)
	evidence := ""
	var failure *proxy.Failure
	if errors.As(err, &failure) && failure != nil {
		if normalized := normalizedBackend(failure.Backend); normalized != proxy.KindUnknown && normalized == backend {
			backend = normalized
		}
		evidence = failure.Output
	}
	if evidence == "" && err != nil {
		evidence = err.Error()
	}
	evidence = recoverymodel.SanitizeEvidence(evidence)

	result := classifyFailure(ctx, failure)
	paths := make([]string, 0, len(result.paths))
	fingerprintPaths := make([]string, 0, len(result.paths))
	for _, guarded := range result.paths {
		paths = append(paths, guarded.Path)
		fingerprintPaths = append(fingerprintPaths, guarded.ResolvedPath)
	}
	fingerprint := fingerprint(result.code, backend, result.evidenceClass, fingerprintPaths)
	diagnostic := recoverymodel.Diagnostic{
		Code: result.code, Subsystem: "proxy", Severity: recoverymodel.SeverityError,
		Ownership: result.ownership, OwnershipConfidence: result.ownershipConfidence,
		Summary: summaryFor(result.code), Evidence: evidence,
		AffectedPaths: paths, ResourceFingerprint: fingerprint, ProposedAction: result.action,
		RepairScope: result.repairScope, RepairEligible: result.repairEligible,
		RepairRefusalCode: result.refusalCode, AutoRepairEligible: result.autoEligible, HardChange: result.hardChange,
		FirstSeenAt: now, LastSeenAt: now, Occurrences: 1,
	}
	diagnostic.ID = recoverymodel.StableDiagnosticID(ctx.AgentID, diagnostic.Code, fingerprint)
	if diagnostic.Validate() != nil {
		return fallbackDiagnostic(ctx.AgentID, backend, now)
	}
	return diagnostic
}

type backendLayout struct {
	available string
	enabled   string
	guard     *PathGuard
}

func classifyFailure(ctx Context, failure *proxy.Failure) classification {
	if !validFailureMetadata(ctx, failure) {
		return unknownClassification()
	}
	if failure.BinaryMissing {
		return hardSystemClassification(recoverymodel.CodeProxyBinaryMissing, "binary_missing", recoverymodel.RepairScopeSupportedPackage, true, "")
	}
	if systemdSandboxFailure(failure.Output) {
		return hardSystemClassification(recoverymodel.CodeSystemdSandboxDenied, "systemd_sandbox", recoverymodel.RepairScopeAgentSandbox, true, "")
	}
	if failure.Permission {
		return hardSystemClassification(recoverymodel.CodePermissionDenied, "permission_denied", recoverymodel.RepairScopeAmbiguous, false, "permission_scope_ambiguous")
	}
	if portConflictFailure(failure.Output) {
		return hardSystemClassification(recoverymodel.CodePortConflict, "port_conflict", recoverymodel.RepairScopeUnsupportedEnvironment, false, "process_killing_unsupported")
	}
	if proxyNotRunningFailure(failure.Output) {
		return hardSystemClassification(recoverymodel.CodeProxyNotRunning, "proxy_not_running", recoverymodel.RepairScopeDetectedProxyService, true, "")
	}
	if failure.Phase == proxy.FailurePhaseReload {
		return hardSystemClassification(recoverymodel.CodeProxyReloadFailed, "reload_failed", recoverymodel.RepairScopeDetectedProxyService, true, "")
	}
	if failure.MissingCert || failure.MissingRuntimeKey || failure.RuntimeKeyMismatch {
		return classifyReferencedFailure(ctx, failure)
	}
	return classifyLocatedFailure(ctx, failure)
}

func validFailureMetadata(ctx Context, failure *proxy.Failure) bool {
	if failure == nil || (ctx.ProxyInfo.Kind != proxy.KindNginx && ctx.ProxyInfo.Kind != proxy.KindApache) || failure.Backend != ctx.ProxyInfo.Kind {
		return false
	}
	switch failure.Phase {
	case proxy.FailurePhaseValidate, proxy.FailurePhaseReload, proxy.FailurePhaseCertInstall:
	default:
		return false
	}
	primary := 0
	for _, set := range []bool{failure.BinaryMissing, failure.Permission, failure.MissingCert, failure.MissingRuntimeKey, failure.RuntimeKeyMismatch} {
		if set {
			primary++
		}
	}
	if primary > 1 || len(failure.ReferencedPaths) > 2 {
		return false
	}
	certificateFailure := failure.MissingCert || failure.MissingRuntimeKey || failure.RuntimeKeyMismatch
	if certificateFailure != (len(failure.ReferencedPaths) > 0) || (certificateFailure && failure.Phase != proxy.FailurePhaseValidate) {
		return false
	}
	if failure.RuntimeKeyMismatch && ((failure.Backend == proxy.KindNginx && len(failure.ReferencedPaths) != 1) || (failure.Backend == proxy.KindApache && len(failure.ReferencedPaths) != 2)) {
		return false
	}
	for _, path := range failure.ReferencedPaths {
		if !proxy.ValidFailurePath(path) {
			return false
		}
	}
	if failure.Located {
		return failure.Line > 0 && proxy.ValidFailurePath(failure.File)
	}
	return failure.File == "" && failure.Line == 0 && !failure.ManagedHint
}

func classifyLocatedFailure(ctx Context, failure *proxy.Failure) classification {
	if !failure.Located {
		return unknownClassification()
	}
	layout, ok := resolveBackendLayout(ctx)
	if !ok {
		return unknownClassification()
	}
	checked, err := layout.guard.Resolve(failure.File)
	if err != nil {
		return unknownClassification()
	}
	resource, ownership := matchDesiredTarget(ctx.DesiredResources, checked, layout)
	if resource != nil {
		if ownership == recoverymodel.OwnershipUnknown {
			return unknownClassification()
		}
		code := recoverymodel.CodeGeneratedConfigInvalid
		class := "generated_config"
		if ownership == recoverymodel.OwnershipOperator {
			code, class = recoverymodel.CodeOperatorConfigInvalid, "operator_config"
		}
		return classification{code: code, ownership: ownership, ownershipConfidence: recoverymodel.OwnershipConfidenceCertain,
			repairScope: recoverymodel.RepairScopeExactProvenancedFile, refusalCode: "generated_config_restore_requires_known_failed_hash", evidenceClass: class, paths: []GuardedPath{checked}}
	}
	if markerInExactLayout(checked, layout) && hasManagedArtifactProvenance(checked) {
		if filepath.Dir(checked.Path) == layout.available && isManagedTemp(checked.Path) {
			return classification{code: recoverymodel.CodeManagedStaleTemp, ownership: recoverymodel.OwnershipNurProxy,
				ownershipConfidence: recoverymodel.OwnershipConfidenceCertain, action: recoverymodel.ActionRemoveManagedTemp,
				autoEligible: true, repairEligible: true, repairScope: recoverymodel.RepairScopeExactProvenancedFile,
				evidenceClass: "managed_temp", paths: []GuardedPath{checked}}
		}
		if isManagedConfig(checked.Path) {
			return classification{code: recoverymodel.CodeManagedOrphanConfig, ownership: recoverymodel.OwnershipNurProxy,
				ownershipConfidence: recoverymodel.OwnershipConfidenceCertain, action: recoverymodel.ActionPruneManagedOrphan,
				autoEligible: true, repairEligible: true, repairScope: recoverymodel.RepairScopeExactProvenancedFile,
				evidenceClass: "managed_orphan", paths: []GuardedPath{checked}}
		}
	}
	return classification{code: recoverymodel.CodeOperatorConfigInvalid, ownership: recoverymodel.OwnershipOperator,
		ownershipConfidence: recoverymodel.OwnershipConfidenceCertain, repairScope: recoverymodel.RepairScopeExactProvenancedFile,
		refusalCode: "operator_owned_config", evidenceClass: "operator_config", paths: []GuardedPath{checked}}
}

func resolveBackendLayout(ctx Context) (backendLayout, bool) {
	if !proxy.ValidFailurePath(ctx.ProxyInfo.ConfigDir) {
		return backendLayout{}, false
	}
	canonicalConfig, ok := canonicalExistingDir(ctx.ProxyInfo.ConfigDir)
	if !ok {
		return backendLayout{}, false
	}
	var available, enabled string
	switch ctx.ProxyInfo.Kind {
	case proxy.KindNginx:
		layout := nginx.ResolveLayout(canonicalConfig)
		available, enabled = layout.Available, layout.Enabled
	case proxy.KindApache:
		layout := apache.ResolveLayout(canonicalConfig)
		available, enabled = layout.Available, layout.Enabled
	default:
		return backendLayout{}, false
	}
	canonicalAvailable, ok := canonicalExistingDir(available)
	if !ok {
		return backendLayout{}, false
	}
	if canonicalConfig != canonicalAvailable {
		return backendLayout{}, false
	}
	canonicalEnabled := ""
	if enabled != "" {
		canonicalEnabled, ok = canonicalExistingDir(enabled)
		if !ok || canonicalEnabled == canonicalAvailable {
			return backendLayout{}, false
		}
	}
	guard, err := NewPathGuard(ctx.ManagedRoots...)
	if err != nil || !guard.containsDirectory(canonicalAvailable) || (canonicalEnabled != "" && !guard.containsDirectory(canonicalEnabled)) {
		return backendLayout{}, false
	}
	return backendLayout{available: canonicalAvailable, enabled: canonicalEnabled, guard: guard}, true
}

func canonicalExistingDir(path string) (string, bool) {
	if !proxy.ValidFailurePath(path) {
		return "", false
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(canonical)
	return canonical, err == nil && info.IsDir()
}

func markerInExactLayout(path GuardedPath, layout backendLayout) bool {
	parent := filepath.Dir(path.Path)
	if parent == layout.available {
		return path.EntryType == GuardedPathRegular
	}
	if layout.enabled == "" || parent != layout.enabled || path.EntryType != GuardedPathSymlink {
		return false
	}
	name := filepath.Base(path.Path)
	return filepath.Base(path.ResolvedPath) == name && path.ResolvedPath == filepath.Join(layout.available, name)
}

func hasManagedArtifactProvenance(path GuardedPath) bool {
	if (path.EntryType != GuardedPathRegular && path.EntryType != GuardedPathSymlink) || !path.resolvedExists {
		return false
	}
	file, err := os.Open(path.ResolvedPath)
	if err != nil {
		return false
	}
	probe, readErr := io.ReadAll(io.LimitReader(file, proxy.MaxManagedArtifactMarkerProbeBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || path.owner.Recheck(path) != nil {
		return false
	}
	return proxy.HasManagedArtifactMarker(string(probe))
}

func matchDesiredTarget(resources []DesiredResource, path GuardedPath, layout backendLayout) (*DesiredResource, recoverymodel.Ownership) {
	var match *DesiredResource
	for i := range resources {
		resource := &resources[i]
		if !validDesiredIdentity(*resource) || resource.Target.Kind != proxy.TargetKindFile || resource.Target.Path == "" {
			continue
		}
		desired, err := layout.guard.Resolve(resource.Target.Path)
		if err != nil || desired.EntryType == GuardedPathSymlink {
			continue
		}
		exact := path.Path == desired.Path
		activationAlias := markerInExactLayout(path, layout) && path.EntryType == GuardedPathSymlink && path.ResolvedPath == desired.Path
		if !exact && !activationAlias {
			continue
		}
		if match != nil {
			return nil, recoverymodel.OwnershipUnknown
		}
		match = resource
	}
	if match == nil {
		return nil, recoverymodel.OwnershipUnknown
	}
	return match, resourceOwnership(*match)
}

func resourceOwnership(resource DesiredResource) recoverymodel.Ownership {
	if !validDesiredIdentity(resource) {
		return recoverymodel.OwnershipUnknown
	}
	if resource.Source == models.ArtifactSourceManual || resource.Drifted || resource.ApplyState == models.ArtifactStateDrifted {
		return recoverymodel.OwnershipOperator
	}
	if resource.Source == models.ArtifactSourceGenerated && (resource.ApplyState == models.ArtifactStateLive || resource.ApplyState == models.ArtifactStateApplyFailed) {
		return recoverymodel.OwnershipNurProxy
	}
	return recoverymodel.OwnershipUnknown
}

func validDesiredIdentity(resource DesiredResource) bool {
	return strings.TrimSpace(resource.ArtifactID) != "" && strings.TrimSpace(resource.Host) != ""
}

func classifyReferencedFailure(ctx Context, failure *proxy.Failure) classification {
	layout, ok := resolveBackendLayout(ctx)
	if !ok {
		return unknownClassification()
	}
	dataRoot, ok := canonicalExistingDir(ctx.AgentDataRoot)
	if !ok {
		return unknownClassification()
	}
	guard, err := NewPathGuard(dataRoot)
	if err != nil {
		return unknownClassification()
	}
	references := make([]GuardedPath, 0, len(failure.ReferencedPaths))
	for _, path := range failure.ReferencedPaths {
		checked, resolveErr := guard.Resolve(path)
		if resolveErr != nil || checked.EntryType == GuardedPathSymlink {
			return unknownClassification()
		}
		references = append(references, checked)
	}

	var matched *DesiredResource
	for i := range ctx.DesiredResources {
		resource := &ctx.DesiredResources[i]
		if !referencesMatchResource(failure, references, *resource, guard, layout) {
			continue
		}
		if matched != nil {
			return unknownClassification()
		}
		matched = resource
	}
	if matched == nil {
		return unknownClassification()
	}
	code, action, evidenceClass := referencedFailureKind(failure)
	ownership := resourceOwnership(*matched)
	if ownership == recoverymodel.OwnershipUnknown {
		return unknownClassification()
	}
	result := classification{code: code, ownership: ownership, evidenceClass: evidenceClass, paths: references}
	result.ownershipConfidence = recoverymodel.OwnershipConfidenceCertain
	result.repairScope = recoverymodel.RepairScopeExactProvenancedFile
	if ownership == recoverymodel.OwnershipNurProxy && matched.ValidBundle {
		result.action = action
		result.autoEligible = true
		result.repairEligible = true
	} else {
		result.refusalCode = "managed_bundle_unavailable"
	}
	return result
}

func referencesMatchResource(failure *proxy.Failure, references []GuardedPath, resource DesiredResource, guard *PathGuard, layout backendLayout) bool {
	if !validDesiredIdentity(resource) || !validDesiredTarget(resource, layout) {
		return false
	}
	cert, certOK := resolveExpectedPath(guard, resource.CertPath)
	key, keyOK := resolveExpectedPath(guard, resource.RuntimeKeyPath)
	if certOK && keyOK && cert.Path == key.Path {
		return false
	}
	switch {
	case failure.MissingCert:
		return len(references) == 1 && certOK && references[0].EntryType == GuardedPathAbsent && references[0].Path == cert.Path
	case failure.MissingRuntimeKey:
		return len(references) == 1 && keyOK && references[0].EntryType == GuardedPathAbsent && references[0].Path == key.Path
	case failure.RuntimeKeyMismatch && failure.Backend == proxy.KindNginx:
		return len(references) == 1 && certOK && keyOK && cert.EntryType == GuardedPathRegular && key.EntryType == GuardedPathRegular && references[0].Path == key.Path
	case failure.RuntimeKeyMismatch && failure.Backend == proxy.KindApache:
		return len(references) == 2 && certOK && keyOK && cert.EntryType == GuardedPathRegular && key.EntryType == GuardedPathRegular && references[0].Path == cert.Path && references[1].Path == key.Path
	default:
		return false
	}
}

func validDesiredTarget(resource DesiredResource, layout backendLayout) bool {
	if resource.Target.Kind != proxy.TargetKindFile || resource.Target.Path == "" {
		return false
	}
	checked, err := layout.guard.Resolve(resource.Target.Path)
	return err == nil && filepath.Dir(checked.Path) == layout.available && isManagedConfig(checked.Path) && checked.EntryType != GuardedPathSymlink
}

func resolveExpectedPath(guard *PathGuard, path string) (GuardedPath, bool) {
	if !proxy.ValidFailurePath(path) {
		return GuardedPath{}, false
	}
	checked, err := guard.Resolve(path)
	return checked, err == nil && checked.EntryType != GuardedPathSymlink
}

func referencedFailureKind(failure *proxy.Failure) (recoverymodel.Code, recoverymodel.Action, string) {
	switch {
	case failure.MissingCert:
		return recoverymodel.CodeManagedCertFileMissing, recoverymodel.ActionRematerializeCertBundle, "cert_missing"
	case failure.MissingRuntimeKey:
		return recoverymodel.CodeManagedRuntimeKeyMissing, recoverymodel.ActionRematerializeRuntimeKey, "runtime_key_missing"
	default:
		return recoverymodel.CodeManagedRuntimeKeyMismatch, recoverymodel.ActionRematerializeRuntimeKey, "runtime_key_mismatch"
	}
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

func hardSystemClassification(code recoverymodel.Code, evidenceClass string, scope recoverymodel.RepairScope, eligible bool, refusalCode string) classification {
	return classification{code: code, ownership: recoverymodel.OwnershipSystem,
		ownershipConfidence: recoverymodel.OwnershipConfidenceInferred, repairEligible: eligible,
		repairScope: scope, refusalCode: refusalCode, hardChange: true, evidenceClass: evidenceClass}
}

func unknownClassification() classification {
	return classification{code: recoverymodel.CodeUnknownProxyError, ownership: recoverymodel.OwnershipUnknown,
		ownershipConfidence: recoverymodel.OwnershipConfidenceUnknown, repairScope: recoverymodel.RepairScopeAmbiguous,
		refusalCode: "unknown_proxy_error", evidenceClass: "unknown"}
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
	return hex.EncodeToString(h.Sum(nil))
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
