package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestClassifierMapsEveryDiagnosticCodeAndOwnershipClass(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	managed := filepath.Join(fixture.available, "nurproxy-app.example.conf")
	operator := filepath.Join(fixture.available, "operator.conf")
	temp := filepath.Join(fixture.available, "nurproxy-stale.example.conf.nurproxy-tmp")
	orphan := filepath.Join(fixture.available, "nurproxy-orphan.example.conf")
	certPath := filepath.Join(fixture.certs, "missing.crt")
	keyPath := filepath.Join(fixture.certs, "missing.key.plain")
	mismatchCert := filepath.Join(fixture.certs, "mismatch.crt")
	mismatchKey := filepath.Join(fixture.certs, "mismatch.key.plain")
	mismatchTarget := filepath.Join(fixture.available, "nurproxy-mismatch.example.conf")
	for _, path := range []string{managed, operator, temp, orphan, mismatchCert, mismatchKey, mismatchTarget} {
		content := "fixture"
		if path == temp || path == orphan {
			content = proxy.StampManagedArtifact(content)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	generated := DesiredResource{
		ArtifactID: "artifact-generated", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: managed},
		Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateApplyFailed, ValidBundle: true, CertPath: certPath, RuntimeKeyPath: keyPath,
	}
	mismatch := DesiredResource{ArtifactID: "artifact-mismatch", Host: "mismatch.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: mismatchTarget}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: mismatchCert, RuntimeKeyPath: mismatchKey}
	manual := DesiredResource{
		ArtifactID: "artifact-manual", Host: "operator.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: operator},
		Source: models.ArtifactSourceManual, ApplyState: models.ArtifactStateLive,
	}
	ctx := fixture.ctx
	ctx.DesiredResources = []DesiredResource{generated, mismatch, manual}

	tests := []struct {
		name       string
		err        error
		wantCode   recoverymodel.Code
		ownership  recoverymodel.Ownership
		action     recoverymodel.Action
		eligible   bool
		hardChange bool
	}{
		{"managed orphan", locatedFailure(proxy.FailurePhaseValidate, orphan), recoverymodel.CodeManagedOrphanConfig, recoverymodel.OwnershipNurProxy, recoverymodel.ActionPruneManagedOrphan, true, false},
		{"managed stale temp", locatedFailure(proxy.FailurePhaseValidate, temp), recoverymodel.CodeManagedStaleTemp, recoverymodel.OwnershipNurProxy, recoverymodel.ActionRemoveManagedTemp, true, false},
		{"managed cert missing", proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, `nginx: [emerg] cannot load certificate "`+certPath+`": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`, errors.New("exit 1")), recoverymodel.CodeManagedCertFileMissing, recoverymodel.OwnershipNurProxy, recoverymodel.ActionRematerializeCertBundle, true, false},
		{"managed runtime key missing", proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, `nginx: [emerg] cannot load certificate key "`+keyPath+`": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`, errors.New("exit 1")), recoverymodel.CodeManagedRuntimeKeyMissing, recoverymodel.OwnershipNurProxy, recoverymodel.ActionRematerializeRuntimeKey, true, false},
		{"managed runtime key mismatch", proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, `nginx: [emerg] SSL_CTX_use_PrivateKey("`+mismatchKey+`") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)`, errors.New("exit 1")), recoverymodel.CodeManagedRuntimeKeyMismatch, recoverymodel.OwnershipNurProxy, recoverymodel.ActionRematerializeRuntimeKey, true, false},
		{"generated config invalid", locatedFailure(proxy.FailurePhaseValidate, managed), recoverymodel.CodeGeneratedConfigInvalid, recoverymodel.OwnershipNurProxy, "", false, false},
		{"operator config invalid", locatedFailure(proxy.FailurePhaseValidate, operator), recoverymodel.CodeOperatorConfigInvalid, recoverymodel.OwnershipOperator, "", false, false},
		{"permission denied", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, Permission: true, Output: "permission denied", Err: os.ErrPermission}, recoverymodel.CodePermissionDenied, recoverymodel.OwnershipSystem, "", false, true},
		{"systemd sandbox denied", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, Output: "Failed at step NAMESPACE spawning /usr/sbin/nginx: Operation not permitted", Err: errors.New("exit 226")}, recoverymodel.CodeSystemdSandboxDenied, recoverymodel.OwnershipSystem, "", false, true},
		{"proxy reload failed", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseReload, Output: "reload failed", Err: errors.New("exit 1")}, recoverymodel.CodeProxyReloadFailed, recoverymodel.OwnershipSystem, "", false, true},
		{"proxy not running", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseReload, Output: `nginx: [error] invalid PID number "" in "/run/nginx.pid"`, Err: errors.New("exit 1")}, recoverymodel.CodeProxyNotRunning, recoverymodel.OwnershipSystem, "", false, true},
		{"port conflict", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, Output: "nginx: [emerg] bind() to 0.0.0.0:443 failed (98: Address already in use)", Err: errors.New("exit 1")}, recoverymodel.CodePortConflict, recoverymodel.OwnershipSystem, "", false, true},
		{"proxy binary missing", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, BinaryMissing: true, Err: errors.New("missing")}, recoverymodel.CodeProxyBinaryMissing, recoverymodel.OwnershipSystem, "", false, true},
		{"unknown proxy error", errors.New("unexpected proxy failure token=secret"), recoverymodel.CodeUnknownProxyError, recoverymodel.OwnershipUnknown, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(ctx, tt.err)
			if got.Code != tt.wantCode || got.Ownership != tt.ownership || got.ProposedAction != tt.action || got.AutoRepairEligible != tt.eligible || got.HardChange != tt.hardChange {
				t.Fatalf("classification = code=%q owner=%q action=%q eligible=%v hard=%v", got.Code, got.Ownership, got.ProposedAction, got.AutoRepairEligible, got.HardChange)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("invalid diagnostic: %v\n%+v", err, got)
			}
			if strings.Contains(got.Evidence, "secret") {
				t.Fatalf("evidence leaked secret: %q", got.Evidence)
			}
		})
	}
}

func TestClassifierFailsClosedForOwnershipAndBundlePredicates(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	managed := filepath.Join(fixture.available, "nurproxy-app.example.conf")
	if err := os.WriteFile(managed, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(fixture.certs, "app.crt")
	base := DesiredResource{ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: managed}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateApplyFailed, ValidBundle: true, CertPath: certPath, RuntimeKeyPath: filepath.Join(fixture.certs, "app.key")}
	baseCtx := fixture.ctx

	tests := []struct {
		name      string
		resource  *DesiredResource
		err       error
		wantOwner recoverymodel.Ownership
	}{
		{"manual", resourceWith(base, func(r *DesiredResource) { r.Source = models.ArtifactSourceManual }), locatedFailure(proxy.FailurePhaseValidate, managed), recoverymodel.OwnershipOperator},
		{"drifted", resourceWith(base, func(r *DesiredResource) { r.Drifted = true }), locatedFailure(proxy.FailurePhaseValidate, managed), recoverymodel.OwnershipOperator},
		{"review state", resourceWith(base, func(r *DesiredResource) { r.ApplyState = models.ArtifactStateDrifted }), locatedFailure(proxy.FailurePhaseValidate, managed), recoverymodel.OwnershipOperator},
		{"unknown apply state", resourceWith(base, func(r *DesiredResource) { r.ApplyState = "unexpected" }), locatedFailure(proxy.FailurePhaseValidate, managed), recoverymodel.OwnershipUnknown},
		{"absent bundle", resourceWith(base, func(r *DesiredResource) { r.ValidBundle = false }), proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, `nginx: [emerg] cannot load certificate "`+certPath+`": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`, errors.New("exit 1")), recoverymodel.OwnershipNurProxy},
		{"outside root", nil, locatedFailure(proxy.FailurePhaseValidate, filepath.Join(filepath.Dir(fixture.base), "nurproxy-outside.conf")), recoverymodel.OwnershipUnknown},
		{"deceptive managed name", nil, locatedFailure(proxy.FailurePhaseValidate, filepath.Join(fixture.available, "nurproxy-fake.conf.backup")), recoverymodel.OwnershipOperator},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := baseCtx
			if tt.resource != nil {
				ctx.DesiredResources = []DesiredResource{*tt.resource}
			}
			got := Classify(ctx, tt.err)
			if got.Ownership != tt.wantOwner || got.AutoRepairEligible {
				t.Fatalf("classification = owner=%q eligible=%v code=%q", got.Ownership, got.AutoRepairEligible, got.Code)
			}
			if tt.name == "absent bundle" && (got.Code != recoverymodel.CodeManagedCertFileMissing || got.ProposedAction != "") {
				t.Fatalf("absent bundle classification = code=%q action=%q", got.Code, got.ProposedAction)
			}
		})
	}
}

func TestClassifierDoesNotTreatAgentDataBasenameAsBackendMarker(t *testing.T) {
	base := t.TempDir()
	managedRoot := filepath.Join(base, "proxy")
	dataRoot := filepath.Join(base, "data")
	for _, dir := range []string{managedRoot, dataRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dataRoot, "nurproxy-deceptive.conf")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := Context{AgentID: "agent-1", ProxyInfo: proxy.Info{Kind: proxy.KindNginx}, ManagedRoots: []string{managedRoot}, AgentDataRoot: dataRoot}
	got := Classify(ctx, locatedFailure(proxy.FailurePhaseValidate, path))
	if got.Ownership == recoverymodel.OwnershipNurProxy || got.AutoRepairEligible {
		t.Fatalf("agent-data basename became ownership proof: %+v", got)
	}
}

func TestClassifierRejectsSymlinkEscapeDespiteManagedHint(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "escape", "nurproxy-app.conf")
	ctx := Context{AgentID: "agent-1", ProxyInfo: proxy.Info{Kind: proxy.KindNginx}, ManagedRoots: []string{root}, AgentDataRoot: filepath.Join(root, "data")}
	got := Classify(ctx, &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, File: path, Line: 1, Located: true, ManagedHint: true, Err: errors.New("exit 1")})
	if got.Ownership != recoverymodel.OwnershipUnknown || got.AutoRepairEligible || len(got.AffectedPaths) != 0 {
		t.Fatalf("symlink escape classified as %+v", got)
	}
}

func TestClassifierFingerprintIgnoresRawTextAndUsesEvidenceClass(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	path := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	resource := DesiredResource{ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: path}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateApplyFailed, ValidBundle: true}
	ctx := fixture.ctx
	ctx.DesiredResources = []DesiredResource{resource}
	first := locatedFailure(proxy.FailurePhaseValidate, path).(*proxy.Failure)
	first.Output = "unknown directive alpha token=one"
	second := locatedFailure(proxy.FailurePhaseValidate, path).(*proxy.Failure)
	second.Output = "different raw detail token=two"
	a := Classify(ctx, first)
	b := Classify(ctx, second)
	if a.ResourceFingerprint != b.ResourceFingerprint || a.ID != b.ID {
		t.Fatalf("raw output changed identity: (%q, %q) vs (%q, %q)", a.ResourceFingerprint, a.ID, b.ResourceFingerprint, b.ID)
	}
	if strings.Contains(a.ResourceFingerprint, "alpha") || strings.Contains(a.ResourceFingerprint, path) || strings.Contains(a.ResourceFingerprint, "backend") {
		t.Fatalf("fingerprint contains raw input: %q", a.ResourceFingerprint)
	}
}

func locatedFailure(phase proxy.FailurePhase, path string) error {
	return &proxy.Failure{Backend: proxy.KindNginx, Phase: phase, File: path, Line: 1, Located: true, ManagedHint: true, Output: "configtest failed", Err: errors.New("exit 1")}
}

func resourceWith(base DesiredResource, mutate func(*DesiredResource)) *DesiredResource {
	mutate(&base)
	return &base
}
