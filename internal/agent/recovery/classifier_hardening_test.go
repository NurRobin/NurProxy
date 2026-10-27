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

type recoveryFixture struct {
	base, available, enabled, data, certs string
	ctx                                   Context
}

func newRecoveryFixture(t *testing.T, backend proxy.Kind) recoveryFixture {
	t.Helper()
	base := t.TempDir()
	var available, enabled string
	switch backend {
	case proxy.KindNginx:
		available = filepath.Join(base, "etc", "nginx", "sites-available")
		enabled = filepath.Join(base, "etc", "nginx", "sites-enabled")
	case proxy.KindApache:
		available = filepath.Join(base, "etc", "apache2", "sites-available")
		enabled = filepath.Join(base, "etc", "apache2", "sites-enabled")
	default:
		available = filepath.Join(base, "proxy")
	}
	data := filepath.Join(base, "var", "lib", "nurproxy-agent")
	certs := filepath.Join(data, "certs")
	for _, dir := range []string{available, enabled, certs} {
		if dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	return recoveryFixture{
		base: base, available: available, enabled: enabled, data: data, certs: certs,
		ctx: Context{AgentID: "agent-1", ProxyInfo: proxy.Info{Kind: backend, ConfigDir: available}, ManagedRoots: []string{base}, AgentDataRoot: data},
	}
}

func TestClassifierMarkerOwnershipRequiresExactBackendLayout(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	available := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(available, []byte(proxy.StampManagedArtifact("managed")), 0o600); err != nil {
		t.Fatal(err)
	}
	enabled := filepath.Join(fixture.enabled, filepath.Base(available))
	if err := os.Symlink(available, enabled); err != nil {
		t.Fatal(err)
	}
	otherDir := filepath.Join(fixture.base, "broad-but-not-layout")
	if err := os.Mkdir(otherDir, 0o755); err != nil {
		t.Fatal(err)
	}
	deceptive := filepath.Join(otherDir, "nurproxy-deceptive.conf")
	if err := os.WriteFile(deceptive, []byte("operator"), 0o600); err != nil {
		t.Fatal(err)
	}
	enabledRegular := filepath.Join(fixture.enabled, "nurproxy-regular.conf")
	if err := os.WriteFile(enabledRegular, []byte("operator"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongTarget := filepath.Join(fixture.available, "nurproxy-other.conf")
	if err := os.WriteFile(wrongTarget, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongAlias := filepath.Join(fixture.enabled, "nurproxy-wrong.conf")
	if err := os.Symlink(wrongTarget, wrongAlias); err != nil {
		t.Fatal(err)
	}
	enabledTemp := filepath.Join(fixture.enabled, "nurproxy-stage.conf.nurproxy-tmp")
	availableTemp := filepath.Join(fixture.available, filepath.Base(enabledTemp))
	if err := os.WriteFile(availableTemp, []byte(proxy.StampManagedArtifact("stage")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(availableTemp, enabledTemp); err != nil {
		t.Fatal(err)
	}
	hardlinkMarker := filepath.Join(fixture.available, "nurproxy-hardlink.conf")
	if err := os.Link(wrongTarget, hardlinkMarker); err != nil {
		t.Fatal(err)
	}
	stampedTarget := filepath.Join(fixture.available, "stamped-source")
	if err := os.WriteFile(stampedTarget, []byte(proxy.StampManagedArtifact("hardlink")), 0o600); err != nil {
		t.Fatal(err)
	}
	stampedHardlink := filepath.Join(fixture.available, "nurproxy-stamped-hardlink.conf")
	if err := os.Link(stampedTarget, stampedHardlink); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(fixture.available, "nurproxy-malformed.conf")
	if err := os.WriteFile(malformed, []byte(proxy.ManagedArtifactMarker+"\n"+proxy.ManagedArtifactMarker+"\nserver {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	unmarkedTemp := filepath.Join(fixture.available, "nurproxy-unmarked.conf.nurproxy-tmp")
	if err := os.WriteFile(unmarkedTemp, []byte("staged without provenance"), 0o600); err != nil {
		t.Fatal(err)
	}
	lateMarker := filepath.Join(fixture.available, "nurproxy-late-marker.conf")
	lateContent := strings.Repeat("x", proxy.MaxManagedArtifactMarkerProbeBytes+1) + "\n" + proxy.ManagedArtifactMarker + "\n"
	if err := os.WriteFile(lateMarker, []byte(lateContent), 0o600); err != nil {
		t.Fatal(err)
	}
	danglingAlias := filepath.Join(fixture.enabled, "nurproxy-missing.conf")
	if err := os.Symlink(filepath.Join(fixture.available, filepath.Base(danglingAlias)), danglingAlias); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		eligible bool
	}{
		{"available marker", available, true},
		{"old unmarked config", wrongTarget, false},
		{"exact enabled alias", enabled, true},
		{"broad managed root is not layout", deceptive, false},
		{"enabled regular file is not activation alias", enabledRegular, false},
		{"enabled alias basename differs from target", wrongAlias, false},
		{"enabled temp alias is not a backend activation", enabledTemp, false},
		{"unmarked hardlink is not provenance", hardlinkMarker, false},
		{"stamped hardlink entry is safe for later unlink", stampedHardlink, true},
		{"multiple malformed markers fail closed", malformed, false},
		{"unmarked staged temp fails closed", unmarkedTemp, false},
		{"marker beyond bounded probe fails closed", lateMarker, false},
		{"missing enabled target fails closed", danglingAlias, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(fixture.ctx, locatedFailure(proxy.FailurePhaseValidate, tt.path))
			if got.AutoRepairEligible != tt.eligible {
				t.Fatalf("eligible=%v owner=%q code=%q action=%q", got.AutoRepairEligible, got.Ownership, got.Code, got.ProposedAction)
			}
			if tt.eligible && (got.Ownership != recoverymodel.OwnershipNurProxy || got.Code != recoverymodel.CodeManagedOrphanConfig) {
				t.Fatalf("exact layout marker classification = %+v", got)
			}
		})
	}
}

func TestClassifierAgentDataRootIsAnIndependentAllowlist(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	fixture.ctx.ManagedRoots = []string{filepath.Join(fixture.base, "etc")}
	target := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(target, []byte(proxy.StampManagedArtifact("managed")), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(fixture.certs, "app.crt")
	fixture.ctx.DesiredResources = []DesiredResource{{
		ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target},
		Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true,
		CertPath: cert, RuntimeKeyPath: filepath.Join(fixture.certs, "app.key.plain"),
	}}
	output := `nginx: [emerg] cannot load certificate "` + cert + `": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`
	got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, output, errors.New("exit 1")))
	if !got.AutoRepairEligible || got.Code != recoverymodel.CodeManagedCertFileMissing {
		t.Fatalf("sibling agent-data allowlist classification = %+v", got)
	}
}

func TestClassifierRequiresBackendSpecificMismatchCardinality(t *testing.T) {
	for _, backend := range []proxy.Kind{proxy.KindNginx, proxy.KindApache} {
		t.Run(string(backend), func(t *testing.T) {
			fixture := newRecoveryFixture(t, backend)
			cert := filepath.Join(fixture.certs, "app.crt")
			key := filepath.Join(fixture.certs, "app.key.plain")
			target := filepath.Join(fixture.available, "nurproxy-app.conf")
			for _, path := range []string{cert, key, target} {
				if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fixture.ctx.DesiredResources = []DesiredResource{{ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: cert, RuntimeKeyPath: key}}
			failure := &proxy.Failure{Backend: backend, Phase: proxy.FailurePhaseValidate, RuntimeKeyMismatch: true, Err: errors.New("exit 1")}
			if backend == proxy.KindNginx {
				failure.ReferencedPaths = []string{cert, key}
			} else {
				failure.ReferencedPaths = []string{key}
			}
			got := Classify(fixture.ctx, failure)
			if got.Code != recoverymodel.CodeUnknownProxyError || got.AutoRepairEligible || got.ProposedAction != "" {
				t.Fatalf("cross-form mismatch classification = %+v", got)
			}
		})
	}
}

func TestClassifierMarkerOwnershipFailsClosedForInvalidLayoutContext(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	marker := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(marker, []byte(proxy.StampManagedArtifact("managed")), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Context)
	}{
		{"layout outside outer allowlist", func(ctx *Context) { ctx.ManagedRoots = []string{filepath.Join(fixture.base, "var")} }},
		{"missing config dir", func(ctx *Context) { ctx.ProxyInfo.ConfigDir = filepath.Join(fixture.base, "missing") }},
		{"unsafe config dir", func(ctx *Context) { ctx.ProxyInfo.ConfigDir += "/../sites-available" }},
		{"unknown backend", func(ctx *Context) { ctx.ProxyInfo.Kind = proxy.KindUnknown }},
		{"custom backend", func(ctx *Context) { ctx.ProxyInfo.Kind = proxy.KindCustom }},
		{"caddy backend", func(ctx *Context) { ctx.ProxyInfo.Kind = proxy.KindCaddy }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := fixture.ctx
			tt.mutate(&ctx)
			failure := locatedFailure(proxy.FailurePhaseValidate, marker).(*proxy.Failure)
			failure.Backend = ctx.ProxyInfo.Kind
			got := Classify(ctx, failure)
			if got.Ownership == recoverymodel.OwnershipNurProxy || got.AutoRepairEligible || got.ProposedAction != "" {
				t.Fatalf("invalid layout context produced ownership: %+v", got)
			}
		})
	}
}

func TestClassifierDerivesLayoutFromCanonicalConfigDirectory(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	marker := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(marker, []byte(proxy.StampManagedArtifact("managed")), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(fixture.base, "config-dir-alias")
	if err := os.Symlink(fixture.available, alias); err != nil {
		t.Fatal(err)
	}
	ctx := fixture.ctx
	ctx.ProxyInfo.ConfigDir = alias
	got := Classify(ctx, locatedFailure(proxy.FailurePhaseValidate, marker))
	if !got.AutoRepairEligible || got.Ownership != recoverymodel.OwnershipNurProxy {
		t.Fatalf("canonical config directory alias was not resolved: %+v", got)
	}
}

func TestClassifierUsesSafeReferencedCertPathsWithoutConfigLocation(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	target := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(target, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(fixture.certs, "app.crt")
	keyPath := filepath.Join(fixture.certs, "app.key.plain")
	mismatchCert := filepath.Join(fixture.certs, "mismatch.crt")
	mismatchKey := filepath.Join(fixture.certs, "mismatch.key.plain")
	mismatchTarget := filepath.Join(fixture.available, "nurproxy-mismatch.conf")
	for _, path := range []string{mismatchCert, mismatchKey, mismatchTarget} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resource := DesiredResource{
		ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target},
		Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true,
		CertPath: certPath, RuntimeKeyPath: keyPath,
	}
	mismatchResource := DesiredResource{ArtifactID: "art-mismatch", Host: "mismatch.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: mismatchTarget}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: mismatchCert, RuntimeKeyPath: mismatchKey}
	fixture.ctx.DesiredResources = []DesiredResource{resource, mismatchResource}
	tests := []struct {
		name       string
		output     string
		wantCode   recoverymodel.Code
		wantAction recoverymodel.Action
	}{
		{"missing cert", `nginx: [emerg] cannot load certificate "` + certPath + `": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`, recoverymodel.CodeManagedCertFileMissing, recoverymodel.ActionRematerializeCertBundle},
		{"missing key", `nginx: [emerg] cannot load certificate key "` + keyPath + `": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`, recoverymodel.CodeManagedRuntimeKeyMissing, recoverymodel.ActionRematerializeRuntimeKey},
		{"nginx mismatch key reference", `nginx: [emerg] SSL_CTX_use_PrivateKey("` + mismatchKey + `") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)`, recoverymodel.CodeManagedRuntimeKeyMismatch, recoverymodel.ActionRematerializeRuntimeKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, tt.output, errors.New("exit 1")))
			if got.Code != tt.wantCode || got.Ownership != recoverymodel.OwnershipNurProxy || got.ProposedAction != tt.wantAction || !got.AutoRepairEligible {
				t.Fatalf("classification = %+v", got)
			}
			if len(got.AffectedPaths) != 1 || got.AffectedPaths[0] != map[recoverymodel.Code]string{recoverymodel.CodeManagedCertFileMissing: certPath, recoverymodel.CodeManagedRuntimeKeyMissing: keyPath, recoverymodel.CodeManagedRuntimeKeyMismatch: mismatchKey}[tt.wantCode] {
				t.Fatalf("affected paths = %q", got.AffectedPaths)
			}
		})
	}
}

func TestClassifierRequiresMissingAndMismatchFilesystemState(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	cert := filepath.Join(fixture.certs, "app.crt")
	key := filepath.Join(fixture.certs, "app.key.plain")
	target := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(target, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	resource := DesiredResource{ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: cert, RuntimeKeyPath: key}
	fixture.ctx.DesiredResources = []DesiredResource{resource}
	missingOutput := `nginx: [emerg] cannot load certificate "` + cert + `": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`
	mismatchOutput := `nginx: [emerg] SSL_CTX_use_PrivateKey("` + key + `") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)`
	if got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, mismatchOutput, errors.New("exit 1"))); got.AutoRepairEligible {
		t.Fatal("mismatch with absent expected pair became eligible")
	}
	for _, path := range []string{cert, key} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, missingOutput, errors.New("exit 1"))); got.AutoRepairEligible {
		t.Fatal("missing-file report with an existing file became eligible")
	}
}

func TestClassifierValidatesTwoPathMismatchAsOneExpectedPair(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindApache)
	cert1 := filepath.Join(fixture.certs, "one.crt")
	key1 := filepath.Join(fixture.certs, "one.key.plain")
	cert2 := filepath.Join(fixture.certs, "two.crt")
	key2 := filepath.Join(fixture.certs, "two.key.plain")
	target1 := filepath.Join(fixture.available, "nurproxy-one.conf")
	target2 := filepath.Join(fixture.available, "nurproxy-two.conf")
	for _, path := range []string{cert1, key1, cert2, key2, target1, target2} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture.ctx.DesiredResources = []DesiredResource{
		{ArtifactID: "one", Host: "one.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target1}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: cert1, RuntimeKeyPath: key1},
		{ArtifactID: "two", Host: "two.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target2}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: cert2, RuntimeKeyPath: key2},
	}
	tests := []struct {
		name      string
		cert, key string
		eligible  bool
	}{
		{"exact pair", cert1, key1, true},
		{"cross-resource spoof", cert1, key2, false},
		{"outside pair", filepath.Join(fixture.base, "outside.crt"), filepath.Join(fixture.base, "outside.key"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := `AH02565: Certificate and private key app.example:443:0 from ` + tt.cert + ` and ` + tt.key + ` do not match`
			got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindApache, proxy.FailurePhaseValidate, output, errors.New("exit 1")))
			if got.AutoRepairEligible != tt.eligible {
				t.Fatalf("eligible=%v code=%q owner=%q paths=%q", got.AutoRepairEligible, got.Code, got.Ownership, got.AffectedPaths)
			}
		})
	}
}

func TestClassifierReferencedPathsFailClosedForAmbiguityAndPolicy(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	certPath := filepath.Join(fixture.certs, "app.crt")
	target := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(target, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := DesiredResource{ArtifactID: "one", Host: "one.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: certPath, RuntimeKeyPath: filepath.Join(fixture.certs, "app.key")}
	output := `nginx: [emerg] cannot load certificate "` + certPath + `": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`
	tests := []struct {
		name      string
		resources []DesiredResource
	}{
		{"ambiguous", []DesiredResource{base, *resourceWith(base, func(r *DesiredResource) { r.ArtifactID = "two" })}},
		{"absent bundle", []DesiredResource{*resourceWith(base, func(r *DesiredResource) { r.ValidBundle = false })}},
		{"manual", []DesiredResource{*resourceWith(base, func(r *DesiredResource) { r.Source = models.ArtifactSourceManual })}},
		{"drifted", []DesiredResource{*resourceWith(base, func(r *DesiredResource) { r.Drifted = true })}},
		{"unknown state", []DesiredResource{*resourceWith(base, func(r *DesiredResource) { r.ApplyState = "future" })}},
		{"missing resource host", []DesiredResource{*resourceWith(base, func(r *DesiredResource) { r.Host = "" })}},
		{"missing artifact identity", []DesiredResource{*resourceWith(base, func(r *DesiredResource) { r.ArtifactID = "" })}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := fixture.ctx
			ctx.DesiredResources = tt.resources
			got := Classify(ctx, proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, output, errors.New("exit 1")))
			if got.AutoRepairEligible || got.ProposedAction != "" {
				t.Fatalf("unsafe reference policy produced action: %+v", got)
			}
			if tt.name == "unknown state" && got.Ownership != recoverymodel.OwnershipUnknown {
				t.Fatalf("unknown state ownership = %q", got.Ownership)
			}
		})
	}
}

func TestClassifierRejectsMismatchWhenExpectedPairAliasesSamePath(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindApache)
	shared := filepath.Join(fixture.certs, "shared.pem")
	target := filepath.Join(fixture.available, "nurproxy-app.conf")
	for _, path := range []string{shared, target} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture.ctx.DesiredResources = []DesiredResource{{ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: shared, RuntimeKeyPath: shared}}
	output := `AH02565: Certificate and private key app.example:443:0 from ` + shared + ` and ` + shared + ` do not match`
	got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindApache, proxy.FailurePhaseValidate, output, errors.New("exit 1")))
	if got.AutoRepairEligible || got.ProposedAction != "" || got.Ownership == recoverymodel.OwnershipNurProxy {
		t.Fatalf("aliased cert/key pair became repairable: %+v", got)
	}
}

func TestClassifierReferencedOwnershipRequiresDesiredBackendTarget(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	cert := filepath.Join(fixture.certs, "app.crt")
	fixture.ctx.DesiredResources = []DesiredResource{{ArtifactID: "art-1", Host: "app.example", Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive, ValidBundle: true, CertPath: cert, RuntimeKeyPath: filepath.Join(fixture.certs, "app.key")}}
	output := `nginx: [emerg] cannot load certificate "` + cert + `": BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory)`
	got := Classify(fixture.ctx, proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseValidate, output, errors.New("exit 1")))
	if got.AutoRepairEligible || got.ProposedAction != "" || got.Ownership == recoverymodel.OwnershipNurProxy {
		t.Fatalf("cert path without a desired backend target proved ownership: %+v", got)
	}
}

func TestClassifierRejectsContradictoryFailureMetadata(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	tests := []struct {
		name    string
		failure *proxy.Failure
	}{
		{"backend mismatch", &proxy.Failure{Backend: proxy.KindApache, Phase: proxy.FailurePhaseValidate, BinaryMissing: true}},
		{"unknown backend", &proxy.Failure{Backend: proxy.Kind("haproxy"), Phase: proxy.FailurePhaseValidate, BinaryMissing: true}},
		{"unknown phase", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhase("future"), BinaryMissing: true}},
		{"two primary flags", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, Permission: true, BinaryMissing: true}},
		{"two certificate flags", &proxy.Failure{Backend: proxy.KindNginx, Phase: proxy.FailurePhaseValidate, MissingCert: true, MissingRuntimeKey: true, ReferencedPaths: []string{filepath.Join(fixture.certs, "app.crt")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(fixture.ctx, tt.failure)
			if got.Code != recoverymodel.CodeUnknownProxyError || got.Ownership != recoverymodel.OwnershipUnknown || got.AutoRepairEligible || got.ProposedAction != "" {
				t.Fatalf("contradiction did not fail closed: %+v", got)
			}
		})
	}
}

func TestClassifierRejectsArbitrarySymlinkAndHardlinkAliasesToDesiredResource(t *testing.T) {
	fixture := newRecoveryFixture(t, proxy.KindNginx)
	target := filepath.Join(fixture.available, "nurproxy-app.conf")
	if err := os.WriteFile(target, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	resource := DesiredResource{ArtifactID: "art-1", Host: "app.example", Target: proxy.Target{Kind: proxy.TargetKindFile, Path: target}, Source: models.ArtifactSourceGenerated, ApplyState: models.ArtifactStateLive}
	fixture.ctx.DesiredResources = []DesiredResource{resource}
	symlinkAlias := filepath.Join(fixture.available, "operator-symlink.conf")
	hardlinkAlias := filepath.Join(fixture.available, "operator-hardlink.conf")
	if err := os.Symlink(target, symlinkAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, hardlinkAlias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{symlinkAlias, hardlinkAlias} {
		got := Classify(fixture.ctx, locatedFailure(proxy.FailurePhaseValidate, path))
		if got.Ownership == recoverymodel.OwnershipNurProxy || got.AutoRepairEligible || got.ProposedAction != "" {
			t.Fatalf("alias %q became desired-resource ownership: %+v", path, got)
		}
	}
}
