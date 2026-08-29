package apache

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

// TestPrune_removesOrphanedGeneratedKeepsOperator mirrors the nginx Prune test:
// Prune deletes only NurProxy-generated vhosts absent from the keep set, never an
// operator's adopted config, reloads once, and drops the htpasswd sidecar too.
func TestPrune_removesOrphanedGeneratedKeepsOperator(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	ctx := context.Background()

	keep := sampleArtifact(b, "keep.example.com", "<VirtualHost *:80></VirtualHost>\n")
	orphan := sampleArtifact(b, "gone.example.com", "<VirtualHost *:80></VirtualHost>\n")
	if err := b.Apply(ctx, []proxy.Artifact{keep, orphan}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	operatorPath := filepath.Join(layout.Available, "operator-site.conf")
	if err := os.WriteFile(operatorPath, []byte("<VirtualHost *:80></VirtualHost>\n"), 0o644); err != nil {
		t.Fatalf("seeding operator file: %v", err)
	}
	orphanAuth := strings.TrimSuffix(orphan.Target.Path, ".conf") + htpasswdSuffix
	if err := os.WriteFile(orphanAuth, []byte("admin:x\n"), 0o644); err != nil {
		t.Fatalf("seeding orphan htpasswd: %v", err)
	}

	r.reloads = 0
	n, err := b.Prune(ctx, []proxy.Target{keep.Target})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	if _, err := os.Stat(orphan.Target.Path); !os.IsNotExist(err) {
		t.Errorf("orphaned generated vhost still present")
	}
	if _, err := os.Stat(orphanAuth); !os.IsNotExist(err) {
		t.Errorf("orphaned htpasswd sidecar not removed")
	}
	if _, err := os.Stat(keep.Target.Path); err != nil {
		t.Errorf("kept vhost was removed: %v", err)
	}
	if _, err := os.Stat(operatorPath); err != nil {
		t.Errorf("operator config was removed — must never be pruned: %v", err)
	}
	if r.reloads != 1 {
		t.Errorf("reloads = %d, want 1", r.reloads)
	}
}

func TestWildcardRecoveryDecodesHostAndRoutinePruneStillConverges(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	ctx := context.Background()
	wildcard := sampleArtifact(b, "*.example.com", "<VirtualHost *:80></VirtualHost>\n")
	if err := b.Apply(ctx, []proxy.Artifact{wildcard}); err != nil {
		t.Fatal(err)
	}
	candidates, err := b.InspectRecovery(ctx, proxy.RecoveryDesired{})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Host != "*.example.com" || candidates[0].Action != recoverymodel.ActionPruneManagedOrphan {
		t.Fatalf("wildcard candidates = %+v", candidates)
	}
	if n, err := b.Prune(ctx, nil); err != nil || n != 1 {
		t.Fatalf("wildcard routine prune = %d, %v", n, err)
	}
	if _, err := os.Lstat(wildcard.Target.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wildcard config survived routine prune: %v", err)
	}
	temp := layout.AvailablePath("*.temp.example.com") + tempSuffix
	if err := os.WriteFile(temp, []byte(proxy.StampManagedArtifact("staged\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	candidates, err = b.InspectRecovery(ctx, proxy.RecoveryDesired{})
	if err != nil || len(candidates) != 1 || candidates[0].Host != "*.temp.example.com" || candidates[0].Action != recoverymodel.ActionRemoveManagedTemp {
		t.Fatalf("wildcard temp candidates = %+v err=%v", candidates, err)
	}
}

// TestRender_basicAuth_writesHtpasswdAndReferencesIt proves basic auth is functional
// on apache: Render writes the htpasswd from the intent's bcrypt entry and the vhost
// references it via AuthUserFile (instead of dropping it).
func TestRender_basicAuth_writesHtpasswdAndReferencesIt(t *testing.T) {
	b, _ := newDebianBackend(t, &fakeRunner{})
	route := proxymodel.Route{
		Host:     "secure.example.com",
		Upstream: proxymodel.Upstream{Addr: "127.0.0.1", Port: 8080},
		BasicAuth: &proxymodel.BasicAuth{
			Username:     "admin",
			PasswordHash: "$2y$05$abcdefghijklmnopqrstuvWXYZ0123456789abcdefghijklmO",
		},
	}
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(art.Content, "AuthType Basic") || !strings.Contains(art.Content, "AuthUserFile") {
		t.Errorf("vhost missing basic-auth directives:\n%s", art.Content)
	}
	for _, w := range art.Warnings {
		if strings.Contains(w, "basic_auth") {
			t.Errorf("basic_auth should NOT be dropped now: %q", w)
		}
	}
	authPath := b.authFilePath("secure.example.com")
	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("htpasswd not written: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "admin:$2y$05$abcdefghijklmnopqrstuvWXYZ0123456789abcdefghijklmO" {
		t.Errorf("htpasswd content = %q", got)
	}
}

// fakeRunner is an injectable Runner that records calls and returns canned
// results so Apply's atomic orchestration is testable without a real apache.
type fakeRunner struct {
	testOut   string
	testErr   error
	reloadErr error
	tests     int
	reloads   int
}

func (f *fakeRunner) Test(ctx context.Context) (string, error) {
	f.tests++
	return f.testOut, f.testErr
}

func (f *fakeRunner) Reload(ctx context.Context) error {
	f.reloads++
	return f.reloadErr
}

// newDebianBackend builds a backend rooted at a temp sites-available dir (Debian
// layout, with sites-enabled symlinks) and an injected runner.
func newDebianBackend(t *testing.T, r Runner) (*Backend, Layout) {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{Type: "apache", ConfigDir: filepath.Join(dir, "sites-available")})
	b.WithRunner(r)
	return b, b.layout
}

// newRHELBackend builds a backend rooted at a temp conf.d dir (RHEL flat layout,
// no symlinks) and an injected runner.
func newRHELBackend(t *testing.T, r Runner) (*Backend, Layout) {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{Type: "apache", ConfigDir: filepath.Join(dir, "conf.d")})
	b.WithRunner(r)
	return b, b.layout
}

func sampleArtifact(b *Backend, host, content string) proxy.Artifact {
	return proxy.Artifact{
		Target:  proxy.Target{Kind: proxy.TargetKindFile, Path: b.layout.AvailablePath(host)},
		Content: proxy.StampManagedArtifact(content),
		Enabled: true,
	}
}

func TestApply_debian_success_writesFileSymlinkAndReloads(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	got, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied file: %v", err)
	}
	if string(got) != art.Content {
		t.Errorf("file content = %q, want %q", got, art.Content)
	}
	link := layout.EnabledPath("app.example.com")
	if !symlinkPresent(link) {
		t.Errorf("expected sites-enabled symlink at %q", link)
	}
	if _, err := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(err) {
		t.Errorf("temp file should be removed after commit, stat err = %v", err)
	}
	if r.tests != 1 || r.reloads != 1 {
		t.Errorf("tests=%d reloads=%d, want 1/1", r.tests, r.reloads)
	}
}

func TestApply_rhel_confd_noSymlink_reloads(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newRHELBackend(t, r)
	if !layout.IsConfD() {
		t.Fatalf("expected conf.d layout, got Enabled=%q", layout.Enabled)
	}
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	// The file lives in conf.d; there is no enable symlink (presence == enabled).
	if _, err := os.Stat(art.Target.Path); err != nil {
		t.Fatalf("expected conf.d file present: %v", err)
	}
	if layout.EnabledPath("app.example.com") != "" {
		t.Errorf("conf.d layout should have no enabled path")
	}
	if r.reloads != 1 {
		t.Errorf("reloads=%d, want 1", r.reloads)
	}
}

func TestApply_configtestFails_rollsBack_newFile(t *testing.T) {
	r := &fakeRunner{testErr: errors.New("bad"), testOut: "Syntax error on line 3 of /x/nurproxy-app.example.com.conf:"}
	b, layout := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected Apply to fail on configtest error")
	}
	if _, statErr := os.Stat(art.Target.Path); !os.IsNotExist(statErr) {
		t.Errorf("brand-new file should be removed on rollback")
	}
	if symlinkPresent(layout.EnabledPath("app.example.com")) {
		t.Errorf("symlink should not survive rollback of a new file")
	}
	if _, statErr := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(statErr) {
		t.Errorf("temp file should be removed on rollback")
	}
	if r.reloads != 0 {
		t.Errorf("reload should not run after a failed configtest")
	}
}

func TestApply_configtestFails_rollsBack_priorContent(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	host := "app.example.com"

	// First good apply establishes prior content.
	first := sampleArtifact(b, host, "<VirtualHost *:80># v1</VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{first}); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// Second apply fails configtest; prior content must be restored.
	r.testErr = errors.New("bad")
	r.testOut = "Syntax error on line 1 of /x/nurproxy-app.example.com.conf:"
	second := sampleArtifact(b, host, "<VirtualHost *:80># v2 BROKEN</VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{second}); err == nil {
		t.Fatal("expected second apply to fail")
	}
	got, err := os.ReadFile(first.Target.Path)
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(got) != first.Content {
		t.Errorf("prior content not restored: got %q want %q", got, first.Content)
	}
}

// TestApply_symlinkFails_restoresPriorContent reproduces the operator setup where
// the sites-enabled entry is a copied regular file (not a symlink): ensureSymlink
// refuses to clobber it and Apply fails. The prior content of the live file must
// be restored — the failed apply must not leave the new (rejected) config on disk.
func TestApply_symlinkFails_restoresPriorContent(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)

	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Enabled, 0o755); err != nil {
		t.Fatal(err)
	}

	dest := layout.AvailablePath("app.example.com")
	prior := "<VirtualHost *:80># GOOD\n</VirtualHost>\n"
	if err := os.WriteFile(dest, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	// Operator activated by COPYING a regular file into sites-enabled (not a
	// symlink); ensureSymlink refuses to replace it, so Apply fails mid-iteration.
	if err := os.WriteFile(layout.EnabledPath("app.example.com"), []byte("copied\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80># NEW\n</VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err == nil {
		t.Fatal("expected error when sites-enabled holds a regular file")
	}
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("reading restored file: %v", readErr)
	}
	if string(got) != prior {
		t.Errorf("restored content = %q, want prior %q", got, prior)
	}
	if r.tests != 0 {
		t.Errorf("configtest ran %d times, want 0 (failed before validation)", r.tests)
	}
}

func TestApply_reloadFails_rollsBack(t *testing.T) {
	r := &fakeRunner{reloadErr: errors.New("reload boom")}
	b, layout := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected Apply to fail on reload error")
	}
	var failure *proxy.Failure
	if !errors.As(err, &failure) || failure.Backend != proxy.KindApache || failure.Phase != proxy.FailurePhaseReload {
		t.Fatalf("reload error = %#v, want typed apache reload failure", err)
	}
	if _, statErr := os.Stat(art.Target.Path); !os.IsNotExist(statErr) {
		t.Errorf("file should be removed on rollback after reload failure")
	}
	if symlinkPresent(layout.EnabledPath("app.example.com")) {
		t.Errorf("symlink should not survive rollback after reload failure")
	}
}

func TestApply_reloadSudoDenialReturnsPermissionFailure(t *testing.T) {
	r := &fakeRunner{reloadErr: errors.New("exit status 1: sudo: a password is required")}
	b, _ := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")
	err := b.Apply(context.Background(), []proxy.Artifact{art})
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if !failure.Permission || failure.Phase != proxy.FailurePhaseReload {
		t.Fatalf("failure = %#v, want reload permission failure", failure)
	}
}

func TestValidate_untypedBinaryMissingIsUnknown(t *testing.T) {
	b, _ := newDebianBackend(t, &fakeRunner{testErr: exec.ErrNotFound})
	err := b.Validate(context.Background())
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if failure.BinaryMissing || failure.Phase != proxy.FailurePhaseValidate {
		t.Fatalf("failure = %#v, want unverified binary error to stay unknown", failure)
	}
}

func TestValidate_missingApacheExecutableReturnsBinaryFailure(t *testing.T) {
	t.Setenv("NURPROXY_NO_SUDO", "1")
	missing := filepath.Join(t.TempDir(), "apachectl")
	b, _ := newDebianBackend(t, &execRunner{binary: missing})
	err := b.Validate(context.Background())
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if !failure.BinaryMissing {
		t.Fatalf("failure = %#v, want verified missing apachectl", failure)
	}
	var executionErr *proxy.ExecutionError
	if !errors.As(failure, &executionErr) || executionErr.Role != proxy.ExecutionRoleBackend {
		t.Fatalf("execution error = %#v, want backend role", executionErr)
	}
}

func TestExecRunnerSameNameOverridesAreNotBackendBinaryFailures(t *testing.T) {
	t.Setenv("NURPROXY_NO_SUDO", "1")
	for _, step := range []string{"test", "reload"} {
		t.Run(step, func(t *testing.T) {
			name := "apachectl"
			if step == "reload" {
				name = "httpd"
			}
			missing := filepath.Join(t.TempDir(), name)
			r := &execRunner{binary: "/usr/sbin/apachectl"}
			var err error
			if step == "test" {
				r.testCmd = missing
				_, err = r.Test(context.Background())
			} else {
				r.reloadCmd = missing
				err = r.Reload(context.Background())
			}
			failure := proxy.NewFailure(proxy.KindApache, proxy.FailurePhaseValidate, "", err)
			if failure.BinaryMissing {
				t.Fatalf("same-name %s override was mistaken for backend binary: %#v", step, failure)
			}
			var executionErr *proxy.ExecutionError
			if !errors.As(err, &executionErr) || executionErr.Role != proxy.ExecutionRoleOverride {
				t.Fatalf("execution error = %#v, want override role", executionErr)
			}
		})
	}
}

func TestExecRunnerExecutionMetadataDistinguishesBackendAndOverrides(t *testing.T) {
	r := &execRunner{
		binary:    "/tmp/configured/apachectl",
		testCmd:   "/tmp/override/apachectl configtest",
		reloadCmd: "/tmp/override/httpd graceful",
	}
	tests := []struct {
		name     string
		override string
		args     []string
		wantPath string
		wantRole proxy.ExecutionRole
	}{
		{name: "backend test", args: []string{"configtest"}, wantPath: r.binary, wantRole: proxy.ExecutionRoleBackend},
		{name: "backend reload", args: []string{"graceful"}, wantPath: r.binary, wantRole: proxy.ExecutionRoleBackend},
		{name: "override test", override: r.testCmd, args: []string{"configtest"}, wantPath: "/tmp/override/apachectl", wantRole: proxy.ExecutionRoleOverride},
		{name: "override reload", override: r.reloadCmd, args: []string{"graceful"}, wantPath: "/tmp/override/httpd", wantRole: proxy.ExecutionRoleOverride},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, target, role := r.execution(context.Background(), tt.override, tt.args...)
			if target != tt.wantPath || role != tt.wantRole {
				t.Fatalf("target/role = %q/%q, want %q/%q", target, role, tt.wantPath, tt.wantRole)
			}
		})
	}
}

func TestExecRunnerReloadCanonicalCaptureClassifiesRealAH00091(t *testing.T) {
	t.Setenv("NURPROXY_NO_SUDO", "1")
	output := `(13)Permission denied: AH00091: apache2: could not open error log file /var/log/apache2/error.log.`
	script := filepath.Join(t.TempDir(), "reload-check")
	body := "#!/bin/sh\nprintf '%s\\n' '" + output + "' >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	err := (&execRunner{binary: "/usr/sbin/apachectl", reloadCmd: script}).Reload(context.Background())
	failure := proxy.NewFailure(proxy.KindApache, proxy.FailurePhaseReload, err.Error(), err)
	if !failure.Permission || failure.Output != output+"\n" {
		t.Fatalf("failure = %#v, want canonical AH00091 output %q", failure, output+"\n")
	}
	if strings.Contains(failure.Output, "starting proxy executable failed") {
		t.Fatalf("Failure.Output used wrapper text: %q", failure.Output)
	}
	var exitErr *exec.ExitError
	if !errors.As(failure, &exitErr) {
		t.Fatal("reload ExitError chain was not preserved")
	}
}

func TestValidate_permissionDeniedReturnsTypedFailure(t *testing.T) {
	r := &fakeRunner{
		testErr: errors.New("exit status 1"),
		testOut: "httpd: could not open error log file /var/log/httpd/error_log. Permission denied",
	}
	b, _ := newDebianBackend(t, r)
	err := b.Validate(context.Background())
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if !failure.Permission || failure.Located || failure.ManagedHint {
		t.Fatalf("failure = %#v, want unlocated permission failure without managed hint", failure)
	}
}

func TestInstallCerts_failureReturnsTypedFailure(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: t.TempDir(), CertDir: t.TempDir()})
	err := b.InstallCerts(context.Background(), []proxy.CertBundle{{Host: "app.example.com"}})
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if failure.Backend != proxy.KindApache || failure.Phase != proxy.FailurePhaseCertInstall {
		t.Fatalf("failure = %#v, want apache cert_install failure", failure)
	}
}

func TestApply_configtestFails_returnsAttributedError(t *testing.T) {
	r := &fakeRunner{
		testErr: errors.New("exit 1"),
		testOut: "AH00526: Syntax error on line 9 of /etc/apache2/sites-enabled/operator.conf:\nInvalid command 'Bogus'",
	}
	b, _ := newDebianBackend(t, r)
	art := sampleArtifact(b, "app.example.com", "<VirtualHost *:80></VirtualHost>\n")

	err := b.Apply(context.Background(), []proxy.Artifact{art})
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if failure.Backend != proxy.KindApache || failure.Phase != proxy.FailurePhaseValidate {
		t.Errorf("backend/phase = %s/%s, want apache/validate", failure.Backend, failure.Phase)
	}
	if !failure.Located {
		t.Fatalf("attribution should be located")
	}
	if failure.ManagedHint {
		t.Errorf("blame should be the operator's file, not ours")
	}
	if failure.Line != 9 {
		t.Errorf("line = %d, want 9", failure.Line)
	}
}

func TestApply_configtestFailureInSecondArtifactHasManagedHint(t *testing.T) {
	r := &fakeRunner{testErr: errors.New("exit 1")}
	b, _ := newDebianBackend(t, r)
	first := sampleArtifact(b, "one.example.com", "<VirtualHost *:80></VirtualHost>\n")
	second := sampleArtifact(b, "two.example.com", "<VirtualHost *:80>Bad</VirtualHost>\n")
	r.testOut = "Syntax error on line 1 of " + second.Target.Path + ":"

	err := b.Apply(context.Background(), []proxy.Artifact{first, second})
	var failure *proxy.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *proxy.Failure", err)
	}
	if !failure.ManagedHint || failure.File != second.Target.Path {
		t.Fatalf("failure = %#v, want managed hint for second artifact", failure)
	}
}

func TestExecRunnerTestBoundsCombinedOutput(t *testing.T) {
	t.Setenv("NURPROXY_NO_SUDO", "1")
	script := filepath.Join(t.TempDir(), "noisy-apache-test")
	body := "#!/bin/sh\nprintf 'apache-test-stdout\\n'\nprintf 'apache-test-stderr\\n' >&2\nhead -c 4194304 /dev/zero | tr '\\000' x\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := (&execRunner{testCmd: script}).Test(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > proxy.MaxFailureCaptureBytes || !strings.Contains(out, proxy.FailureOutputTruncated) {
		t.Fatalf("captured bytes=%d marker=%v", len(out), strings.Contains(out, proxy.FailureOutputTruncated))
	}
}

func TestRemove_debian_deletesFileAndSymlink(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	host := "gone.example.com"
	art := sampleArtifact(b, host, "<VirtualHost *:80></VirtualHost>\n")
	if err := b.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := b.Remove(context.Background(), art.Target); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(art.Target.Path); !os.IsNotExist(err) {
		t.Errorf("config file should be removed")
	}
	if symlinkPresent(layout.EnabledPath(host)) {
		t.Errorf("symlink should be removed")
	}
}

func TestRemove_missingFile_notAnError(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	tgt := proxy.Target{Kind: proxy.TargetKindFile, Path: b.layout.AvailablePath("nope.example.com")}
	if err := b.Remove(context.Background(), tgt); err != nil {
		t.Errorf("removing a missing file should be a no-op, got %v", err)
	}
}

func TestReadManaged_adoptsAllFiles_taggingManagedVsOperator(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Enabled, 0o755); err != nil {
		t.Fatal(err)
	}

	// A managed (generated) file.
	managed := layout.AvailablePath("managed.example.com")
	if err := os.WriteFile(managed, []byte(proxy.StampManagedArtifact("<VirtualHost *:80></VirtualHost>\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	// Enable it via symlink.
	if err := os.Symlink(managed, layout.EnabledPath("managed.example.com")); err != nil {
		t.Fatal(err)
	}
	// An operator-authored file (no nurproxy- prefix).
	operator := filepath.Join(layout.Available, "operator.conf")
	if err := os.WriteFile(operator, []byte("<VirtualHost *:80># mine</VirtualHost>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An in-flight temp must be skipped.
	if err := os.WriteFile(managed+tempSuffix, []byte("temp"), 0o644); err != nil {
		t.Fatal(err)
	}

	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged: %v", err)
	}
	byBase := map[string]proxy.Artifact{}
	for _, a := range arts {
		byBase[filepath.Base(a.Target.Path)] = a
	}
	if _, ok := byBase[filepath.Base(managed)+tempSuffix]; ok {
		t.Errorf("temp file should be skipped")
	}
	m, ok := byBase[ManagedFileName("managed.example.com")]
	if !ok {
		t.Fatalf("managed file not read")
	}
	if m.Adopted {
		t.Errorf("managed file should not be Adopted")
	}
	if !m.Enabled {
		t.Errorf("managed file symlink present, Enabled should be true")
	}
	o, ok := byBase["operator.conf"]
	if !ok {
		t.Fatalf("operator file not read")
	}
	if !o.Adopted {
		t.Errorf("operator file should be Adopted (Source: manual)")
	}
}

func TestManagedProvenanceControlsReadAndPrune(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackend(t, r)
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	stamped := layout.AvailablePath("stamped.example.com")
	unmarked := layout.AvailablePath("unmarked.example.com")
	malformed := layout.AvailablePath("malformed.example.com")
	late := layout.AvailablePath("late.example.com")
	for path, content := range map[string]string{
		stamped:   proxy.StampManagedArtifact("<VirtualHost *:80></VirtualHost>\n"),
		unmarked:  "<VirtualHost *:80></VirtualHost>\n",
		malformed: proxy.ManagedArtifactMarker + " trailing\n<VirtualHost *:80></VirtualHost>\n",
		late:      strings.Repeat("x", proxy.MaxManagedArtifactMarkerProbeBytes+1) + "\n" + proxy.ManagedArtifactMarker + "\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	symlink := layout.AvailablePath("symlink.example.com")
	if err := os.Symlink(stamped, symlink); err != nil {
		t.Fatal(err)
	}

	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]proxy.Artifact, len(arts))
	for _, art := range arts {
		byPath[art.Target.Path] = art
	}
	if art, ok := byPath[stamped]; !ok || art.Adopted {
		t.Fatalf("stamped artifact = %+v, present=%v", art, ok)
	}
	for _, path := range []string{unmarked, malformed, late} {
		if art, ok := byPath[path]; !ok || !art.Adopted {
			t.Errorf("unsafe artifact %q = %+v, present=%v", path, art, ok)
		}
	}
	if _, ok := byPath[symlink]; ok {
		t.Error("ReadManaged followed a symlink entry")
	}

	removed, err := b.Prune(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want stamped artifact only", removed)
	}
	if _, err := os.Lstat(stamped); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stamped artifact survived prune: %v", err)
	}
	for _, path := range []string{unmarked, malformed, late, symlink} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("unsafe entry %q was pruned: %v", path, err)
		}
	}
}

func TestRecoveryAdapterInspectsAndExecutesOwnedFileCandidates(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newDebianBackendWithCerts(t, r)
	for _, dir := range []string{layout.Available, layout.Enabled, b.certs.Dir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	host := "orphan.example.com"
	config := layout.AvailablePath(host)
	if err := os.WriteFile(config, []byte(proxy.StampManagedArtifact("<VirtualHost/>\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	link := layout.EnabledPath(host)
	if err := os.Symlink(config, link); err != nil {
		t.Fatal(err)
	}
	auth := strings.TrimSuffix(config, confSuffix) + htpasswdSuffix
	if err := os.WriteFile(auth, []byte("admin:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	certInspection, err := b.certs.InspectRecovery(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{certInspection.CertPath, certInspection.SourceKeyPath, certInspection.RuntimeKeyPath} {
		if err := os.WriteFile(path, []byte("sidecar"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	temp := layout.AvailablePath("stale.example.com") + tempSuffix
	if err := os.WriteFile(temp, []byte(proxy.StampManagedArtifact("staged\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	activeTemp := layout.AvailablePath("active.example.com") + tempSuffix
	if err := os.WriteFile(activeTemp, []byte(proxy.StampManagedArtifact("active\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	invalidHost := "invalid-key.example.com"
	invalidPaths := b.certs.RecoveryPaths(invalidHost)
	if err := os.WriteFile(invalidPaths.CertPath, []byte("present-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPaths.SourceKeyPath, []byte("invalid-encrypted-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidates, err := b.InspectRecovery(context.Background(), proxy.RecoveryDesired{ActiveOperationPaths: []string{activeTemp}, KeepCertHosts: []string{"missing.example.com", invalidHost}})
	if err != nil {
		t.Fatal(err)
	}
	byAction := map[recoverymodel.Action]proxy.RecoveryCandidate{}
	for _, candidate := range candidates {
		byAction[candidate.Action] = candidate
		if err := candidate.Validate(); err != nil || len(candidate.Paths) != len(candidate.Identities) {
			t.Fatalf("invalid candidate: %+v err=%v", candidate, err)
		}
	}
	orphan := byAction[recoverymodel.ActionPruneManagedOrphan]
	stale := byAction[recoverymodel.ActionRemoveManagedTemp]
	missingCert := byAction[recoverymodel.ActionRematerializeCertBundle]
	certHosts := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.Action == recoverymodel.ActionRematerializeCertBundle {
			certHosts[candidate.Host] = true
		}
	}
	if orphan.Host != host || len(orphan.Paths) < 3 || stale.Host != "stale.example.com" || !certHosts["missing.example.com"] || !certHosts[invalidHost] || missingCert.Host == "" {
		t.Fatalf("candidates = %+v", candidates)
	}
	if err := b.ExecuteRecovery(context.Background(), stale, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.ExecuteRecovery(context.Background(), orphan, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(orphan.Paths, stale.Paths...) {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("recovered path %q remains: %v", path, err)
		}
	}
	if _, err := os.Lstat(activeTemp); err != nil {
		t.Fatalf("active temp was removed: %v", err)
	}
	if r.tests != 2 || r.reloads != 2 {
		t.Fatalf("validate/reload = %d/%d, want 2/2", r.tests, r.reloads)
	}
}

func TestReadManaged_confd_presenceMeansEnabled(t *testing.T) {
	r := &fakeRunner{}
	b, layout := newRHELBackend(t, r)
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}
	f := layout.AvailablePath("app.example.com")
	if err := os.WriteFile(f, []byte("<VirtualHost *:80></VirtualHost>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged: %v", err)
	}
	if len(arts) != 1 || !arts[0].Enabled {
		t.Errorf("conf.d file should report Enabled=true via presence, got %+v", arts)
	}
}

func TestReadManaged_missingDir_returnsNil(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	arts, err := b.ReadManaged(context.Background())
	if err != nil {
		t.Fatalf("ReadManaged on missing dir: %v", err)
	}
	if arts != nil {
		t.Errorf("expected nil artifacts for missing dir, got %v", arts)
	}
}

func TestRender_dropsUnsupportedRateLimit(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	route := proxymodel.Route{
		Host:      "app.example.com",
		Upstream:  proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080},
		RateLimit: proxymodel.RateLimit{RequestsPerSecond: 5},
		TLS:       proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Render never errors on a dropped option; the artifact still has a vhost.
	if art.Content == "" {
		t.Errorf("expected non-empty content even with a dropped option")
	}
	if !proxy.HasManagedArtifactMarker(art.Content) || strings.Count(art.Content, proxy.ManagedArtifactMarker) != 1 {
		t.Fatalf("Render content has no single managed marker: %q", art.Content)
	}
	if art.Target.Path != b.layout.AvailablePath("app.example.com") {
		t.Errorf("target path = %q", art.Target.Path)
	}
}

func TestRender_rawRouteStampsManagedArtifactMarkerOnce(t *testing.T) {
	b, _ := newDebianBackend(t, &fakeRunner{})
	raw := "<VirtualHost *:80></VirtualHost>\n" + proxy.ManagedArtifactMarker + "\n"
	art, err := b.Render(context.Background(), proxymodel.Route{Host: "raw.example.com", Raw: proxymodel.RawConfig{Backend: "apache", Content: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if !proxy.HasManagedArtifactMarker(art.Content) || strings.Count(art.Content, proxy.ManagedArtifactMarker) != 1 {
		t.Fatalf("raw Render marker = %q", art.Content)
	}
}

func TestCapabilities_rateLimitFalse_centralTLSDependsOnCertStore(t *testing.T) {
	noCerts := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available"})
	if noCerts.Capabilities().RateLimit {
		t.Errorf("apache must report RateLimit=false")
	}
	if noCerts.Capabilities().CentralTLS {
		t.Errorf("CentralTLS should be false without a cert dir")
	}
	withCerts := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", CertDir: t.TempDir()})
	if !withCerts.Capabilities().CentralTLS {
		t.Errorf("CentralTLS should be true with a cert dir")
	}
}

func TestApply_emptyArtifacts_noop(t *testing.T) {
	r := &fakeRunner{}
	b, _ := newDebianBackend(t, r)
	if err := b.Apply(context.Background(), nil); err != nil {
		t.Errorf("empty apply should be a no-op, got %v", err)
	}
	if r.tests != 0 || r.reloads != 0 {
		t.Errorf("empty apply should not run commands")
	}
}

func TestRegistered_includesApache(t *testing.T) {
	found := false
	for _, n := range proxy.Registered() {
		if n == "apache" {
			found = true
		}
	}
	if !found {
		t.Errorf("apache backend should be registered in init(); registered = %v", proxy.Registered())
	}
}

func TestProbeDirs_debianLayout_includesEnabledDir(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available"})
	dirs := b.ProbeDirs()
	if len(dirs) != 2 {
		t.Fatalf("Debian layout should probe sites-available + sites-enabled, got %v", dirs)
	}
	if dirs[0] != "/etc/apache2/sites-available" || dirs[1] != "/etc/apache2/sites-enabled" {
		t.Fatalf("unexpected probe dirs: %v", dirs)
	}
}

func TestProbeDirs_confDLayout_onlyAvailableDir(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/httpd/conf.d"})
	dirs := b.ProbeDirs()
	if len(dirs) != 1 || dirs[0] != "/etc/httpd/conf.d" {
		t.Fatalf("conf.d layout should probe only the one dir, got %v", dirs)
	}
}

func TestReloadHint_default_andOverride(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", Binary: "/usr/sbin/apachectl"})
	if got := b.ReloadHint(); got != "/usr/sbin/apachectl graceful" {
		t.Fatalf("default ReloadHint = %q", got)
	}
	o := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", ReloadCmd: "sudo systemctl reload apache2"})
	if got := o.ReloadHint(); got != "sudo systemctl reload apache2" {
		t.Fatalf("override ReloadHint = %q", got)
	}
}

func TestResolvedCommands_default_andOverride(t *testing.T) {
	b := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", Binary: "/usr/sbin/apachectl"})
	test, reload := b.ResolvedCommands()
	if test != "/usr/sbin/apachectl configtest" {
		t.Fatalf("default test cmd = %q", test)
	}
	if reload != "/usr/sbin/apachectl graceful" {
		t.Fatalf("default reload cmd = %q", reload)
	}

	o := New(proxy.Config{
		Type:      "apache",
		ConfigDir: "/etc/apache2/sites-available",
		Binary:    "/usr/sbin/apachectl",
		TestCmd:   "sudo /usr/sbin/apachectl configtest",
		ReloadCmd: "sudo systemctl reload apache2",
	})
	test, reload = o.ResolvedCommands()
	if test != "sudo /usr/sbin/apachectl configtest" {
		t.Fatalf("override test cmd = %q", test)
	}
	if reload != "sudo systemctl reload apache2" {
		t.Fatalf("override reload cmd = %q", reload)
	}

	// No detected binary falls back to the bare "apachectl" defaults.
	nb := New(proxy.Config{Type: "apache", ConfigDir: "/etc/apache2/sites-available", Binary: "nope-not-a-real-binary"})
	nb.binary = ""
	nb.runner = &execRunner{}
	test, reload = nb.ResolvedCommands()
	if test != "apachectl configtest" || reload != "apachectl graceful" {
		t.Fatalf("empty-binary fallback = %q / %q", test, reload)
	}
}

// newDebianBackendWithCerts builds a Debian-layout backend whose cert store
// points at a temp dir so Remove/Prune cert-scrubbing is exercisable.
func newDebianBackendWithCerts(t *testing.T, r Runner) (*Backend, Layout) {
	t.Helper()
	dir := t.TempDir()
	b := New(proxy.Config{
		Type:      "apache",
		ConfigDir: filepath.Join(dir, "sites-available"),
		CertDir:   filepath.Join(dir, "certs"),
	})
	b.WithRunner(r)
	if b.certs == nil {
		t.Fatal("expected cert store to be configured")
	}
	return b, b.layout
}

func installCertArtifacts(t *testing.T, b *Backend, host string) []string {
	t.Helper()
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
	if err := b.InstallCerts(context.Background(), []proxy.CertBundle{{Host: host, CertPEM: certPEM, KeyPEM: keyPEM}}); err != nil {
		t.Fatalf("InstallCerts: %v", err)
	}
	base := filepath.Join(b.certs.Dir(), host)
	plain := base + ".key.plain"
	if err := os.WriteFile(plain, keyPEM, 0o600); err != nil {
		t.Fatalf("seed .key.plain: %v", err)
	}
	return []string{base + ".crt", base + ".key", plain}
}

func assertGone(t *testing.T, paths []string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("cert artifact %q still present (stat err=%v)", p, err)
		}
	}
}

// TestRemove_scrubsCertArtifacts proves a removed managed vhost's cert/key files
// (including the decrypted .key.plain) are deleted, while an operator config
// never triggers a cert scrub.
func TestRemove_scrubsCertArtifacts(t *testing.T) {
	t.Run("managed vhost scrubs certs", func(t *testing.T) {
		b, layout := newDebianBackendWithCerts(t, &fakeRunner{})
		host := "app.example.com"
		artifacts := installCertArtifacts(t, b, host)
		confPath := layout.AvailablePath(host)
		if err := os.MkdirAll(layout.Available, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(confPath, []byte("<VirtualHost/>\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := b.Remove(context.Background(), proxy.Target{Kind: proxy.TargetKindFile, Path: confPath}); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		assertGone(t, artifacts)
	})

	t.Run("operator config leaves certs untouched", func(t *testing.T) {
		b, layout := newDebianBackendWithCerts(t, &fakeRunner{})
		artifacts := installCertArtifacts(t, b, "app.example.com")
		opPath := filepath.Join(layout.Available, "operator-site.conf")
		if err := os.MkdirAll(layout.Available, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(opPath, []byte("<VirtualHost/>\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := b.Remove(context.Background(), proxy.Target{Kind: proxy.TargetKindFile, Path: opPath}); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		for _, p := range artifacts {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("unrelated cert artifact %q was wrongly removed: %v", p, err)
			}
		}
	})
}

// TestPrune_scrubsCertArtifacts proves a pruned orphan vhost's cert/key files
// are deleted while a kept vhost's stay.
func TestPrune_scrubsCertArtifacts(t *testing.T) {
	b, layout := newDebianBackendWithCerts(t, &fakeRunner{})
	if err := os.MkdirAll(layout.Available, 0o755); err != nil {
		t.Fatal(err)
	}

	orphanHost := "orphan.example.com"
	keepHost := "keep.example.com"
	orphanArts := installCertArtifacts(t, b, orphanHost)
	keepArts := installCertArtifacts(t, b, keepHost)

	orphanConf := layout.AvailablePath(orphanHost)
	keepConf := layout.AvailablePath(keepHost)
	for _, p := range []string{orphanConf, keepConf} {
		if err := os.WriteFile(p, []byte(proxy.StampManagedArtifact("<VirtualHost/>\n")), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	n, err := b.Prune(context.Background(), []proxy.Target{{Kind: proxy.TargetKindFile, Path: keepConf}})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("Prune removed %d, want 1", n)
	}
	assertGone(t, orphanArts)
	for _, p := range keepArts {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("kept host cert artifact %q was wrongly removed: %v", p, err)
		}
	}
}
