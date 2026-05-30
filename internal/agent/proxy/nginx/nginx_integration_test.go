//go:build integration

// Integration tests for the nginx backend against a REAL nginx binary running in
// Docker (nginx:alpine), per the testing strategy in EXTERNAL_PROXIES_DESIGN.md
// §14 and docs/ENGINEERING.md. They are guarded by the `integration` build tag
// and run with:
//
//	go test -tags integration ./...
//
// Unlike the pure unit tests (which inject a fake Runner), these exercise the
// whole atomic apply dance against `nginx -t` / `nginx -s reload` as executed by
// the real binary inside a container. The Backend writes config files into a host
// temp dir that is bind-mounted into the container at /etc/nginx/sites-available
// and /etc/nginx/sites-enabled; a docker-exec Runner runs the privileged commands
// inside the container. This validates the host-facing behavior the unit tests
// cannot: a genuine nginx accepting (or rejecting) what nginxgen renders, the
// symlink activation nginx actually includes, a live reload, and real error
// attribution parsed from real nginx -t output.
//
// If Docker is unavailable, every test in this file is skipped (t.Skip) so the
// suite still passes on hosts without a container runtime — the pure renderer and
// orchestration unit tests cover the no-host path regardless.
package nginx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// nginxImage is the real nginx the integration tests validate against (§14).
const nginxImage = "nginx:alpine"

// mainNginxConfTemplate is a minimal main config that includes the host
// sites-enabled directory (where the Backend symlinks activated vhosts). The %s
// is the sites-enabled path. CRUCIAL: the host dirs are bind-mounted at the SAME
// absolute path inside the container, so the absolute symlink targets the Backend
// writes (host sites-available paths) resolve identically inside nginx — a host
// path mounted elsewhere would leave the symlink dangling and nginx -t would fail
// to open the included file. The image's default nginx.conf is overridden so the
// container validates exactly the files the Backend manages.
const mainNginxConfTemplate = `
events {}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    access_log    /var/log/nginx/access.log;
    include       /etc/nginx/conf.d/*.conf;
    include       %s/*;
}
`

// dockerAvailable reports whether a usable Docker daemon is reachable. When it is
// not, integration tests skip rather than fail, so the suite is green on hosts
// without a container runtime.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

// dockerExecRunner implements the Backend's Runner against a running container:
// it runs `nginx -t` / `nginx -s reload` via `docker exec`, so the real binary
// validates and reloads the bind-mounted files the Backend wrote on the host.
type dockerExecRunner struct {
	container string
}

func (r *dockerExecRunner) Test(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "exec", r.container, "nginx", "-t").CombinedOutput()
	return string(out), err
}

func (r *dockerExecRunner) Reload(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "docker", "exec", r.container, "nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return &execReloadError{output: string(out), err: err}
	}
	return nil
}

// execReloadError carries the docker-exec reload output for assertions.
type execReloadError struct {
	output string
	err    error
}

func (e *execReloadError) Error() string { return e.err.Error() + ": " + strings.TrimSpace(e.output) }
func (e *execReloadError) Unwrap() error { return e.err }

// nginxFixture is a running nginx container with its sites-available /
// sites-enabled dirs bind-mounted from host temp dirs, plus a Backend wired to
// those host dirs and a docker-exec Runner. Cleanup stops the container.
type nginxFixture struct {
	backend   *Backend
	layout    Layout
	container string
	hostAvail string
}

// startNginx builds the fixture: it creates host temp dirs, writes a main config
// that includes sites-enabled, starts an nginx:alpine container with everything
// bind-mounted, waits for nginx to be ready, and returns a Backend rooted at the
// host sites-available dir using a docker-exec Runner. The container is removed
// via t.Cleanup.
func startNginx(t *testing.T) *nginxFixture {
	t.Helper()

	root := t.TempDir()
	hostAvail := filepath.Join(root, "sites-available")
	hostEnabled := filepath.Join(root, "sites-enabled")
	for _, d := range []string{hostAvail, hostEnabled} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	confPath := filepath.Join(root, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(fmt.Sprintf(mainNginxConfTemplate, hostEnabled)), 0o644); err != nil {
		t.Fatalf("writing main nginx.conf: %v", err)
	}

	name := "nurproxy-nginx-it-" + sanitizeName(t.Name())
	// Best-effort remove any leftover container from a previous aborted run.
	_ = exec.Command("docker", "rm", "-f", name).Run()

	runCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// Mount the host dirs at their SAME absolute paths inside the container so the
	// absolute symlink targets the Backend writes (host sites-available paths)
	// resolve identically inside nginx.
	args := []string{
		"run", "-d", "--rm", "--name", name,
		"-v", confPath + ":/etc/nginx/nginx.conf:ro",
		"-v", hostAvail + ":" + hostAvail,
		"-v", hostEnabled + ":" + hostEnabled,
		nginxImage,
	}
	var startOut bytes.Buffer
	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.Stdout = &startOut
	cmd.Stderr = &startOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", nginxImage, err, startOut.String())
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	waitNginxReady(t, name)

	b := New(proxy.Config{Type: "nginx", ConfigDir: hostAvail})
	b.WithRunner(&dockerExecRunner{container: name})

	return &nginxFixture{
		backend:   b,
		layout:    b.layout,
		container: name,
		hostAvail: hostAvail,
	}
}

// waitNginxReady polls `nginx -t` inside the container until it passes (nginx has
// started and the base config is valid) or a deadline elapses. It avoids fixed
// sleeps per the deterministic-test convention.
func waitNginxReady(t *testing.T, container string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "exec", container, "nginx", "-t").CombinedOutput()
		cancel()
		last = string(out)
		if err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nginx in container %s never became ready; last nginx -t output:\n%s", container, last)
}

// sanitizeName turns a test name into a docker-safe container name suffix.
func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "-", " ", "-", "_", "-")
	return strings.ToLower(r.Replace(s))
}

// renderRoute renders a structured route through the Backend (the same path Apply
// callers use), returning the Artifact the integration test then applies.
func renderRoute(t *testing.T, b *Backend, route proxymodel.Route) proxy.Artifact {
	t.Helper()
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render(%q): %v", route.Host, err)
	}
	return art
}

// sampleRoute is a minimal valid reverse-proxy route a real nginx accepts.
func sampleRoute(host string) proxymodel.Route {
	return proxymodel.Route{
		Host: host,
		Upstream: proxymodel.Upstream{
			Addr:   "127.0.0.1",
			Port:   8080,
			Scheme: proxymodel.SchemeHTTP,
		},
	}
}

// TestIntegration_Apply_atomicWrite_realNginx verifies that Apply against a real
// nginx writes the rendered file, creates the sites-enabled symlink nginx
// actually includes, passes the real nginx -t, reloads, and removes the temp.
func TestIntegration_Apply_atomicWrite_realNginx(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-nginx integration test")
	}
	f := startNginx(t)

	host := "app.example.com"
	art := renderRoute(t, f.backend, sampleRoute(host))

	if err := f.backend.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply against real nginx: %v", err)
	}

	// The rendered file is on disk at the sites-available path with our content.
	got, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied file: %v", err)
	}
	if string(got) != art.Content {
		t.Errorf("applied content mismatch:\n got %q\nwant %q", got, art.Content)
	}
	// The sites-enabled symlink nginx includes is present.
	if !symlinkPresent(f.layout.EnabledPath(host)) {
		t.Errorf("expected sites-enabled symlink for %q", host)
	}
	// The temp file is gone (committed).
	if _, err := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(err) {
		t.Errorf("temp file should be removed after commit, stat err = %v", err)
	}
	// The live config is valid as seen by the real nginx.
	if err := f.backend.Validate(context.Background()); err != nil {
		t.Errorf("Validate against real nginx after apply: %v", err)
	}
}

// TestIntegration_Apply_symlinkEnable_includedByNginx asserts that the activated
// vhost is part of the config the real nginx validates: it appears in the parsed
// dump (`nginx -T`), proving the sites-enabled symlink is genuinely included.
func TestIntegration_Apply_symlinkEnable_includedByNginx(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-nginx integration test")
	}
	f := startNginx(t)

	host := "enabled.example.com"
	art := renderRoute(t, f.backend, sampleRoute(host))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", f.container, "nginx", "-T").CombinedOutput()
	if err != nil {
		t.Fatalf("nginx -T: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), host) {
		t.Errorf("activated vhost %q not found in nginx -T dump; symlink not included.\n%s", host, out)
	}
}

// TestIntegration_Apply_badConfig_rollsBack verifies the rollback path against a
// real nginx: a raw route with an invalid directive trips real nginx -t, Apply
// returns an attributed error, and the proxy is left serving exactly its prior
// state (the bad file removed, no dangling symlink, temp cleaned up).
func TestIntegration_Apply_badConfig_rollsBack(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-nginx integration test")
	}
	f := startNginx(t)

	// First apply a good vhost so there is prior serving state to preserve.
	goodHost := "good.example.com"
	good := renderRoute(t, f.backend, sampleRoute(goodHost))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{good}); err != nil {
		t.Fatalf("apply good vhost: %v", err)
	}
	goodBefore, err := os.ReadFile(good.Target.Path)
	if err != nil {
		t.Fatalf("reading good vhost: %v", err)
	}

	// Now apply a syntactically invalid vhost via the raw escape hatch.
	badHost := "bad.example.com"
	badRoute := proxymodel.Route{
		Host: badHost,
		Raw: proxymodel.RawConfig{
			// The nginx renderer's raw escape hatch recognizes the literal "nginx"
			// backend tag (nginxgen.backendNginx).
			Backend: "nginx",
			Content: "server {\n    listen 80;\n    server_name bad.example.com;\n    not_a_real_directive on;\n}\n",
		},
	}
	bad := renderRoute(t, f.backend, badRoute)

	err = f.backend.Apply(context.Background(), []proxy.Artifact{bad})
	if err == nil {
		t.Fatal("expected Apply to fail on invalid config validated by real nginx")
	}

	// The bad new file was removed on rollback (it did not exist before).
	if _, statErr := os.Stat(bad.Target.Path); !os.IsNotExist(statErr) {
		t.Errorf("bad file should be removed on rollback, stat err = %v", statErr)
	}
	// No dangling sites-enabled symlink for the bad host.
	if symlinkPresent(f.layout.EnabledPath(badHost)) {
		t.Errorf("symlink for bad host should not survive rollback")
	}
	// Temp cleaned up.
	if _, statErr := os.Stat(bad.Target.Path + tempSuffix); !os.IsNotExist(statErr) {
		t.Errorf("temp file should be removed on rollback, stat err = %v", statErr)
	}
	// The previously-good vhost is untouched and the live config is still valid.
	goodAfter, err := os.ReadFile(good.Target.Path)
	if err != nil {
		t.Fatalf("good vhost gone after failed apply: %v", err)
	}
	if !bytes.Equal(goodBefore, goodAfter) {
		t.Errorf("prior good vhost content changed by a failed apply")
	}
	if err := f.backend.Validate(context.Background()); err != nil {
		t.Errorf("live config invalid after rollback; proxy left non-serving: %v", err)
	}
}

// TestIntegration_Apply_reload_realNginx asserts a second apply on top of an
// existing live config reloads the real nginx successfully (no error), exercising
// the nginx -s reload path against the running master process.
func TestIntegration_Apply_reload_realNginx(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-nginx integration test")
	}
	f := startNginx(t)

	first := renderRoute(t, f.backend, sampleRoute("one.example.com"))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{first}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// A second apply forces a live reload of the already-running nginx.
	second := renderRoute(t, f.backend, sampleRoute("two.example.com"))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{second}); err != nil {
		t.Fatalf("second apply (reload of running nginx): %v", err)
	}
	if !symlinkPresent(f.layout.EnabledPath("two.example.com")) {
		t.Errorf("second vhost not activated after reload")
	}
}

// TestIntegration_errorAttribution_existingConfig verifies real error
// attribution: a pre-existing operator vhost with a broken directive trips our
// apply's nginx -t, and AttributeNginxTestError (fed real nginx output) blames
// the operator's file, not ours (§10).
func TestIntegration_errorAttribution_existingConfig(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-nginx integration test")
	}
	f := startNginx(t)

	// Plant a broken operator-authored vhost directly in sites-available +
	// sites-enabled (not via the Backend) so it is part of the live config but is
	// NOT one of our managed files.
	operatorFile := filepath.Join(f.hostAvail, "operator-site")
	operatorContent := "server {\n    listen 80;\n    server_name operator.example.com;\n    bogus_directive yes;\n}\n"
	if err := os.WriteFile(operatorFile, []byte(operatorContent), 0o644); err != nil {
		t.Fatalf("writing operator vhost: %v", err)
	}
	if err := os.Symlink(operatorFile, filepath.Join(f.layout.Enabled, "operator-site")); err != nil {
		t.Fatalf("symlinking operator vhost: %v", err)
	}

	// Now apply a perfectly valid managed vhost; nginx -t validates the WHOLE
	// config, so the operator's error trips our apply.
	host := "mine.example.com"
	art := renderRoute(t, f.backend, sampleRoute(host))
	err := f.backend.Apply(context.Background(), []proxy.Artifact{art})
	if err == nil {
		t.Fatal("expected Apply to fail because the operator's existing config is broken")
	}

	var ce *commandError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *commandError carrying attribution", err)
	}
	if !ce.Attribution.Located {
		t.Fatalf("attribution should be located from real nginx -t output; raw:\n%s", ce.Attribution.Raw)
	}
	if ce.Attribution.Ours {
		t.Errorf("attribution blamed our file, but the fault is the operator's existing config; blamed %q\nraw:\n%s",
			ce.Attribution.File, ce.Attribution.Raw)
	}
	if !strings.Contains(filepath.Base(ce.Attribution.File), "operator-site") {
		t.Errorf("expected blame on operator-site, got %q", ce.Attribution.File)
	}
}
