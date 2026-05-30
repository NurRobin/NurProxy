//go:build integration

// Integration tests for the apache backend against a REAL Apache httpd binary
// running in Docker (httpd:alpine), per the testing strategy in
// EXTERNAL_PROXIES_DESIGN.md §14 and docs/ENGINEERING.md. They are guarded by the
// `integration` build tag and run with:
//
//	go test -tags integration ./...
//
// Unlike the pure unit tests (which inject a fake Runner), these exercise the
// whole atomic apply dance against `httpd -t` (configtest) / a graceful reload as
// executed by the real binary inside a container. The Backend writes config files
// into a host temp dir that is bind-mounted into the container; a docker-exec
// Runner runs the privileged commands inside the container. This validates the
// host-facing behavior the unit tests cannot: a genuine Apache accepting (or
// rejecting) what apachegen renders, real configtest output, and real error
// attribution.
//
// The image's stock httpd.conf is overridden with a minimal one that loads
// mod_proxy + the modules our rendered vhosts rely on and Includes the
// bind-mounted conf.d directory the Backend manages. We use the RHEL-style flat
// conf.d layout in-container (httpd:alpine is not Debian's a2ensite world); the
// Debian sites-enabled symlink path is covered by the unit tests.
//
// If Docker is unavailable, every test in this file is skipped (t.Skip) so the
// suite still passes on hosts without a container runtime — the pure renderer and
// orchestration unit tests cover the no-host path regardless.
package apache

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

// apacheImage is the real Apache the integration tests validate against (§14).
const apacheImage = "httpd:alpine"

// mainHTTPDConfTemplate is a minimal httpd.conf that loads the modules our
// rendered vhosts use (proxy, rewrite, headers, authn/authz, ssl, wstunnel) and
// Includes the bind-mounted conf.d the Backend writes to. The %s is the conf.d
// path. CRUCIAL: the host dir is bind-mounted at the SAME absolute path inside
// the container so file references resolve identically.
const mainHTTPDConfTemplate = `
ServerRoot /usr/local/apache2
Listen 80
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule log_config_module modules/mod_log_config.so
User daemon
Group daemon
ServerName localhost
ErrorLog /proc/self/fd/2
LogLevel warn
LogFormat "%%h %%l %%u %%t \"%%r\" %%>s %%b" common
CustomLog /proc/self/fd/1 common
IncludeOptional %s/*.conf
`

// dockerAvailable reports whether a usable Docker daemon is reachable. When it is
// not, integration tests skip rather than fail.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

// dockerExecRunner implements the Backend's Runner against a running container:
// it runs `httpd -t` (configtest) / a graceful reload via `docker exec`, so the
// real binary validates and reloads the bind-mounted files the Backend wrote.
type dockerExecRunner struct {
	container string
}

func (r *dockerExecRunner) Test(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "exec", r.container, "httpd", "-t").CombinedOutput()
	return string(out), err
}

func (r *dockerExecRunner) Reload(ctx context.Context) error {
	// httpd -k graceful re-reads config without dropping connections.
	out, err := exec.CommandContext(ctx, "docker", "exec", r.container, "httpd", "-k", "graceful").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// apacheFixture is a running httpd container with its conf.d dir bind-mounted
// from a host temp dir, plus a Backend wired to that host dir and a docker-exec
// Runner. Cleanup stops the container.
type apacheFixture struct {
	backend   *Backend
	layout    Layout
	container string
	hostConfD string
}

// startApache builds the fixture: it creates a host conf.d temp dir, writes a
// main httpd.conf that Includes it, starts an httpd:alpine container with
// everything bind-mounted, waits for httpd to be ready, and returns a Backend
// rooted at the host conf.d dir using a docker-exec Runner.
func startApache(t *testing.T) *apacheFixture {
	t.Helper()

	root := t.TempDir()
	hostConfD := filepath.Join(root, "conf.d")
	if err := os.MkdirAll(hostConfD, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", hostConfD, err)
	}
	confPath := filepath.Join(root, "httpd.conf")
	if err := os.WriteFile(confPath, []byte(fmt.Sprintf(mainHTTPDConfTemplate, hostConfD)), 0o644); err != nil {
		t.Fatalf("writing main httpd.conf: %v", err)
	}

	name := "nurproxy-apache-it-" + sanitizeName(t.Name())
	_ = exec.Command("docker", "rm", "-f", name).Run()

	runCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{
		"run", "-d", "--rm", "--name", name,
		"-v", confPath + ":/usr/local/apache2/conf/httpd.conf:ro",
		"-v", hostConfD + ":" + hostConfD,
		apacheImage,
	}
	var startOut bytes.Buffer
	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.Stdout = &startOut
	cmd.Stderr = &startOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", apacheImage, err, startOut.String())
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	waitApacheReady(t, name)

	b := New(proxy.Config{Type: "apache", ConfigDir: hostConfD})
	b.WithRunner(&dockerExecRunner{container: name})

	return &apacheFixture{
		backend:   b,
		layout:    b.layout,
		container: name,
		hostConfD: hostConfD,
	}
}

// waitApacheReady polls `httpd -t` inside the container until it passes or a
// deadline elapses, avoiding fixed sleeps.
func waitApacheReady(t *testing.T, container string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "exec", container, "httpd", "-t").CombinedOutput()
		cancel()
		last = string(out)
		if err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("apache in container %s never became ready; last httpd -t output:\n%s", container, last)
}

// sanitizeName turns a test name into a docker-safe container name suffix.
func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "-", " ", "-", "_", "-")
	return strings.ToLower(r.Replace(s))
}

// renderRoute renders a structured route through the Backend.
func renderRoute(t *testing.T, b *Backend, route proxymodel.Route) proxy.Artifact {
	t.Helper()
	art, err := b.Render(context.Background(), route)
	if err != nil {
		t.Fatalf("Render(%q): %v", route.Host, err)
	}
	return art
}

// sampleRoute is a minimal valid reverse-proxy route a real Apache accepts.
func sampleRoute(host string) proxymodel.Route {
	return proxymodel.Route{
		Host: host,
		Upstream: proxymodel.Upstream{
			Addr:   "127.0.0.1",
			Port:   8080,
			Scheme: proxymodel.SchemeHTTP,
		},
		TLS: proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyOff},
	}
}

// TestIntegration_Apply_atomicWrite_realApache verifies that Apply against a real
// Apache writes the rendered file into conf.d, passes the real httpd -t, reloads,
// and removes the temp.
func TestIntegration_Apply_atomicWrite_realApache(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-apache integration test")
	}
	f := startApache(t)

	host := "app.example.com"
	art := renderRoute(t, f.backend, sampleRoute(host))

	if err := f.backend.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply against real apache: %v", err)
	}

	got, err := os.ReadFile(art.Target.Path)
	if err != nil {
		t.Fatalf("reading applied file: %v", err)
	}
	if string(got) != art.Content {
		t.Errorf("applied content mismatch:\n got %q\nwant %q", got, art.Content)
	}
	if _, err := os.Stat(art.Target.Path + tempSuffix); !os.IsNotExist(err) {
		t.Errorf("temp file should be removed after commit, stat err = %v", err)
	}
	if err := f.backend.Validate(context.Background()); err != nil {
		t.Errorf("Validate against real apache after apply: %v", err)
	}
}

// TestIntegration_Apply_includedByApache asserts that the applied vhost is part
// of the config the real Apache validates: its ServerName appears in the dumped
// config (`httpd -S` lists vhosts), proving the conf.d file is genuinely
// included.
func TestIntegration_Apply_includedByApache(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-apache integration test")
	}
	f := startApache(t)

	host := "included.example.com"
	art := renderRoute(t, f.backend, sampleRoute(host))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{art}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// httpd -S dumps the vhost settings; -t -D DUMP_VHOSTS is the portable form.
	out, err := exec.CommandContext(ctx, "docker", "exec", f.container, "httpd", "-t", "-D", "DUMP_VHOSTS").CombinedOutput()
	if err != nil {
		t.Fatalf("httpd -S: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), host) {
		t.Errorf("applied vhost %q not found in httpd vhost dump; not included.\n%s", host, out)
	}
}

// TestIntegration_Apply_badConfig_rollsBack verifies the rollback path against a
// real Apache: a raw route with an invalid directive trips real httpd -t, Apply
// returns an attributed error, and the proxy is left serving its prior state.
func TestIntegration_Apply_badConfig_rollsBack(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-apache integration test")
	}
	f := startApache(t)

	goodHost := "good.example.com"
	good := renderRoute(t, f.backend, sampleRoute(goodHost))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{good}); err != nil {
		t.Fatalf("apply good vhost: %v", err)
	}
	goodBefore, err := os.ReadFile(good.Target.Path)
	if err != nil {
		t.Fatalf("reading good vhost: %v", err)
	}

	badHost := "bad.example.com"
	badRoute := proxymodel.Route{
		Host: badHost,
		Raw: proxymodel.RawConfig{
			Backend: "apache",
			Content: "<VirtualHost *:80>\n    ServerName bad.example.com\n    NotARealDirective on\n</VirtualHost>\n",
		},
	}
	bad := renderRoute(t, f.backend, badRoute)

	err = f.backend.Apply(context.Background(), []proxy.Artifact{bad})
	if err == nil {
		t.Fatal("expected Apply to fail on invalid config validated by real apache")
	}

	if _, statErr := os.Stat(bad.Target.Path); !os.IsNotExist(statErr) {
		t.Errorf("bad file should be removed on rollback, stat err = %v", statErr)
	}
	if _, statErr := os.Stat(bad.Target.Path + tempSuffix); !os.IsNotExist(statErr) {
		t.Errorf("temp file should be removed on rollback, stat err = %v", statErr)
	}
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

// TestIntegration_Apply_reload_realApache asserts a second apply on top of an
// existing live config reloads the real Apache successfully.
func TestIntegration_Apply_reload_realApache(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-apache integration test")
	}
	f := startApache(t)

	first := renderRoute(t, f.backend, sampleRoute("one.example.com"))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{first}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second := renderRoute(t, f.backend, sampleRoute("two.example.com"))
	if err := f.backend.Apply(context.Background(), []proxy.Artifact{second}); err != nil {
		t.Fatalf("second apply (reload of running apache): %v", err)
	}
	if _, err := os.Stat(second.Target.Path); err != nil {
		t.Errorf("second vhost file missing after reload: %v", err)
	}
}

// TestIntegration_errorAttribution_existingConfig verifies real error
// attribution: a pre-existing operator vhost with a broken directive trips our
// apply's httpd -t, and AttributeConfigtestError (fed real output) blames the
// operator's file, not ours (§10).
func TestIntegration_errorAttribution_existingConfig(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available; skipping real-apache integration test")
	}
	f := startApache(t)

	// Plant a broken operator-authored vhost directly in conf.d (not via the
	// Backend) so it is part of the live config but is NOT one of our managed files.
	operatorFile := filepath.Join(f.hostConfD, "operator.conf")
	operatorContent := "<VirtualHost *:80>\n    ServerName operator.example.com\n    BogusDirective yes\n</VirtualHost>\n"
	if err := os.WriteFile(operatorFile, []byte(operatorContent), 0o644); err != nil {
		t.Fatalf("writing operator vhost: %v", err)
	}

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
		t.Fatalf("attribution should be located from real httpd -t output; raw:\n%s", ce.Attribution.Raw)
	}
	if ce.Attribution.Ours {
		t.Errorf("attribution blamed our file, but the fault is the operator's existing config; blamed %q\nraw:\n%s",
			ce.Attribution.File, ce.Attribution.Raw)
	}
	if !strings.Contains(filepath.Base(ce.Attribution.File), "operator.conf") {
		t.Errorf("expected blame on operator.conf, got %q", ce.Attribution.File)
	}
}
