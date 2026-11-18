//go:build sandbox

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Real-proxy validation for the sandbox. The dry stack renders real artifacts
// (caddygen, nginxgen) but simulates the proxy, so a config that renders but the
// real proxy rejects would pass. When a real binary is available these helpers
// feed the rendered artifacts through it and fail the test on rejection; when
// none is, they log and skip just that check.
//
// Binary lookup, per proxy: the NP_SANDBOX_<PROXY> env var (a path), then PATH.
// With NP_SANDBOX_DOCKER=1, nginx runs from the image the nginxparse
// integration test uses (docker, no network) instead of a local binary.

// sandboxNginxImage matches the nginx image of the nginxparse integration test.
const sandboxNginxImage = "nginx:1.29-alpine"

// lookupProxyBinary returns the binary named by env, or the first of names on
// PATH, or "" when there is none.
func lookupProxyBinary(env string, names ...string) string {
	if p := os.Getenv(env); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// sandboxCaddy returns the real caddy binary for the sandbox, or "".
func sandboxCaddy() string { return lookupProxyBinary("NP_SANDBOX_CADDY", "caddy") }

func dockerOptIn() bool {
	if os.Getenv("NP_SANDBOX_DOCKER") != "1" {
		return false
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

// mockCaddyConfig is the shape the agent's in-memory Caddy client reports on
// GET /caddy/config: srv0 as "server", each route under "route:<id>", plus the
// TLS strategy pieces the client would have PUT into a real Caddy.
type mockCaddyConfig map[string]json.RawMessage

// fullCaddyConfig assembles the complete Caddy JSON config a real built-in
// agent would have built through the admin API from the mock client's record.
func fullCaddyConfig(mock mockCaddyConfig) ([]byte, int, error) {
	var server struct {
		Listen []string `json:"listen"`
	}
	if raw := mock["server"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &server); err != nil {
			return nil, 0, fmt.Errorf("mock server: %w", err)
		}
	}
	if len(server.Listen) == 0 {
		server.Listen = []string{":443", ":80"}
	}
	var keys []string
	for k := range mock {
		if strings.HasPrefix(k, "route:") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	routes := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		routes = append(routes, mock[k])
	}
	srv0 := map[string]any{"listen": server.Listen, "routes": routes}
	if raw := mock["automatic_https"]; isJSONValue(raw) {
		srv0["automatic_https"] = raw
	}
	if raw := mock["tls_connection_policies"]; isJSONValue(raw) {
		srv0["tls_connection_policies"] = raw
	}
	apps := map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": srv0}}}
	if raw := mock["tls_load_files"]; isJSONValue(raw) {
		apps["tls"] = map[string]any{"certificates": map[string]any{"load_files": raw}}
	}
	out, err := json.MarshalIndent(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps":  apps,
	}, "", "  ")
	return out, len(routes), err
}

func isJSONValue(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}

// caddyValidate runs `caddy validate` on a JSON config. Caddy's state dirs are
// pointed into a temp dir so validation never touches the user's real ones.
func caddyValidate(t *testing.T, caddyBin string, config []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy.json")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatalf("write caddy config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, caddyBin, "validate", "--config", path)
	cmd.Env = append(os.Environ(), caddyStateEnv(dir)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real caddy rejected the config the dry agent rendered: %v\n%s\n--- config ---\n%s", err, out, config)
	}
}

// caddyStateEnv points Caddy's data, config and home dirs below dir.
func caddyStateEnv(dir string) []string {
	return []string{
		"HOME=" + dir,
		"XDG_DATA_HOME=" + filepath.Join(dir, "data"),
		"XDG_CONFIG_HOME=" + filepath.Join(dir, "config"),
	}
}

// validateDryCaddyAgent fetches the in-memory Caddy config of a dry built-in
// agent and runs it through a real caddy, if one is available.
func validateDryCaddyAgent(t *testing.T, agentAPIPort int, agentDataDir string, wantRoutes int) {
	t.Helper()
	caddyBin := sandboxCaddy()
	if caddyBin == "" {
		t.Log("real-proxy validation: caddy not found (set NP_SANDBOX_CADDY or put caddy on PATH); skipped")
		return
	}
	token, err := os.ReadFile(filepath.Join(agentDataDir, "token"))
	if err != nil {
		t.Fatalf("read agent token: %v", err)
	}
	var mock mockCaddyConfig
	var routes int
	var config []byte
	waitFor(t, 30*time.Second, func() bool {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/caddy/config", agentAPIPort), nil)
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		mock = nil
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&mock) != nil {
			return false
		}
		config, routes, err = fullCaddyConfig(mock)
		return err == nil && routes >= wantRoutes && isJSONValue(mock["tls_load_files"])
	})
	caddyValidate(t, caddyBin, config)
	t.Logf("real-proxy validation: caddy (%s) accepted %d rendered route(s) plus the TLS strategy", caddyBin, routes)
}

// nginxTestConf is a main config that includes only the managed vhosts and
// keeps every writable path inside prefix, so `nginx -t` runs unprivileged.
const nginxTestConf = `pid %[1]s/nginx.pid;
error_log %[1]s/error.log;
events {}
http {
    access_log %[1]s/access.log;
    client_body_temp_path %[1]s/client_body;
    proxy_temp_path %[1]s/proxy;
    fastcgi_temp_path %[1]s/fastcgi;
    uwsgi_temp_path %[1]s/uwsgi;
    scgi_temp_path %[1]s/scgi;
    include %[2]s/nurproxy-*.conf;
}
`

// privilegedListen matches the port of a `listen` directive below 1024.
var privilegedListen = regexp.MustCompile(`(?m)^(\s*listen\s+(?:\S*:)?)([1-9]\d{0,2})\b`)

// unprivilegedCopies copies the managed vhosts of confDir into dir with every
// listen port below 1024 moved to a free high port. `nginx -t` binds the
// listen sockets, which an unprivileged user cannot do on :80/:443 in the host
// network namespace; nothing else in the files changes.
func unprivilegedCopies(t *testing.T, confDir, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(confDir, "nurproxy-*.conf"))
	mapped := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read vhost: %v", err)
		}
		out := privilegedListen.ReplaceAllStringFunc(string(b), func(m string) string {
			sub := privilegedListen.FindStringSubmatch(m)
			if _, ok := mapped[sub[2]]; !ok {
				mapped[sub[2]] = strconv.Itoa(freePort(t))
			}
			return sub[1] + mapped[sub[2]]
		})
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), []byte(out), 0o644); err != nil {
			t.Fatalf("write vhost copy: %v", err)
		}
	}
}

// validateNginxVhosts runs `nginx -t` over the managed vhosts in confDir with
// a real nginx: the integration-test image when NP_SANDBOX_DOCKER=1 (its own
// network namespace lets it bind :80/:443 unprivileged, so the files are
// checked unchanged), else a local binary (as non-root on copies whose
// privileged listen ports are moved, see unprivilegedCopies). mounts are host
// dirs the vhosts reference (the agent's cert store), bind-mounted read-only
// at the same path for docker.
func validateNginxVhosts(t *testing.T, confDir string, mounts ...string) {
	t.Helper()
	prefix := t.TempDir()
	conf := filepath.Join(prefix, "nginx.conf")
	writeConf := func(vhostDir string) {
		if err := os.WriteFile(conf, []byte(fmt.Sprintf(nginxTestConf, prefix, vhostDir)), 0o644); err != nil {
			t.Fatalf("write nginx test conf: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	var via string
	if dockerOptIn() {
		writeConf(confDir)
		// Run as the invoking user so the files need no extra permissions.
		args := []string{"run", "--rm", "--network", "none", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"-v", prefix + ":" + prefix, "-v", confDir + ":" + confDir + ":ro"}
		for _, m := range mounts {
			args = append(args, "-v", m+":"+m+":ro")
		}
		args = append(args, sandboxNginxImage, "nginx", "-t", "-p", prefix+"/", "-e", filepath.Join(prefix, "error.log"), "-c", conf)
		cmd = exec.CommandContext(ctx, "docker", args...)
		via = "docker " + sandboxNginxImage
	} else if bin := lookupProxyBinary("NP_SANDBOX_NGINX", "nginx"); bin != "" {
		vhostDir := confDir
		via = bin
		if os.Geteuid() != 0 {
			vhostDir = filepath.Join(prefix, "vhosts")
			unprivilegedCopies(t, confDir, vhostDir)
			via += ", listen ports < 1024 moved"
		}
		writeConf(vhostDir)
		cmd = exec.CommandContext(ctx, bin, "-t", "-p", prefix+"/", "-e", filepath.Join(prefix, "error.log"), "-c", conf)
	} else {
		t.Log("real-proxy validation: nginx not found (set NP_SANDBOX_NGINX, put nginx on PATH, or NP_SANDBOX_DOCKER=1); skipped")
		return
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var vhosts bytes.Buffer
		files, _ := filepath.Glob(filepath.Join(confDir, "nurproxy-*.conf"))
		for _, f := range files {
			b, _ := os.ReadFile(f)
			fmt.Fprintf(&vhosts, "--- %s ---\n%s\n", f, b)
		}
		t.Fatalf("real nginx (%s) rejected the rendered vhosts: %v\n%s\n%s", via, err, out, vhosts.String())
	}
	files, _ := filepath.Glob(filepath.Join(confDir, "nurproxy-*.conf"))
	t.Logf("real-proxy validation: nginx (%s) accepted %d rendered vhost(s)", via, len(files))
}
