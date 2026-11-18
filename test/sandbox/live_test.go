//go:build sandbox

package sandbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// upstreamMarker is what the fake upstream (test/sandbox/fakeupstream) starts
// every response body with.
const upstreamMarker = "nurproxy-sandbox-upstream"

// TestSandboxLiveTraffic is the live profile of the sandbox (#96): the
// orchestrator is still dry (no external DNS or ACME), but the agent runs a REAL
// Caddy on unprivileged loopback ports and proxies to a fake upstream, so actual
// HTTP and TLS flow end to end through the config NurProxy rendered. It skips
// when no caddy binary is available (NP_SANDBOX_CADDY or PATH).
func TestSandboxLiveTraffic(t *testing.T) {
	caddyBin := sandboxCaddy()
	if caddyBin == "" {
		t.Skip("live sandbox needs a real caddy binary (set NP_SANDBOX_CADDY or put caddy on PATH)")
	}
	bin := buildBinaries(t, repoRoot(t))
	dataRoot := t.TempDir()

	// The agent finds Caddy as "caddy" on PATH, whatever NP_SANDBOX_CADDY names.
	caddyDir := filepath.Join(dataRoot, "caddy-bin")
	if err := os.MkdirAll(caddyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(caddyBin, filepath.Join(caddyDir, "caddy")); err != nil {
		t.Fatalf("link caddy: %v", err)
	}

	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	upstream := startProcess(t, bin.upstream, []string{"-listen", upstreamAddr, "-name", "live-app"})
	t.Cleanup(upstream.stop)
	waitFor(t, 10*time.Second, func() bool { return httpOK("http://" + upstreamAddr + "/") })

	stack := startDryOrchestrator(t, bin, dataRoot)

	httpPort, httpsPort, adminPort := freePort(t), freePort(t), freePort(t)
	agentDataDir := filepath.Join(dataRoot, "agent-live")
	caddyState := filepath.Join(dataRoot, "caddy-state")
	env := append([]string{"PATH=" + caddyDir + string(os.PathListSeparator) + os.Getenv("PATH")}, caddyStateEnv(caddyState)...)
	agent := startProcess(t, bin.agent, []string{
		"-orchestrator", stack.base,
		"-fqdn", "edge-live.sandbox.test",
		"-api-port", fmt.Sprintf("%d", freePort(t)),
		"-data-dir", agentDataDir,
		"-caddy-admin-port", fmt.Sprintf("%d", adminPort),
		"-caddy-http-port", fmt.Sprintf("%d", httpPort),
		"-caddy-https-port", fmt.Sprintf("%d", httpsPort),
		"-caddy-listen-host", "127.0.0.1",
	}, env...)
	// SIGTERM lets the agent stop its Caddy; the admin /stop is the backstop
	// so no Caddy outlives the test even if the agent died first.
	t.Cleanup(func() {
		agent.terminate(15 * time.Second)
		stopCaddy(adminPort)
	})
	t.Cleanup(func() {
		if t.Failed() || os.Getenv("NP_SANDBOX_LOGS") == "1" {
			t.Logf("agent log tail:\n%s", agent.logTail(6000))
		}
	})

	agentID := stack.adoptAgent(t, "edge-live.sandbox.test", "edge-live")
	var server struct {
		ID string `json:"id"`
	}
	host, port, _ := net.SplitHostPort(upstreamAddr)
	stack.api.post("/api/v1/agents/"+agentID+"/servers", map[string]string{"name": "live-app", "address": host}, &server)
	var domain struct {
		ID int `json:"id"`
	}
	stack.api.post("/api/v1/domains", map[string]any{
		"subdomain": "app", "zone_id": stack.zone.ID, "server_id": server.ID,
		"port": mustAtoi(t, port), "ssl_mode": "central",
		"proxy_config": map[string]any{"force_https": true},
	}, &domain)

	// The dry orchestrator issues a self-signed cert and pushes it to the
	// agent's cert store; the HTTPS client trusts exactly that certificate, so
	// a successful handshake proves Caddy serves it.
	const fqdn = "app.sandbox.test"
	var stored string
	waitFor(t, 90*time.Second, func() bool {
		stored = findFile(agentDataDir, fqdn+".crt")
		return stored != ""
	})
	storedPEM, err := os.ReadFile(stored)
	if err != nil {
		t.Fatalf("read installed cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(storedPEM) {
		t.Fatalf("installed cert %s is not PEM", stored)
	}
	httpsClient, peer := loopbackHTTPSClient(fmt.Sprintf("127.0.0.1:%d", httpsPort), fqdn, roots)
	httpClient := loopbackHTTPClient(fmt.Sprintf("127.0.0.1:%d", httpPort))

	// HTTPS through the real Caddy reaches the fake upstream.
	var body string
	var lastErr error
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		body, lastErr = get(httpsClient, fmt.Sprintf("https://%s:%d/hello?x=1", fqdn, httpsPort), nil)
		if lastErr == nil && strings.Contains(body, upstreamMarker) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !strings.Contains(body, upstreamMarker) {
		t.Fatalf("HTTPS request never reached the fake upstream through Caddy: last error %v, body %q", lastErr, body)
	}
	for _, want := range []string{"name=live-app", "host=" + fqdn, "path=/hello?x=1", "forwarded_proto=https"} {
		if !strings.Contains(body, want) {
			t.Errorf("upstream response %q lacks %q", body, want)
		}
	}

	// The TLS handshake presents the certificate the dry orchestrator issued
	// and pushed to the agent: same leaf as in the agent's cert store.
	leaf := peer()
	if leaf == nil {
		t.Fatal("no peer certificate captured")
	}
	if err := leaf.VerifyHostname(fqdn); err != nil {
		t.Errorf("served certificate does not cover %s: %v", fqdn, err)
	}
	if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != "NurProxy dry-run" {
		t.Errorf("served certificate is not the sandbox's self-signed one: subject %v", leaf.Subject)
	}
	if !sameLeaf(t, stored, leaf) {
		t.Errorf("served certificate differs from the one installed at %s", stored)
	}

	// Plain HTTP redirects to HTTPS (force_https).
	resp, err := httpClient.Get(fmt.Sprintf("http://%s:%d/hello?x=1", fqdn, httpPort))
	if err != nil {
		t.Fatalf("plain HTTP request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Fatalf("plain HTTP status = %d, want a redirect", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://"+fqdn+"/hello?x=1" {
		t.Errorf("redirect Location = %q, want https://%s/hello?x=1", loc, fqdn)
	}

	// A change made through the API reaches the running Caddy: the re-apply
	// replaces routes and TLS strategy on a live admin API, not a fresh one.
	stack.api.put(fmt.Sprintf("/api/v1/domains/%d", domain.ID), map[string]any{
		"proxy_config": map[string]any{
			"force_https":             true,
			"custom_response_headers": map[string]string{"X-Sandbox-Live": "yes"},
		},
	}, nil)
	var header string
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		h := http.Header{}
		if _, err := get(httpsClient, fmt.Sprintf("https://%s:%d/", fqdn, httpsPort), h); err == nil {
			if header = h.Get("X-Sandbox-Live"); header == "yes" {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if header != "yes" {
		t.Fatalf("response header from the updated domain never appeared (got %q)", header)
	}

	// A second domain added to a Caddy that already has a TLS strategy: its
	// certificate must be loaded too, which needs the re-apply to replace the
	// strategy rather than fail on keys that already exist.
	const fqdn2 = "app2.sandbox.test"
	stack.api.post("/api/v1/domains", map[string]any{
		"subdomain": "app2", "zone_id": stack.zone.ID, "server_id": server.ID,
		"port": mustAtoi(t, port), "ssl_mode": "central",
	}, nil)
	var stored2 string
	waitFor(t, 90*time.Second, func() bool {
		stored2 = findFile(agentDataDir, fqdn2+".crt")
		return stored2 != ""
	})
	pem2, err := os.ReadFile(stored2)
	if err != nil {
		t.Fatalf("read second cert: %v", err)
	}
	roots2 := x509.NewCertPool()
	roots2.AppendCertsFromPEM(pem2)
	httpsClient2, _ := loopbackHTTPSClient(fmt.Sprintf("127.0.0.1:%d", httpsPort), fqdn2, roots2)
	body, lastErr = "", nil
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		body, lastErr = get(httpsClient2, fmt.Sprintf("https://%s:%d/", fqdn2, httpsPort), nil)
		if lastErr == nil && strings.Contains(body, "host="+fqdn2) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !strings.Contains(body, "host="+fqdn2) {
		t.Fatalf("second domain never served with its own certificate: last error %v, body %q", lastErr, body)
	}

	t.Logf("live sandbox: real Caddy on 127.0.0.1:%d/%d served %s and %s via the fake upstream with the dry-issued certs; HTTP redirected; updates applied live", httpPort, httpsPort, fqdn, fqdn2)
}

// loopbackHTTPSClient returns a client that sends every request to addr with
// SNI serverName, trusts only roots, and records the leaf certificate of the
// last handshake.
func loopbackHTTPSClient(addr, serverName string, roots *x509.CertPool) (*http.Client, func() *x509.Certificate) {
	var leaf *x509.Certificate
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: serverName,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) > 0 {
					leaf = cs.PeerCertificates[0]
				}
				return nil
			},
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, func() *x509.Certificate { return leaf }
}

// loopbackHTTPClient returns a client that sends every request to addr and
// does not follow redirects.
func loopbackHTTPClient(addr string) *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
			DisableKeepAlives: true,
		},
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// get fetches url and returns the body of a 200 response; headers, when not
// nil, receives the response headers.
func get(cli *http.Client, url string, headers http.Header) (string, error) {
	resp, err := cli.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("status %d", resp.StatusCode)
	}
	for k, v := range resp.Header {
		if headers != nil {
			headers[k] = v
		}
	}
	return string(b), nil
}

// stopCaddy asks a Caddy admin API on adminPort to stop; a no-op when nothing
// listens there.
func stopCaddy(adminPort int) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/stop", adminPort), nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// findFile returns the first file named name below root, or "".
func findFile(root, name string) string {
	found := ""
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == name && found == "" {
			found = path
		}
		return nil
	})
	return found
}

// sameLeaf reports whether the first certificate in the PEM file at path is
// leaf.
func sameLeaf(t *testing.T, path string, leaf *x509.Certificate) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	return string(block.Bytes) == string(leaf.Raw)
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}
