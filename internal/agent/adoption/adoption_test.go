package adoption

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// New must generate a token + agent id on first run and then REUSE the persisted
// values on subsequent runs (so an agent keeps its identity across restarts).
func TestManager_New_generatesAndPersistsIdentity(t *testing.T) {
	dir := t.TempDir()

	m1, err := New("http://orch:8080", "edge1.example.com", dir, 8780)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m1.Token() == "" || m1.AgentID() == "" {
		t.Fatal("expected a generated token and agent id")
	}

	// Both must be persisted to disk...
	for _, name := range []string{"token", "agent-id"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected %s to be written: %v", name, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s mode = %v, want 0600 (identity is sensitive)", name, info.Mode().Perm())
		}
	}

	// ...and reused by a second Manager over the same data dir.
	m2, err := New("http://orch:8080", "edge1.example.com", dir, 8780)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	if m2.Token() != m1.Token() {
		t.Error("token not persisted: second New generated a different token")
	}
	if m2.AgentID() != m1.AgentID() {
		t.Error("agent id not persisted: second New generated a different id")
	}
}

// checkStatus is the core of WaitForAdoption: it reads the agent's status from
// the orchestrator and returns it, erroring on a non-200.
func TestManager_checkStatus(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"status":"adopted"}`))
	}))
	defer server.Close()

	m, err := New(server.URL, "edge1.example.com", t.TempDir(), 8780)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	status, err := m.checkStatus(context.Background(), server.URL+"/api/v1/agents/x/status")
	if err != nil {
		t.Fatalf("checkStatus: %v", err)
	}
	if status != "adopted" {
		t.Errorf("status = %q, want adopted", status)
	}
	if gotAuth != "Bearer "+m.Token() {
		t.Errorf("checkStatus must authenticate with the agent token, got %q", gotAuth)
	}
}

func TestManager_checkStatus_non200_errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	m, err := New(server.URL, "edge1.example.com", t.TempDir(), 8780)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.checkStatus(context.Background(), server.URL+"/x"); err == nil {
		t.Fatal("expected an error on a non-200 status response")
	}
}

// isValidPublicIPv4 must accept only routable public IPv4 addresses, rejecting
// malformed input, the wrong family (IPv6), and non-public ranges — otherwise a
// rogue/garbage detection response would become A-record content.
func TestIsValidPublicIPv4(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"public v4", "203.0.113.7", true},
		{"another public v4", "8.8.8.8", true},
		{"empty", "", false},
		{"garbage", "not-an-ip", false},
		{"html error page", "<html>error</html>", false},
		{"trailing junk", "203.0.113.7 extra", false},
		{"ipv6 wrong family", "2606:4700:4700::1111", false},
		{"ipv4-mapped ipv6", "::ffff:203.0.113.7", false},
		{"private 10/8", "10.0.0.5", false},
		{"private 192.168/16", "192.168.1.1", false},
		{"private 172.16/12", "172.16.0.1", false},
		{"loopback", "127.0.0.1", false},
		{"link-local", "169.254.1.1", false},
		{"unspecified", "0.0.0.0", false},
		{"multicast", "224.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidPublicIPv4(tt.in); got != tt.want {
				t.Errorf("isValidPublicIPv4(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// detectPublicIPSimple must skip a service that returns a non-public or malformed
// address and accept the first valid public IPv4. Without validation, the garbage
// body from the first stub would be returned verbatim.
func TestDetectPublicIPSimple_validatesSource(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{"valid public", "203.0.113.7", "203.0.113.7", false},
		{"private rejected", "192.168.0.10", "", true},
		{"garbage rejected", "<html>oops</html>", "", true},
		{"ipv6 rejected", "2606:4700:4700::1111", "", true},
	}

	orig := detectPublicIPv4Services
	defer func() { detectPublicIPv4Services = orig }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			detectPublicIPv4Services = []string{server.URL}

			got, err := detectPublicIPSimple(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for body %q, got %q", tt.body, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("detectPublicIPSimple() = %q, want %q", got, tt.want)
			}
		})
	}
}

// detectPublicIPSimple must fall through a bad source to a later good one rather
// than returning the bad body.
func TestDetectPublicIPSimple_fallsThroughToValid(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("garbage"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.7"))
	}))
	defer good.Close()

	orig := detectPublicIPv4Services
	defer func() { detectPublicIPv4Services = orig }()
	detectPublicIPv4Services = []string{bad.URL, good.URL}

	got, err := detectPublicIPSimple(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "203.0.113.7" {
		t.Errorf("detectPublicIPSimple() = %q, want 203.0.113.7", got)
	}
}
