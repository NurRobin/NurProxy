package api

import (
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// makePreviewDomain wires a zone, server, agent (with the given proxy mode +
// detected kind), and a force-https central-TLS domain, returning the domain.
func makePreviewDomain(t *testing.T, srv *Server, proxyMode, detectedKind string) *models.Domain {
	t.Helper()
	d := srv.db
	if err := d.CreateProvider(&models.Provider{ID: "p1", Type: "mock", Name: "p1", Config: "{}"}); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if err := d.CreateZone(&models.Zone{ID: "z1", ProviderID: "p1", Name: "example.com"}); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	agent := &models.Agent{ID: "a1", Name: "a1", FQDN: "a1.example.com", DNSMode: models.DNSModeStatic, ProxyMode: proxyMode}
	if detectedKind != "" {
		agent.ProxyDetection = &models.ProxyDetection{Installed: true, Kind: detectedKind}
	}
	if err := d.CreateAgent(agent); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	// proxy_mode is owned by the heartbeat (CreateAgent defaults it to built-in),
	// so set it explicitly to model an agent running in existing mode.
	if proxyMode != "" {
		if err := d.UpdateAgentHealth("a1", "", "", false, proxyMode); err != nil {
			t.Fatalf("UpdateAgentHealth: %v", err)
		}
	}
	if err := d.CreateServer(&models.Server{ID: "s1", AgentID: "a1", Name: "backend", Address: "10.0.0.9"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	dom := &models.Domain{Subdomain: "app", ZoneID: "z1", ServerID: "s1", Port: 8080, ForceHTTPS: true, SSLMode: models.SSLModeAuto, Status: models.DomainStatusPending}
	if err := d.CreateDomain(dom); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	return dom
}

func TestRenderDomainPreview_nginxAgentRendersNginx(t *testing.T) {
	srv, _ := testServer(t)
	dom := makePreviewDomain(t, srv, "existing", "nginx")
	server, _ := srv.db.GetServer(dom.ServerID)

	backend, cfg, err := srv.renderDomainPreview(dom, server, "app.example.com")
	if err != nil {
		t.Fatalf("renderDomainPreview: %v", err)
	}
	if backend != "nginx" {
		t.Fatalf("backend = %q, want nginx", backend)
	}
	text, ok := cfg.(string)
	if !ok {
		t.Fatalf("nginx preview should be a string, got %T", cfg)
	}
	// A force-https central-TLS domain on nginx must show the 80->443 redirect,
	// the 443 ssl listener, and the cert path (the bug was a plaintext listen 80).
	for _, want := range []string{"listen 80", "return 301 https://", "listen 443 ssl", "ssl_certificate /var/lib/nurproxy/certs/app.example.com.crt"} {
		if !strings.Contains(text, want) {
			t.Errorf("nginx preview missing %q:\n%s", want, text)
		}
	}
}

func TestRenderDomainPreview_builtinAgentRendersCaddyJSON(t *testing.T) {
	srv, _ := testServer(t)
	dom := makePreviewDomain(t, srv, "built-in", "")
	server, _ := srv.db.GetServer(dom.ServerID)

	backend, cfg, err := srv.renderDomainPreview(dom, server, "app.example.com")
	if err != nil {
		t.Fatalf("renderDomainPreview: %v", err)
	}
	if backend != "caddy" {
		t.Fatalf("backend = %q, want caddy", backend)
	}
	if _, ok := cfg.(string); ok {
		t.Errorf("caddy preview should be a JSON object, got a string")
	}
}
