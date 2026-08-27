package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func testDB(t *testing.T) *db.DB {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func scrape(t *testing.T, h http.Handler, token string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(body)
}

func TestHandler_authAndContent(t *testing.T) {
	d := testDB(t)
	h := Handler(d)

	// No admin key generated → every scrape is 401 (never default-open).
	if code, _ := scrape(t, h, "np_ak_whatever"); code != http.StatusUnauthorized {
		t.Fatalf("no stored key: status = %d, want 401", code)
	}

	key := "np_ak_" + "metricstest"
	if err := d.SetSetting("admin_api_key", auth.HashToken(key)); err != nil {
		t.Fatal(err)
	}
	if code, _ := scrape(t, h, ""); code != http.StatusUnauthorized {
		t.Fatalf("missing bearer: want 401")
	}
	if code, _ := scrape(t, h, "np_ak_wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401")
	}

	// Seed one agent, one domain, one cert, one backoff hold.
	if err := d.CreateAgent(&models.Agent{ID: "a1", Name: "a1", FQDN: "a1.example.com", Status: models.AgentStatusAdopted}); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := d.UpsertCertificate(&models.Certificate{ID: "c1", Host: "app.example.com", Names: []string{"app.example.com"}, CertPEM: "C", KeyPEM: "K", ExpiresAt: time.Now().Add(48 * time.Hour)}); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	if err := d.UpsertCertBackoff(&db.CertBackoff{Host: "held.example.com", Attempts: 1, NextAttemptAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("UpsertCertBackoff: %v", err)
	}

	code, body := scrape(t, h, key)
	if code != http.StatusOK {
		t.Fatalf("valid key: status = %d, want 200\n%s", code, body)
	}
	for _, want := range []string{
		`nurproxy_agents_total{status="adopted"} 1`,
		`nurproxy_certificate_expiry_seconds{host="app.example.com"}`,
		`nurproxy_certificate_backoff{host="held.example.com"} 1`,
		`nurproxy_metrics_scrape_errors 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output missing %q\n%s", want, body)
		}
	}
}
