package api

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// applyFQDNChange must clear BOTH the A-record id (DNSRecordID) and the
// AAAA-record id (DNSRecordID6) when the anchor moves, so a stale AAAA record
// doesn't leak at the old name after a rename.
func TestApplyFQDNChange_clearsBothRecordIDs(t *testing.T) {
	srv, _ := testServer(t)

	tests := []struct {
		name        string
		current     string
		newFQDN     string
		wantMoved   bool // true if the anchor actually changes
		recID, rec6 string
	}{
		{
			name:      "anchor moves clears both record ids",
			current:   "old.example.com",
			newFQDN:   "new.example.com",
			wantMoved: true,
			recID:     "a-rec-123",
			rec6:      "aaaa-rec-456",
		},
		{
			name:      "case-insensitive move still clears both",
			current:   "old.example.com",
			newFQDN:   "NEW2.example.com",
			wantMoved: true,
			recID:     "a-rec-123",
			rec6:      "aaaa-rec-456",
		},
		{
			name:      "no-op when fqdn unchanged leaves ids intact",
			current:   "same.example.com",
			newFQDN:   "same.example.com",
			wantMoved: false,
			recID:     "a-rec-123",
			rec6:      "aaaa-rec-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := &models.Agent{
				FQDN:         tt.current,
				DNSRecordID:  tt.recID,
				DNSRecordID6: tt.rec6,
			}
			if ferr := srv.applyFQDNChange(agent, tt.newFQDN); ferr != nil {
				t.Fatalf("applyFQDNChange returned error: %v", ferr)
			}
			if tt.wantMoved {
				if agent.DNSRecordID != "" {
					t.Errorf("DNSRecordID = %q, want cleared", agent.DNSRecordID)
				}
				if agent.DNSRecordID6 != "" {
					t.Errorf("DNSRecordID6 = %q, want cleared (AAAA record would leak)", agent.DNSRecordID6)
				}
			} else {
				if agent.DNSRecordID != tt.recID || agent.DNSRecordID6 != tt.rec6 {
					t.Errorf("no-op should leave ids intact: got A=%q AAAA=%q", agent.DNSRecordID, agent.DNSRecordID6)
				}
			}
		})
	}
}

// The register endpoint must reject a syntactically invalid FQDN at the
// boundary rather than persisting a bad anchor name.
func TestRegisterAgent_rejectsInvalidFQDN(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		wantCode int
	}{
		{"valid fqdn accepted", "edge1.example.com", http.StatusCreated},
		{"space rejected", "edge 1.example.com", http.StatusBadRequest},
		{"leading hyphen rejected", "-bad.example.com", http.StatusBadRequest},
		{"underscore rejected", "edge_1.example.com", http.StatusBadRequest},
		{"empty label rejected", "edge..example.com", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The limiter is package-scoped and keyed on the (shared) test IP, so
			// clear it per subtest to keep these cases independent of one another.
			registerLimiter.Reset("192.0.2.1")
			srv, _ := testServer(t)
			handler := srv.Handler()
			body := map[string]any{
				"id":    "agent-" + tt.name,
				"fqdn":  tt.fqdn,
				"token": "secret-token",
			}
			w := doRequest(t, handler, "POST", "/api/v1/agents/register", body)
			if w.Code != tt.wantCode {
				t.Fatalf("register fqdn=%q: got %d, want %d (%s)", tt.fqdn, w.Code, tt.wantCode, w.Body.String())
			}
		})
	}
}

// The register endpoint must rate-limit per IP: after the limiter's allowance is
// exhausted from one peer, further attempts get 429 with a Retry-After hint —
// even with otherwise valid, distinct payloads.
func TestRegisterAgent_rateLimitedPerIP(t *testing.T) {
	registerLimiter.Reset("192.0.2.1")
	srv, _ := testServer(t)
	handler := srv.Handler()

	// All httptest requests share the same RemoteAddr, so they key to one IP.
	// Send the limiter's full allowance of valid registrations.
	var last int
	for i := 0; i < 10; i++ {
		body := map[string]any{
			"id":    "agent-" + strconv.Itoa(i),
			"fqdn":  "edge" + strconv.Itoa(i) + ".example.com",
			"token": "tok-" + strconv.Itoa(i),
		}
		w := doRequest(t, handler, "POST", "/api/v1/agents/register", body)
		last = w.Code
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d locked out too early", i+1)
		}
	}
	if last != http.StatusCreated {
		t.Fatalf("10th allowed attempt: got %d, want 201", last)
	}

	// The next attempt is over the threshold → 429 with Retry-After.
	w := doRequest(t, handler, "POST", "/api/v1/agents/register", map[string]any{
		"id":    "agent-overflow",
		"fqdn":  "overflow.example.com",
		"token": "tok-overflow",
	})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after threshold: got %d, want 429 (%s)", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on lockout")
	}
}

// proxy_detection with an over-large variable-length slice is rejected before
// it can be persisted onto the agent row.
func TestRegisterAgent_rejectsOversizedProxyDetection(t *testing.T) {
	registerLimiter.Reset("192.0.2.1")
	srv, _ := testServer(t)
	handler := srv.Handler()

	tooMany := make([]string, maxProxyDetectionEntries+1)
	for i := range tooMany {
		tooMany[i] = "/var/log/x"
	}
	body := map[string]any{
		"id":              "agent-fat",
		"fqdn":            "fat.example.com",
		"token":           "tok",
		"proxy_detection": map[string]any{"log_paths": tooMany},
	}
	w := doRequest(t, handler, "POST", "/api/v1/agents/register", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized proxy_detection: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}
