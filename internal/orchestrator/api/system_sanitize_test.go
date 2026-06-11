package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestHealth_sanitizesDBErrorForUnauthCaller verifies that the public /health
// response never reflects the raw database error string to unauthenticated
// callers. It must report a generic "database unavailable" instead of leaking
// driver/path internals.
func TestHealth_sanitizesDBErrorForUnauthCaller(t *testing.T) {
	srv, database := testServer(t)
	database.Close() // force s.db.Ping to fail

	w := doRequest(t, srv.Handler(), "GET", "/api/v1/health", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when DB is down", w.Code)
	}

	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "degraded" {
		t.Errorf("status = %q, want degraded", body.Status)
	}

	got := body.Checks["database"]
	if got != "database unavailable" {
		t.Errorf("checks.database = %q, want %q", got, "database unavailable")
	}
	// Guard against regression to the old "error: <raw>" leak.
	if strings.HasPrefix(got, "error:") || strings.Contains(got, "sql") || strings.Contains(got, "closed") {
		t.Errorf("checks.database leaks raw DB error: %q", got)
	}
}
