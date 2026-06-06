package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestHealth_okWhenDBReachable(t *testing.T) {
	srv, _ := testServer(t)
	w := doRequest(t, srv.Handler(), "GET", "/api/v1/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Checks["database"] != "ok" {
		t.Fatalf("unexpected healthy body: %+v", body)
	}
}

func TestHealth_degradedWhenDBDown(t *testing.T) {
	srv, database := testServer(t)
	database.Close() // simulate a wedged/unavailable database

	w := doRequest(t, srv.Handler(), "GET", "/api/v1/health", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 when DB is down", w.Code)
	}
	var body struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Status != "degraded" {
		t.Errorf("status = %q, want degraded", body.Status)
	}
}
