package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

func memDB(t *testing.T) *db.DB {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// The session secret must be a persisted, install-unique 32-byte random value —
// not derived from a public constant + version, which would let anyone forge a
// session cookie. It must survive a "restart" (a second NewServer on the same DB).
func TestLoadOrCreateSessionKey_persistsAndIsRandom(t *testing.T) {
	database := memDB(t)

	first := loadOrCreateSessionKey(database)
	if len(first) != 32 {
		t.Fatalf("session key length = %d, want 32", len(first))
	}
	// Must not be the old predictable static key.
	if string(first) == "nurproxy-session-key-test" {
		t.Fatal("session key is the predictable static value")
	}

	// A second call (e.g. after restart) returns the SAME persisted key.
	second := loadOrCreateSessionKey(database)
	if base64.StdEncoding.EncodeToString(first) != base64.StdEncoding.EncodeToString(second) {
		t.Fatal("session key not persisted: second load differs from first")
	}
}

// A session signed by one server instance must verify on another instance built
// from the SAME database (restart resilience), but NOT on one from a different
// database (per-install uniqueness — a stolen cookie from install A is useless
// against install B).
func TestSessionSecret_restartResilientAndInstallUnique(t *testing.T) {
	dbA := memDB(t)
	srvA1 := NewServer(dbA, "v1.0.0")
	signed := srvA1.sessions.Sign("session-token-123")

	// Same DB, new server (simulated restart, possibly a different version).
	srvA2 := NewServer(dbA, "v2.0.0")
	if _, err := srvA2.sessions.Verify(signed); err != nil {
		t.Fatalf("session should survive restart on same DB: %v", err)
	}

	// Different install (different DB) must reject the cookie.
	srvB := NewServer(memDB(t), "v1.0.0")
	if _, err := srvB.sessions.Verify(signed); err == nil {
		t.Fatal("session from install A must not verify on install B")
	}
}

// The session secret must never be exposed through the settings API, even
// though it is stored in the settings table.
func TestSessionSecret_maskedFromSettingsAPI(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()

	// Precondition: the secret is actually stored in the settings table.
	if _, err := database.GetSetting(sessionSecretSetting); err != nil {
		t.Fatalf("precondition: session secret should be stored: %v", err)
	}

	// Authenticate.
	w := doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{"password": "testpassword123"})
	if w.Code != http.StatusOK {
		t.Fatalf("setup: got %d: %s", w.Code, w.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "nurproxy_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie after setup")
	}

	// List settings and assert the secret is filtered out.
	w = doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list settings: got %d: %s", w.Code, w.Body.String())
	}
	var settings []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	for _, s := range settings {
		if s["key"] == sessionSecretSetting {
			t.Fatal("session secret leaked through GET /settings")
		}
	}

	// And it cannot be overwritten through the settings endpoint.
	w = doRequest(t, handler, "PUT", "/api/v1/settings/"+sessionSecretSetting, map[string]string{"value": "x"}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("PUT session secret: expected 403, got %d", w.Code)
	}
}
