package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestSessionSecret_ConcurrentServersShareBootstrapKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		seedLegacy bool
		legacy     string
	}{
		{name: "missing setting"},
		{name: "empty legacy setting", seedLegacy: true},
		{name: "malformed legacy setting", seedLegacy: true, legacy: "not-base64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "nurproxy.db")
			db1, err := db.Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db1.Close() })
			db2, err := db.Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db2.Close() })
			if tc.seedLegacy {
				if err := db1.SetSetting(sessionSecretSetting, tc.legacy); err != nil {
					t.Fatal(err)
				}
			}

			const serverCount = 8
			start := make(chan struct{})
			serverResults := make(chan *Server, serverCount)
			var ready sync.WaitGroup
			ready.Add(serverCount)
			for i := 0; i < serverCount; i++ {
				database := db1
				if i%2 != 0 {
					database = db2
				}
				go func(database *db.DB) {
					ready.Done()
					<-start
					serverResults <- NewServer(database, "test")
				}(database)
			}
			ready.Wait()
			close(start)
			servers := make([]*Server, 0, serverCount)
			for range serverCount {
				servers = append(servers, <-serverResults)
			}

			body, err := json.Marshal(map[string]string{"password": "testpassword123"})
			if err != nil {
				t.Fatal(err)
			}
			type setupResult struct {
				status int
				cookie *http.Cookie
			}
			setupStart := make(chan struct{})
			setupResults := make(chan setupResult, 2)
			ready = sync.WaitGroup{}
			ready.Add(2)
			for _, srv := range servers[:2] {
				go func(srv *Server) {
					req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					ready.Done()
					<-setupStart
					srv.Handler().ServeHTTP(w, req)
					setupResults <- setupResult{status: w.Code, cookie: sessionCookie(w.Result())}
				}(srv)
			}
			ready.Wait()
			close(setupStart)

			var winnerCookie *http.Cookie
			statuses := map[int]int{}
			for range 2 {
				result := <-setupResults
				statuses[result.status]++
				if result.status == http.StatusOK {
					winnerCookie = result.cookie
				} else if result.cookie != nil {
					t.Fatal("setup loser received a session cookie")
				}
			}
			if statuses[http.StatusOK] != 1 || statuses[http.StatusConflict] != 1 {
				t.Fatalf("setup statuses = %#v, want one 200 and one 409", statuses)
			}
			if winnerCookie == nil {
				t.Fatal("setup winner did not receive a session cookie")
			}

			for i, srv := range servers {
				w := doRequest(t, srv.Handler(), http.MethodGet, "/api/v1/providers", nil, winnerCookie)
				if w.Code != http.StatusOK {
					t.Fatalf("winner cookie on concurrent server %d = %d, want 200", i+1, w.Code)
				}
			}

			db3, err := db.Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db3.Close() })
			restarted := NewServer(db3, "test-restart")
			w := doRequest(t, restarted.Handler(), http.MethodGet, "/api/v1/providers", nil, winnerCookie)
			if w.Code != http.StatusOK {
				t.Fatalf("winner cookie after restart = %d, want 200", w.Code)
			}
		})
	}
}

func TestSessionSecret_BusyBootstrapAdoptsCommittedKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nurproxy.db")
	database, err := db.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.SetSetting(sessionSecretSetting, "malformed"); err != nil {
		t.Fatal(err)
	}

	winnerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	winnerEncoded := base64.StdEncoding.EncodeToString(winnerKey)
	lockDB, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lockDB.Close() })
	tx, err := lockDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	t.Cleanup(func() {
		if !committed {
			_ = tx.Rollback()
		}
	})
	if _, err := tx.Exec("UPDATE settings SET value = ? WHERE key = ?", winnerEncoded, sessionSecretSetting); err != nil {
		t.Fatal(err)
	}

	serverResult := make(chan *Server, 1)
	go func() { serverResult <- NewServer(database, "busy-bootstrap") }()
	time.Sleep(5500 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	committed = true

	var busyServer *Server
	select {
	case busyServer = <-serverResult:
	case <-time.After(10 * time.Second):
		t.Fatal("server bootstrap did not recover after the write lock was released")
	}
	signed := busyServer.sessions.Sign("session-token")
	restarted := NewServer(database, "restart")
	if _, err := restarted.sessions.Verify(signed); err != nil {
		t.Fatalf("server retained a discarded ephemeral key after SQLITE_BUSY: %v", err)
	}
	stored, err := database.GetSetting(sessionSecretSetting)
	if err != nil {
		t.Fatal(err)
	}
	if stored != winnerEncoded {
		t.Fatal("bootstrap overwrote or failed to adopt the concurrently committed session secret")
	}
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
