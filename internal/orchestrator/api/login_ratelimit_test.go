package api

import (
	"net/http"
	"testing"
)

// After enough failed logins from one IP, the endpoint must lock out further
// attempts with 429 — even when the correct password is finally supplied.
func TestLogin_locksOutAfterRepeatedFailures(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	w := doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{"password": "correct-horse"})
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}

	// 5 wrong attempts are each rejected with 401 (the limiter allows them).
	for i := 0; i < 5; i++ {
		w = doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{"password": "wrong"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, w.Code)
		}
	}

	// The 6th attempt is locked out — and the correct password does NOT bypass it.
	w = doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{"password": "correct-horse"})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after lockout: got %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on lockout")
	}
}

// A successful login resets the failure counter so earlier misses don't
// accumulate toward a later lockout.
func TestLogin_successResetsFailureCount(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	doRequest(t, handler, "POST", "/api/v1/auth/setup", map[string]string{"password": "correct-horse"})

	// A few misses, then a success.
	for i := 0; i < 4; i++ {
		doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{"password": "wrong"})
	}
	if w := doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{"password": "correct-horse"}); w.Code != http.StatusOK {
		t.Fatalf("valid login should succeed before lockout: got %d", w.Code)
	}

	// The counter is reset, so a fresh miss is treated as the first one (still 401,
	// not 429).
	if w := doRequest(t, handler, "POST", "/api/v1/auth/login", map[string]string{"password": "wrong"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("after a successful login the counter should reset: got %d, want 401", w.Code)
	}
}
