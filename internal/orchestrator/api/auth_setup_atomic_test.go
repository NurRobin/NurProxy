package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestAuthSetup_ConcurrentRequestsMintOnlyWinnerSession(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	type result struct {
		status int
		cookie *http.Cookie
	}
	passwords := []string{"first-password", "second-password"}
	results := make(chan result, len(passwords))
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(len(passwords))
	for _, password := range passwords {
		go func(password string) {
			body, err := json.Marshal(map[string]string{"password": password})
			if err != nil {
				results <- result{status: -1}
				return
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			ready.Done()
			<-start
			handler.ServeHTTP(w, req)
			results <- result{status: w.Code, cookie: sessionCookie(w.Result())}
		}(password)
	}
	ready.Wait()
	close(start)

	var winner, loser *result
	for range passwords {
		r := <-results
		switch r.status {
		case http.StatusOK:
			copy := r
			if winner != nil {
				t.Fatalf("multiple setup winners: both returned 200")
			}
			winner = &copy
		case http.StatusConflict:
			copy := r
			loser = &copy
		default:
			t.Fatalf("setup status = %d, want 200 or 409", r.status)
		}
	}
	if winner == nil || loser == nil {
		t.Fatalf("setup results missing winner or loser: winner=%v loser=%v", winner != nil, loser != nil)
	}
	if winner.cookie == nil {
		t.Fatal("winner did not receive a session cookie")
	}
	if loser.cookie != nil {
		t.Fatal("loser received a session cookie")
	}

	w := doRequest(t, handler, http.MethodGet, "/api/v1/providers", nil, winner.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("winner protected request = %d, want 200", w.Code)
	}
	w = doRequest(t, handler, http.MethodGet, "/api/v1/providers", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("loser protected request = %d, want 401", w.Code)
	}
}
