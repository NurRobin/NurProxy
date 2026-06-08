package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// sessionCookie pulls the nurproxy_session cookie out of a response, or nil.
func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "nurproxy_session" {
			return c
		}
	}
	return nil
}

// Logout must invalidate a previously-valid session token server-side, not just
// nudge the client cookie: the same cookie value must stop authenticating on a
// protected route. Pre-fix the token had no version and logout couldn't revoke
// live tokens, so the second request would still be 200.
func TestLogout_InvalidatesLiveToken(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	cookie := setupAdmin(t, handler)

	// Token works on a protected route.
	w := doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-logout protected request: got %d, want 200", w.Code)
	}

	// Log out (server-side revocation via session-version bump).
	w = doRequest(t, handler, "POST", "/api/v1/auth/logout", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("logout: got %d, want 200", w.Code)
	}

	// The same cookie must now be rejected.
	w = doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout protected request: got %d, want 401", w.Code)
	}
}

// Changing the password must invalidate every outstanding session cookie.
func TestChangePassword_InvalidatesLiveToken(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	cookie := setupAdmin(t, handler)

	w := doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-change protected request: got %d, want 200", w.Code)
	}

	w = doRequest(t, handler, "POST", "/api/v1/auth/change-password", map[string]string{
		"current_password": "testpassword123",
		"new_password":     "newtestpassword456",
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("change-password: got %d: %s", w.Code, w.Body.String())
	}

	w = doRequest(t, handler, "GET", "/api/v1/settings", nil, cookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("post-change protected request: got %d, want 401", w.Code)
	}
}

// runSetup runs first-time setup, applying mutate to the request so a test can
// pick the Host, scheme, or forwarding headers, and returns the session cookie
// (with whatever Secure attribute the server set).
func runSetup(t *testing.T, handler http.Handler, mutate func(*http.Request)) *http.Cookie {
	t.Helper()
	b, err := json.Marshal(map[string]string{"password": "testpassword123"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/setup", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("setup: got %d: %s", w.Code, w.Body.String())
	}
	c := sessionCookie(w.Result())
	if c == nil {
		t.Fatal("no session cookie from setup")
	}
	return c
}

// The Secure attribute defaults to tracking the request scheme: on for HTTPS
// (direct TLS or X-Forwarded-Proto=https), off for plain http regardless of
// host, and overridable either way by the secure_cookies setting.
func TestSessionCookie_SecureFlag(t *testing.T) {
	tests := []struct {
		name       string
		setting    string // "" = unset
		mutate     func(*http.Request)
		wantSecure bool
	}{
		{name: "plain http remote default insecure", mutate: func(r *http.Request) { r.Host = "proxy.example.com" }, wantSecure: false},
		{name: "plain http localhost default insecure", mutate: func(r *http.Request) { r.Host = "localhost:8080" }, wantSecure: false},
		{name: "direct tls default secure", mutate: func(r *http.Request) {
			r.Host = "proxy.example.com"
			r.TLS = &tls.ConnectionState{}
		}, wantSecure: true},
		{name: "forwarded https default secure", mutate: func(r *http.Request) {
			r.Host = "proxy.example.com"
			r.Header.Set("X-Forwarded-Proto", "https")
		}, wantSecure: true},
		{name: "explicit true forces secure on plain http", setting: "true", mutate: func(r *http.Request) { r.Host = "localhost:8080" }, wantSecure: true},
		{name: "explicit false forces insecure over https", setting: "false", mutate: func(r *http.Request) {
			r.Host = "proxy.example.com"
			r.Header.Set("X-Forwarded-Proto", "https")
		}, wantSecure: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, database := testServer(t)
			if tt.setting != "" {
				if err := database.SetSetting(secureCookiesSetting, tt.setting); err != nil {
					t.Fatal(err)
				}
			}
			cookie := runSetup(t, srv.Handler(), tt.mutate)
			if cookie.Secure != tt.wantSecure {
				t.Fatalf("Secure = %v, want %v", cookie.Secure, tt.wantSecure)
			}
		})
	}
}
