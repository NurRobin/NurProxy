package api

import (
	"bytes"
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

// setupOnHost runs first-time setup against a specific Host header and returns
// the resulting session cookie (with whatever Secure attribute the server set).
func setupOnHost(t *testing.T, handler http.Handler, host string) *http.Cookie {
	t.Helper()
	b, err := json.Marshal(map[string]string{"password": "testpassword123"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/setup", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("setup on host %q: got %d: %s", host, w.Code, w.Body.String())
	}
	c := sessionCookie(w.Result())
	if c == nil {
		t.Fatalf("no session cookie from setup on host %q", host)
	}
	return c
}

// The Secure attribute defaults on for non-localhost requests, off for
// localhost, and is overridable by the secure_cookies setting.
func TestSessionCookie_SecureFlag(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		setting    string // "" = unset
		wantSecure bool
	}{
		{name: "non-localhost default secure", host: "proxy.example.com", wantSecure: true},
		{name: "localhost default insecure", host: "localhost:8080", wantSecure: false},
		{name: "loopback ip default insecure", host: "127.0.0.1:8080", wantSecure: false},
		{name: "explicit true forces secure on localhost", host: "localhost:8080", setting: "true", wantSecure: true},
		{name: "explicit false forces insecure on remote", host: "proxy.example.com", setting: "false", wantSecure: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, database := testServer(t)
			if tt.setting != "" {
				if err := database.SetSetting(secureCookiesSetting, tt.setting); err != nil {
					t.Fatal(err)
				}
			}
			cookie := setupOnHost(t, srv.Handler(), tt.host)
			if cookie.Secure != tt.wantSecure {
				t.Fatalf("Secure = %v, want %v", cookie.Secure, tt.wantSecure)
			}
		})
	}
}
