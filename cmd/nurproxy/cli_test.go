package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recordingServer captures the requests a command makes so tests can assert on
// method, path, auth, and body without a real orchestrator.
type capturedReq struct {
	method string
	path   string
	auth   string
	cookie string
	body   string
}

func newTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, rec *capturedReq)) (*httptest.Server, *[]capturedReq) {
	t.Helper()
	var reqs []capturedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := capturedReq{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), body: string(body)}
		if ck, err := r.Cookie("nurproxy_session"); err == nil {
			rec.cookie = ck.Value
		}
		handler(w, r, &rec)
		reqs = append(reqs, rec)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestClientBearerAuth(t *testing.T) {
	srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	c := newClient(srv.URL, "secret-key", "", false)
	if _, err := c.get("/api/v1/zones"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := (*reqs)[0].auth; got != "Bearer secret-key" {
		t.Errorf("auth header = %q, want Bearer secret-key", got)
	}
}

func TestClientPasswordLoginFlow(t *testing.T) {
	srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
		if r.URL.Path == "/api/v1/auth/login" {
			http.SetCookie(w, &http.Cookie{Name: "nurproxy_session", Value: "sess-123"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"logged in"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	c := newClient(srv.URL, "", "hunter2", false)
	if _, err := c.get("/api/v1/agents"); err != nil {
		t.Fatalf("get: %v", err)
	}

	if len(*reqs) != 2 {
		t.Fatalf("expected login + get = 2 requests, got %d", len(*reqs))
	}
	login, call := (*reqs)[0], (*reqs)[1]
	if login.path != "/api/v1/auth/login" || login.method != http.MethodPost {
		t.Errorf("first request = %s %s, want POST /api/v1/auth/login", login.method, login.path)
	}
	if call.cookie != "sess-123" {
		t.Errorf("session cookie = %q, want sess-123", call.cookie)
	}
	if call.auth != "" {
		t.Errorf("authorization header should be empty when using cookie, got %q", call.auth)
	}
}

func TestClientNoCredentials(t *testing.T) {
	c := newClient("http://localhost:0", "", "", false)
	_, err := c.get("/api/v1/zones")
	if err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("expected no-credentials error, got %v", err)
	}
}

func TestClientAPIErrorMessage(t *testing.T) {
	srv, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"type and name are required"}`))
	})

	c := newClient(srv.URL, "k", "", false)
	_, err := c.do(http.MethodPost, "/api/v1/providers", map[string]string{"type": ""})
	if err == nil || !strings.Contains(err.Error(), "type and name are required") {
		t.Fatalf("expected API error message surfaced, got %v", err)
	}
}

func TestPostNoAuthOmitsCredentials(t *testing.T) {
	srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"setup complete"}`))
	})

	c := newClient(srv.URL, "should-not-be-sent", "", false)
	if _, err := c.postNoAuth("/api/v1/auth/setup", map[string]string{"password": "longenough"}); err != nil {
		t.Fatalf("postNoAuth: %v", err)
	}
	if got := (*reqs)[0].auth; got != "" {
		t.Errorf("setup must be unauthenticated, but Authorization=%q", got)
	}
	var sent map[string]string
	_ = json.Unmarshal([]byte((*reqs)[0].body), &sent)
	if sent["password"] != "longenough" {
		t.Errorf("password body = %q, want longenough", sent["password"])
	}
}

func TestApiErrorBytesFallback(t *testing.T) {
	tests := []struct {
		name   string
		status int
		data   string
		want   string
	}{
		{"json error", 400, `{"error":"boom"}`, "boom"},
		{"plain body", 500, "internal", "HTTP 500: internal"},
		{"empty body", 502, "", "HTTP 502"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiErrorBytes(tt.status, []byte(tt.data)); got != tt.want {
				t.Errorf("apiErrorBytes(%d, %q) = %q, want %q", tt.status, tt.data, got, tt.want)
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,, c ", []string{"a", "b", "c"}},
		{"", []string{}},
	}
	for _, tt := range tests {
		got := splitCSV(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("NP_TEST_KEY", "from-env")
	if got := envOr("NP_TEST_KEY", "def"); got != "from-env" {
		t.Errorf("envOr with set value = %q, want from-env", got)
	}
	if got := envOr("NP_TEST_UNSET_KEY", "def"); got != "def" {
		t.Errorf("envOr with unset value = %q, want def", got)
	}
}
