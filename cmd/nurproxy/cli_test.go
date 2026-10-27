package main

import (
	"encoding/json"
	"flag"
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

// newUpdateFlagSet mirrors the shape of `domain update`: a bool and a string
// flag next to a single positional ID.
func newUpdateFlagSet() (*flag.FlagSet, *bool, *string) {
	fs := flag.NewFlagSet("domain update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	forceHTTPS := fs.Bool("force-https", false, "")
	sslMode := fs.String("ssl-mode", "", "")
	return fs, forceHTTPS, sslMode
}

func TestParseArgsInterspersedFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		positional string
		wantArg    string
		wantForce  bool
		wantSSL    string
		wantErr    string
	}{
		{"bool flag after id", []string{"83", "--force-https"}, "domain id", "83", true, "", ""},
		{"bool flag before id", []string{"--force-https", "83"}, "domain id", "83", true, "", ""},
		{"string flag after id", []string{"83", "--ssl-mode", "auto"}, "domain id", "83", false, "auto", ""},
		{"string flag with = after id", []string{"83", "--ssl-mode=auto"}, "domain id", "83", false, "auto", ""},
		{"flags on both sides", []string{"--ssl-mode", "auto", "83", "-force-https"}, "domain id", "83", true, "auto", ""},
		{"explicit bool false after id", []string{"83", "--force-https=false"}, "domain id", "83", false, "", ""},
		{"terminator before id", []string{"--force-https", "--", "83"}, "domain id", "83", true, "", ""},
		{"terminator keeps dash arg positional", []string{"--", "-5"}, "domain id", "-5", false, "", ""},
		{"flag after terminator is positional", []string{"83", "--", "--force-https"}, "domain id", "", false, "", `unexpected argument "--force-https"`},
		{"extra positional", []string{"83", "84", "--force-https"}, "domain id", "", false, "", `unexpected argument "84"`},
		{"missing id", []string{"--force-https"}, "domain id", "", false, "", "missing domain id"},
		{"empty id", []string{""}, "domain id", "", false, "", "missing domain id"},
		{"no positional expected", []string{"--force-https"}, "", "", true, "", ""},
		{"stray positional rejected", []string{"oops", "--force-https"}, "", "", false, "", `unexpected argument "oops"`},
		{"unknown flag after id", []string{"83", "--nope"}, "domain id", "", false, "", "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, force, ssl := newUpdateFlagSet()
			got, err := parseArgs(fs, tt.args, tt.positional)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseArgs(%q) error = %v, want containing %q", tt.args, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs(%q) unexpected error: %v", tt.args, err)
			}
			if got != tt.wantArg {
				t.Errorf("positional = %q, want %q", got, tt.wantArg)
			}
			if *force != tt.wantForce {
				t.Errorf("force-https = %v, want %v", *force, tt.wantForce)
			}
			if *ssl != tt.wantSSL {
				t.Errorf("ssl-mode = %q, want %q", *ssl, tt.wantSSL)
			}
		})
	}
}

// TestParseArgsVisitSeesTrailingFlag guards #145: domain update only sends
// force_https when fs.Visit reports the flag as set, so a flag after the ID
// must register as visited.
func TestParseArgsVisitSeesTrailingFlag(t *testing.T) {
	fs, _, _ := newUpdateFlagSet()
	if _, err := parseArgs(fs, []string{"83", "--force-https"}, "domain id"); err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "force-https" {
			seen = true
		}
	})
	if !seen {
		t.Fatal("force-https after the ID was not visited")
	}
}

// TestDomainLoggingFlags checks that the logging flags reach the API as the
// top-level access_log / error_log_level fields, and that `domain update`
// sends them only when given, so an unrelated update never resets them.
func TestDomainLoggingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want map[string]any // expected logging fields; absent keys must not be sent
	}{
		{"update both", []string{"update", "7", "--access-log", "off", "--error-log-level", "crit"}, map[string]any{"access_log": "off", "error_log_level": "crit"}},
		{"update back to default", []string{"update", "7", "--access-log=default"}, map[string]any{"access_log": "default"}},
		{"update unrelated", []string{"update", "7", "--port", "9000"}, map[string]any{}},
		{"add with logging", []string{"add", "--subdomain", "p", "--zone", "z", "--server", "s", "--port", "80", "--access-log", "off"}, map[string]any{"access_log": "off"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
				_, _ = io.WriteString(w, `{"id":7}`)
			})
			cmdDomain(append(tt.args, "--url", srv.URL, "--key", "k"))
			if len(*reqs) != 1 {
				t.Fatalf("requests = %d, want 1", len(*reqs))
			}
			var body map[string]any
			if err := json.Unmarshal([]byte((*reqs)[0].body), &body); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"access_log", "error_log_level"} {
				want, expected := tt.want[key]
				got, sent := body[key]
				if sent != expected || got != want {
					t.Errorf("%s = %v (sent %v), want %v (sent %v)", key, got, sent, want, expected)
				}
			}
		})
	}
}
