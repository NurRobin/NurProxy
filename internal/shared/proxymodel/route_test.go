package proxymodel

import (
	"encoding/json"
	"strings"
	"testing"
)

func validStructured() Route {
	return Route{
		Host: "app.example.com",
		Upstream: Upstream{
			Addr: "10.0.0.4",
			Port: 8080,
		},
	}
}

func TestRoute_EffectiveScheme(t *testing.T) {
	tests := []struct {
		name string
		in   Scheme
		want Scheme
	}{
		{"empty defaults to http", "", SchemeHTTP},
		{"explicit http", SchemeHTTP, SchemeHTTP},
		{"explicit https", SchemeHTTPS, SchemeHTTPS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validStructured()
			r.Upstream.Scheme = tt.in
			if got := r.EffectiveScheme(); got != tt.want {
				t.Errorf("EffectiveScheme() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRawConfig_IsZero(t *testing.T) {
	tests := []struct {
		name string
		raw  RawConfig
		want bool
	}{
		{"empty", RawConfig{}, true},
		{"backend only", RawConfig{Backend: "nginx"}, false},
		{"content only", RawConfig{Content: "server {}"}, false},
		{"both", RawConfig{Backend: "nginx", Content: "server {}"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.raw.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoute_IsRaw(t *testing.T) {
	structured := validStructured()
	if structured.IsRaw() {
		t.Error("structured route reported IsRaw() = true")
	}
	raw := Route{Raw: RawConfig{Backend: "caddy", Content: "{}"}}
	if !raw.IsRaw() {
		t.Error("raw route reported IsRaw() = false")
	}
}

func TestRoute_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Route)
		wantErr bool
	}{
		{
			name:    "valid structured",
			mutate:  func(r *Route) {},
			wantErr: false,
		},
		{
			name:    "missing host",
			mutate:  func(r *Route) { r.Host = "" },
			wantErr: true,
		},
		{
			name:    "missing upstream addr",
			mutate:  func(r *Route) { r.Upstream.Addr = "" },
			wantErr: true,
		},
		{
			name:    "zero port",
			mutate:  func(r *Route) { r.Upstream.Port = 0 },
			wantErr: true,
		},
		{
			name:    "port too high",
			mutate:  func(r *Route) { r.Upstream.Port = 70000 },
			wantErr: true,
		},
		{
			name:    "negative port",
			mutate:  func(r *Route) { r.Upstream.Port = -1 },
			wantErr: true,
		},
		{
			name:    "explicit https scheme ok",
			mutate:  func(r *Route) { r.Upstream.Scheme = SchemeHTTPS },
			wantErr: false,
		},
		{
			name:    "invalid scheme",
			mutate:  func(r *Route) { r.Upstream.Scheme = "ftp" },
			wantErr: true,
		},
		{
			name:    "negative rate limit",
			mutate:  func(r *Route) { r.RateLimit.RequestsPerSecond = -5 },
			wantErr: true,
		},
		{
			name:    "valid basic auth",
			mutate:  func(r *Route) { r.BasicAuth = &BasicAuth{Username: "u", PasswordHash: "$2a$..."} },
			wantErr: false,
		},
		{
			name:    "basic auth missing username",
			mutate:  func(r *Route) { r.BasicAuth = &BasicAuth{PasswordHash: "$2a$..."} },
			wantErr: true,
		},
		{
			name:    "basic auth missing hash",
			mutate:  func(r *Route) { r.BasicAuth = &BasicAuth{Username: "u"} },
			wantErr: true,
		},
		{
			name:    "access log off",
			mutate:  func(r *Route) { r.AccessLog = AccessLogOff },
			wantErr: false,
		},
		{
			name:    "unknown access log mode",
			mutate:  func(r *Route) { r.AccessLog = "syslog" },
			wantErr: true,
		},
		{
			name:    "error log level crit",
			mutate:  func(r *Route) { r.ErrorLogLevel = "crit" },
			wantErr: false,
		},
		{
			name:    "error log level debug refused",
			mutate:  func(r *Route) { r.ErrorLogLevel = "debug" },
			wantErr: true,
		},
		{
			name:    "error log level with injected directive",
			mutate:  func(r *Route) { r.ErrorLogLevel = "crit; include /etc/passwd" },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validStructured()
			tt.mutate(&r)
			err := r.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRoute_Validate_raw(t *testing.T) {
	tests := []struct {
		name    string
		raw     RawConfig
		wantErr bool
	}{
		{"valid raw", RawConfig{Backend: "nginx", Content: "server {}"}, false},
		{"raw missing backend", RawConfig{Content: "server {}"}, true},
		{"raw blank content", RawConfig{Backend: "nginx", Content: "   "}, true},
		{"raw empty content", RawConfig{Backend: "nginx"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A raw route skips structured validation entirely, even with no
			// host/upstream set, so build it bare.
			r := Route{Raw: tt.raw}
			err := r.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRoute_JSONOmitsDefaultLogging pins that a route without logging settings
// serializes exactly as before the fields existed, so the helper's intent
// digest of existing routes does not change.
func TestRoute_JSONOmitsDefaultLogging(t *testing.T) {
	data, err := json.Marshal(validStructured())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "AccessLog") || strings.Contains(string(data), "ErrorLogLevel") {
		t.Fatalf("default logging leaked into route JSON: %s", data)
	}
	r := validStructured()
	r.AccessLog = AccessLogOff
	r.ErrorLogLevel = "crit"
	data, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Route
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.AccessLog != AccessLogOff || back.ErrorLogLevel != "crit" {
		t.Fatalf("logging did not round-trip: %+v", back)
	}
}

// The API validates stored settings through ValidateOptions, so the logging
// values must be checked there and not only in Validate.
func TestRoute_ValidateOptions_logging(t *testing.T) {
	for _, tt := range []struct {
		access  AccessLogMode
		level   string
		wantErr bool
	}{
		{"", "", false}, {AccessLogOff, "crit", false}, {"on", "", true}, {"", "debug", true}, {"", "crit;", true},
	} {
		r := Route{AccessLog: tt.access, ErrorLogLevel: tt.level}
		if err := r.ValidateOptions(); (err != nil) != tt.wantErr {
			t.Errorf("ValidateOptions(access=%q, level=%q) error = %v, wantErr %v", tt.access, tt.level, err, tt.wantErr)
		}
	}
}
