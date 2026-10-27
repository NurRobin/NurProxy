package proxymodel

import (
	"strings"
	"testing"
)

func TestRoute_Validate_values(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Route)
		ok     bool
	}{
		{"wildcard host", func(r *Route) { r.Host = "*.example.com" }, true},
		{"underscore host", func(r *Route) { r.Host = "_dmarc.example.com" }, true},
		{"host with space", func(r *Route) { r.Host = "a.example.com b" }, false},
		{"host with semicolon", func(r *Route) { r.Host = "a.example.com;" }, false},
		{"host with newline", func(r *Route) { r.Host = "a.example.com\nx" }, false},
		{"inner wildcard", func(r *Route) { r.Host = "a.*.example.com" }, false},
		{"ipv4 upstream", func(r *Route) { r.Upstream.Addr = "10.0.0.1" }, true},
		{"ipv6 upstream", func(r *Route) { r.Upstream.Addr = "::1" }, true},
		{"bracketed ipv6 upstream", func(r *Route) { r.Upstream.Addr = "[2001:db8::1]" }, true},
		{"hostname upstream", func(r *Route) { r.Upstream.Addr = "backend.internal" }, true},
		{"upstream with path", func(r *Route) { r.Upstream.Addr = "10.0.0.1/x" }, false},
		{"upstream with semicolon", func(r *Route) { r.Upstream.Addr = "10.0.0.1;" }, false},
		{"wildcard upstream", func(r *Route) { r.Upstream.Addr = "*.internal" }, false},
		{"header", func(r *Route) { r.ResponseHeaders = map[string]string{"X-A_b": `say "hi"; it's {ok} #1`} }, true},
		{"header name with space", func(r *Route) { r.ResponseHeaders = map[string]string{"X A": "v"} }, false},
		{"header name with colon", func(r *Route) { r.RequestHeaders = map[string]string{"X:A": "v"} }, false},
		{"empty header name", func(r *Route) { r.RequestHeaders = map[string]string{"": "v"} }, false},
		{"header value with backslash", func(r *Route) { r.ResponseHeaders = map[string]string{"X-A": `\";include /etc/x;#`} }, false},
		{"header value with CR", func(r *Route) { r.ResponseHeaders = map[string]string{"X-A": "a\rb"} }, false},
		{"header value with LF", func(r *Route) { r.RequestHeaders = map[string]string{"X-A": "a\nb"} }, false},
		{"header value with NUL", func(r *Route) { r.RequestHeaders = map[string]string{"X-A": "a\x00"} }, false},
		{"header value with tab", func(r *Route) { r.RequestHeaders = map[string]string{"X-A": "a\tb"} }, false},
		{"body sizes", func(r *Route) { r.MaxBodySize = "10MB" }, true},
		{"body size decimal", func(r *Route) { r.MaxBodySize = "1.5g" }, false},
		{"body size zero", func(r *Route) { r.MaxBodySize = "0" }, true},
		{"fully qualified upstream", func(r *Route) { r.Upstream.Addr = "ai.lan." }, true},
		{"upstream with two trailing dots", func(r *Route) { r.Upstream.Addr = "ai.lan.." }, false},
		{"header value expr", func(r *Route) { r.ResponseHeaders = map[string]string{"X-A": "expr=%{file:/etc/shadow}"} }, false},
		{"header value EXPR", func(r *Route) { r.RequestHeaders = map[string]string{"X-A": "EXPR=1"} }, false},
		{"header value containing expr", func(r *Route) { r.RequestHeaders = map[string]string{"X-A": "a expr=1"} }, true},
		{"long header value", func(r *Route) { r.ResponseHeaders = map[string]string{"X-A": strings.Repeat("a", MaxHeaderValueBytes)} }, true},
		{"too long header value", func(r *Route) {
			r.ResponseHeaders = map[string]string{"X-A": strings.Repeat("a", MaxHeaderValueBytes+1)}
		}, false},
		{"too long quoted header value", func(r *Route) {
			r.ResponseHeaders = map[string]string{"X-A": strings.Repeat(`"`, MaxHeaderValueBytes/2+1)}
		}, false},
		{"too long path", func(r *Route) { r.Path.Rewrite = "/" + strings.Repeat("a", 1024) }, false},
		{"body size unlimited", func(r *Route) { r.MaxBodySize = "Unlimited" }, true},
		{"body size with directive", func(r *Route) { r.MaxBodySize = "10m;include /etc/x" }, false},
		{"strip prefix", func(r *Route) { r.Path.StripPrefix = "/api.v1/" }, true},
		{"strip prefix with space", func(r *Route) { r.Path.StripPrefix = "/a b" }, false},
		{"rewrite with semicolon", func(r *Route) { r.Path.Rewrite = "/x;" }, false},
		{"rewrite with brace", func(r *Route) { r.Path.Rewrite = "/${x}" }, false},
		{"rewrite with backslash", func(r *Route) { r.Path.Rewrite = `/x\` }, false},
		{"ip lists", func(r *Route) { r.IPAllowlist = []string{"10.0.0.0/8", "::1"}; r.IPBlocklist = []string{"1.2.3.4"} }, true},
		{"ip list keyword", func(r *Route) { r.IPAllowlist = []string{"all"} }, false},
		{"ip list with space", func(r *Route) { r.IPBlocklist = []string{"1.2.3.4 5.6.7.8"} }, false},
		{"username with colon", func(r *Route) { r.BasicAuth = &BasicAuth{Username: "a:b", PasswordHash: "h"} }, false},
		{"username with newline", func(r *Route) { r.BasicAuth = &BasicAuth{Username: "a\nb", PasswordHash: "h"} }, false},
		{"hash with newline", func(r *Route) { r.BasicAuth = &BasicAuth{Username: "a", PasswordHash: "h\nb:c"} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validStructured()
			tt.mutate(&r)
			if err := r.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
