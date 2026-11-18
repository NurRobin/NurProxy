package caddygen

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestValidateTLSWildcardAndHost(t *testing.T) {
	tests := []struct {
		name     string
		dom      models.Domain
		wantErr  bool
		wantHost string
	}{
		{name: "not opted in", dom: models.Domain{Subdomain: "app"}, wantHost: ""},
		{name: "single label", dom: models.Domain{Subdomain: "app", ProxyConfig: models.ProxyConfig{TLSWildcard: true}},
			wantHost: "*.example.com"},
		{name: "explicit central", dom: models.Domain{Subdomain: "app", ProxyConfig: models.ProxyConfig{TLSWildcard: true, TLSPolicy: "central"}},
			wantHost: "*.example.com"},
		{name: "apex", dom: models.Domain{Subdomain: "@", ProxyConfig: models.ProxyConfig{TLSWildcard: true}}, wantErr: true},
		{name: "nested label", dom: models.Domain{Subdomain: "a.b", ProxyConfig: models.ProxyConfig{TLSWildcard: true}}, wantErr: true},
		{name: "self-acme", dom: models.Domain{Subdomain: "app", ProxyConfig: models.ProxyConfig{TLSWildcard: true, TLSPolicy: "self-acme"}}, wantErr: true},
		{name: "ssl off", dom: models.Domain{Subdomain: "app", SSLMode: models.SSLModeOff, ProxyConfig: models.ProxyConfig{TLSWildcard: true}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTLSWildcard(tt.dom)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTLSWildcard = %v, wantErr %v", err, tt.wantErr)
			}
			if got := WildcardCertHost(tt.dom, "example.com"); got != tt.wantHost {
				t.Fatalf("WildcardCertHost = %q, want %q", got, tt.wantHost)
			}
			// The shared cert reaches the agent as an ordinary per-host bundle;
			// the route must not carry the wildcard flag, which the file
			// backends report as a dropped option and mark the domain degraded.
			if ConfigFromDomain(tt.dom, "app.example.com", "10.0.0.1", nil).TLS.Wildcard {
				t.Fatal("route TLS.Wildcard set")
			}
		})
	}
}
