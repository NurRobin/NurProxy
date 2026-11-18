package models

import "testing"

func TestProxyConfig_CheckHeadersSupported(t *testing.T) {
	withVar := ProxyConfig{CustomResponseHeaders: map[string]string{"X-A": "${HOME}"}}
	tests := []struct {
		name    string
		pc      ProxyConfig
		caps    *ProxyCapabilities
		kind    string
		wantErr bool
	}{
		{"apache capability", withVar, &ProxyCapabilities{HeaderConfigVars: true}, "apache", true},
		{"apache predating capability", withVar, &ProxyCapabilities{}, "apache", true},
		{"apache without matrix", withVar, nil, "apache", true},
		{"capability on unknown kind", withVar, &ProxyCapabilities{HeaderConfigVars: true}, "", true},
		{"nginx", withVar, &ProxyCapabilities{}, "nginx", false},
		{"built-in caddy", withVar, nil, "", false},
		{"apache without variable", ProxyConfig{CustomResponseHeaders: map[string]string{"X-A": "$HOME"}}, &ProxyCapabilities{HeaderConfigVars: true}, "apache", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pc.CheckHeadersSupported(tt.caps, tt.kind); (err != nil) != tt.wantErr {
				t.Fatalf("CheckHeadersSupported() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
