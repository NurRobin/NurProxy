package nginxparse

import "testing"

func TestHasErrorLog(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"none", "server { listen 80; location / { proxy_pass http://a:1; } }", false},
		{"server scope", "server { error_log /var/log/nginx/error.log crit; }", true},
		{"location scope", "server { location / { error_log /var/log/nginx/error.log crit; } }", true},
		{"quoted name", `server { "error_log" /var/log/nginx/error.log crit; }`, true},
		{"only in a header value", `server { add_header X "error_log"; }`, false},
		{"unreadable", "server { error_log", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasErrorLog(tt.content); got != tt.want {
				t.Fatalf("HasErrorLog() = %v, want %v", got, tt.want)
			}
		})
	}
}
