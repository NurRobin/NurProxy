package main

import (
	"net/http"
	"testing"
	"time"
)

// TestNewHTTPServer asserts the orchestrator listener is hardened against
// Slowloris / idle-connection exhaustion: ReadHeaderTimeout, IdleTimeout and
// MaxHeaderBytes must be set, while WriteTimeout stays zero so the long-lived
// agent SSE stream and log-tail responses are never severed by a write deadline.
func TestNewHTTPServer(t *testing.T) {
	const addr = ":8080"
	srv := newHTTPServer(addr, http.NewServeMux())

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"addr", srv.Addr, addr},
		{"read_header_timeout", srv.ReadHeaderTimeout, 15 * time.Second},
		{"idle_timeout", srv.IdleTimeout, 90 * time.Second},
		{"max_header_bytes", srv.MaxHeaderBytes, 1 << 20},
		{"write_timeout_unset", srv.WriteTimeout, time.Duration(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}

	if srv.Handler == nil {
		t.Error("handler must not be nil")
	}
}
