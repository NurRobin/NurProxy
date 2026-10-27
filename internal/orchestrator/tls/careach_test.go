package tls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsCAUnreachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "rate limit is protocol-level", err: &RateLimitError{Detail: "too many"}, want: false},
		{name: "not configured", err: ErrACMENotConfigured, want: false},
		{name: "dns failure", err: &net.DNSError{Err: "no such host", Name: "acme-v02.api.letsencrypt.org"}, want: true},
		{name: "op error", err: &net.OpError{Op: "dial", Err: errors.New("connect: no route to host")}, want: true},
		{name: "wrapped tls handshake timeout", err: fmt.Errorf("get directory: %w", errors.New("net/http: TLS handshake timeout")), want: true},
		{name: "connection refused string", err: errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), want: true},
		{name: "plain validation error", err: errors.New("acme: error: 403 :: urn:ietf:params:acme:error:unauthorized"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCAUnreachable(tt.err); got != tt.want {
				t.Errorf("IsCAUnreachable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestCAProber_reachableAndNot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewCAProber(func() string { return srv.URL })
	st := p.Probe(context.Background())
	if !st.OK || st.URL != srv.URL || st.CheckedAt.IsZero() {
		t.Fatalf("probe against live server = %+v, want OK", st)
	}
	if got := p.Status(); !got.OK {
		t.Fatalf("Status() should return the cached observation, got %+v", got)
	}

	// A closed listener is unreachable — and even a 5xx would still count as
	// reachable (the network path works), so only kill the listener here.
	srv.Close()
	st = p.Probe(context.Background())
	if st.OK {
		t.Fatalf("probe against closed server should fail, got %+v", st)
	}
	if st.Detail == "" {
		t.Error("unreachable probe must carry a detail message")
	}
}

func TestCAProber_5xxStillCountsAsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := NewCAProber(func() string { return srv.URL })
	if st := p.Probe(context.Background()); !st.OK {
		t.Fatalf("a 503 proves the path works; probe = %+v", st)
	}
}

func TestCAProber_emptyURLDefaultsToProduction(t *testing.T) {
	p := NewCAProber(nil)
	// No network call here — just verify the URL default resolution by probing
	// with an immediately-canceled context (the request fails fast).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := p.Probe(ctx)
	if st.URL != LEDirectoryProduction {
		t.Errorf("empty resolver should default to LE production, got %q", st.URL)
	}
}
