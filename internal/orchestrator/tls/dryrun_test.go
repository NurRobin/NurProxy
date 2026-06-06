package tls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// recordingSolver records every Present/CleanUp so tests can assert the dry-run
// ACME client drives the DNS path and cleans up after itself.
type recordingSolver struct {
	presented []string
	cleaned   []string
}

func (s *recordingSolver) Present(_ context.Context, fqdn, _ string) error {
	s.presented = append(s.presented, fqdn)
	return nil
}
func (s *recordingSolver) CleanUp(_ context.Context, fqdn, _ string) error {
	s.cleaned = append(s.cleaned, fqdn)
	return nil
}

func TestDryRunACMESuccess(t *testing.T) {
	solver := &recordingSolver{}
	c := NewDryRunACMEClient(nil, DryRunFailNone)

	res, err := c.ObtainViaDNS01(context.Background(), []string{"app.example.com", "www.example.com"}, solver)
	if err != nil {
		t.Fatalf("ObtainViaDNS01: %v", err)
	}
	if res.Host != "app.example.com" || len(res.Names) != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}

	// The DNS path must have been exercised and cleaned up for every name.
	if len(solver.presented) != 2 || len(solver.cleaned) != 2 {
		t.Fatalf("expected 2 presents and 2 cleanups, got %d/%d", len(solver.presented), len(solver.cleaned))
	}
	if solver.presented[0] != "_acme-challenge.app.example.com" {
		t.Fatalf("unexpected challenge fqdn: %s", solver.presented[0])
	}

	// The bundle must be a usable self-signed cert covering the requested names
	// with a ~90-day validity.
	block, _ := pem.Decode(res.CertPEM)
	if block == nil {
		t.Fatal("cert PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	if err := cert.VerifyHostname("www.example.com"); err != nil {
		t.Fatalf("cert should cover SAN www.example.com: %v", err)
	}
	if d := time.Until(cert.NotAfter); d < 80*24*time.Hour || d > 100*24*time.Hour {
		t.Fatalf("unexpected validity window: %s", d)
	}
	if block, _ := pem.Decode(res.KeyPEM); block == nil {
		t.Fatal("key PEM did not decode")
	}
}

func TestDryRunACMEWildcard(t *testing.T) {
	solver := &recordingSolver{}
	c := NewDryRunACMEClient(nil, DryRunFailNone)
	res, err := c.ObtainViaDNS01(context.Background(), []string{"*.example.com"}, solver)
	if err != nil {
		t.Fatalf("ObtainViaDNS01: %v", err)
	}
	// The challenge name strips the wildcard label.
	if solver.presented[0] != "_acme-challenge.example.com" {
		t.Fatalf("unexpected wildcard challenge fqdn: %s", solver.presented[0])
	}
	block, _ := pem.Decode(res.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if err := cert.VerifyHostname("anything.example.com"); err != nil {
		t.Fatalf("wildcard cert should cover subdomain: %v", err)
	}
}

func TestDryRunACMERateLimit(t *testing.T) {
	c := NewDryRunACMEClient(nil, DryRunFailRateLimit)
	_, err := c.ObtainViaDNS01(context.Background(), []string{"app.example.com"}, &recordingSolver{})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("expected *RateLimitError, got %v", err)
	}
}

func TestDryRunACMEFailureModesCleanUp(t *testing.T) {
	for _, mode := range []string{DryRunFailChallenge, DryRunFailPropagation} {
		t.Run(mode, func(t *testing.T) {
			solver := &recordingSolver{}
			c := NewDryRunACMEClient(nil, mode)
			_, err := c.ObtainViaDNS01(context.Background(), []string{"app.example.com"}, solver)
			if err == nil {
				t.Fatalf("mode %q should return an error", mode)
			}
			if !strings.Contains(err.Error(), "dryrun") {
				t.Fatalf("error should be tagged dryrun: %v", err)
			}
			// Even on failure, the presented challenge must be cleaned up.
			if len(solver.cleaned) != 1 {
				t.Fatalf("expected cleanup after failure, got %d", len(solver.cleaned))
			}
		})
	}
}
