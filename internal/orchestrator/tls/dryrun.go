package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"
)

// Dry-run ACME failure modes. They let a developer exercise the issuance error
// paths (retry/backoff, rate-limit surfacing, challenge handling) without waiting
// for a real CA to fail (#93). Selected via NP_DRY_RUN_FAIL.
const (
	// DryRunFailNone issues a self-signed certificate successfully.
	DryRunFailNone = ""
	// DryRunFailRateLimit returns a *RateLimitError, as if the CA replied 429.
	DryRunFailRateLimit = "ratelimit"
	// DryRunFailChallenge simulates a failed DNS-01 challenge validation.
	DryRunFailChallenge = "challenge"
	// DryRunFailPropagation simulates the challenge TXT never propagating.
	DryRunFailPropagation = "propagation"
)

// dryRunCertValidity mirrors a Let's Encrypt leaf lifetime (90 days) so the
// renewer's window math behaves the same as in production.
const dryRunCertValidity = 90 * 24 * time.Hour

// DryRunACMEClient is an ACMEClient that simulates DNS-01 issuance without
// contacting a real CA. It still drives the DNSSolver (present + clean up the
// _acme-challenge TXT) so the full DNS path is exercised — in full dry-run that
// lands in the in-memory DNS store; with real DNS it performs the same TXT
// dance a real validation would, minus the CA round trip. On success it returns
// a freshly minted self-signed certificate covering the requested names.
type DryRunACMEClient struct {
	logger   *slog.Logger
	failMode string
}

// NewDryRunACMEClient builds a dry-run ACME client. failMode is one of the
// DryRunFail* constants (an unknown value behaves as DryRunFailNone). A nil
// logger defaults to slog.Default().
func NewDryRunACMEClient(logger *slog.Logger, failMode string) *DryRunACMEClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &DryRunACMEClient{logger: logger, failMode: failMode}
}

// ObtainViaDNS01 simulates an ACME order: it presents and cleans up the
// challenge TXT records via the solver, optionally injects a failure, and
// otherwise returns a self-signed bundle for names.
func (c *DryRunACMEClient) ObtainViaDNS01(ctx context.Context, names []string, solver DNSSolver) (*CertResult, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("tls: dryrun: no names to issue")
	}

	c.logger.InfoContext(ctx, "dryrun ACME: simulating DNS-01 issuance (no CA contacted)",
		slog.String("primary", names[0]),
		slog.Int("names", len(names)),
		slog.String("fail_mode", c.failMode),
	)

	// A real CA returns the rate-limit 429 at order creation, before any
	// challenge — reproduce that ordering so the no-retry path is exercised.
	if c.failMode == DryRunFailRateLimit {
		return nil, &RateLimitError{
			Detail: "dryrun: simulated rate limit — too many certificates already issued for this name set",
		}
	}

	// Present the challenge for every name, then clean up — exactly the sequence
	// the real solver runs, so multi-step DNS flows are realistic. Cleanup is
	// deferred so it runs even on the simulated-failure paths below.
	presented := make([]challengePair, 0, len(names))
	defer func() {
		for _, p := range presented {
			if err := solver.CleanUp(ctx, p.fqdn, p.value); err != nil {
				c.logger.WarnContext(ctx, "dryrun ACME: challenge cleanup failed",
					slog.String("fqdn", p.fqdn), slog.Any("error", err))
			}
		}
	}()
	for _, name := range names {
		p := challengeFor(name)
		if err := solver.Present(ctx, p.fqdn, p.value); err != nil {
			return nil, fmt.Errorf("tls: dryrun: presenting challenge for %s: %w", name, err)
		}
		presented = append(presented, p)
	}

	switch c.failMode {
	case DryRunFailChallenge:
		return nil, fmt.Errorf("tls: dryrun: simulated DNS-01 challenge failure for %s", names[0])
	case DryRunFailPropagation:
		return nil, fmt.Errorf("tls: dryrun: simulated DNS propagation timeout for %s", names[0])
	}

	cert, key, err := selfSignedCert(names)
	if err != nil {
		return nil, fmt.Errorf("tls: dryrun: generating self-signed certificate: %w", err)
	}
	c.logger.InfoContext(ctx, "dryrun ACME: issued self-signed certificate",
		slog.String("primary", names[0]), slog.Duration("validity", dryRunCertValidity))
	return &CertResult{
		Host:    names[0],
		Names:   names,
		CertPEM: cert,
		KeyPEM:  key,
	}, nil
}

type challengePair struct {
	fqdn  string
	value string
}

// challengeFor synthesizes the _acme-challenge FQDN and a realistic-looking
// (deterministic) challenge value for a name, mirroring what lego would compute.
func challengeFor(name string) challengePair {
	base := strings.TrimPrefix(name, "*.")
	sum := sha256.Sum256([]byte("dryrun-keyauth:" + name))
	return challengePair{
		fqdn:  "_acme-challenge." + base,
		value: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// selfSignedCert mints an ECDSA P-256 self-signed certificate covering names,
// with a 90-day validity matching production leaves. Returned as PEM cert + key.
func selfSignedCert(names []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0], Organization: []string{"NurProxy dry-run"}},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(dryRunCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
