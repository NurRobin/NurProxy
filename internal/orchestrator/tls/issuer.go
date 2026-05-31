// Package tls issues TLS certificates centrally via DNS-01 against the
// already-configured DNS provider and stores them encrypted at rest (§7). The
// orchestrator holds the DNS credentials, creates the _acme-challenge.<host> TXT
// record through the same provider it uses for records, obtains the cert+key
// (lego as a library), and pushes the bundle down the agent-initiated stream.
//
// The ACME interaction is abstracted behind the ACMEClient seam so issuance
// orchestration is unit-testable without real network or a real CA: the lego
// implementation lives in lego.go, while tests hand-write a fake.
package tls

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// WildcardSharedKeyWarning is the operator-facing warning surfaced whenever a
// wildcard certificate is requested. Per-host certs are the default (§7); a
// wildcard is opt-in precisely because it places the SAME private key on every
// agent that serves any host under the wildcard — a wider blast radius if any
// one of those agents is compromised. The UI shows this on the opt-in toggle and
// the issuer logs + audits it on every wildcard issuance/renewal.
const WildcardSharedKeyWarning = "wildcard certificate: the same private key is installed on every agent serving any host under this wildcard — a compromise of one agent exposes the key for all of them; prefer per-host certificates unless you specifically need a wildcard"

// IssueRequest describes a single certificate to obtain.
type IssueRequest struct {
	// Host is the primary FQDN the certificate must cover, e.g. "app.example.com".
	Host string
	// SANs are additional names to include on the same certificate (batching is
	// the escape hatch for LE rate limits, §7). Optional.
	SANs []string
	// Wildcard requests a *.<host> certificate. Opt-in only: the caller is
	// responsible for surfacing the shared-private-key warning (§7).
	Wildcard bool
}

// Names returns every DNS name the certificate should cover, primary first.
func (r IssueRequest) Names() []string {
	primary := r.Host
	if r.Wildcard {
		primary = "*." + strings.TrimPrefix(r.Host, "*.")
	}
	names := make([]string, 0, 1+len(r.SANs))
	names = append(names, primary)
	names = append(names, r.SANs...)
	return names
}

// CertResult is the issued material: leaf+chain certificate and its private key,
// both PEM-encoded. The key is sensitive and must be encrypted at rest (Store).
type CertResult struct {
	// Host is the primary FQDN (echoes the request).
	Host string
	// Names are all DNS names the certificate covers.
	Names []string
	// CertPEM is the leaf certificate plus issuer chain in PEM form.
	CertPEM []byte
	// KeyPEM is the private key in PEM form (sensitive).
	KeyPEM []byte
}

// ACMEClient is the seam between issuance orchestration and the real ACME CA.
// The production implementation (newLegoClient) wraps lego; tests hand-write a
// fake. ObtainViaDNS01 is expected to install the TXT challenge via the provided
// DNSSolver, drive the ACME order, and return the issued material. A 429 /
// rate-limit response should be returned as an error that classifyACMEError can
// recognize (lego's *acme.ProblemDetails, or the lightweight rate-limit
// interface) so it surfaces as a *RateLimitError.
type ACMEClient interface {
	ObtainViaDNS01(ctx context.Context, names []string, solver DNSSolver) (*CertResult, error)
}

// DNSSolver presents and cleans up the _acme-challenge.<host> TXT records an
// ACME DNS-01 challenge requires. It is implemented by providerSolver, which
// drives a provider.Provider; the ACMEClient calls it during the order.
type DNSSolver interface {
	// Present creates the TXT record fqdn -> value (e.g.
	// _acme-challenge.app.example.com -> "<base64 keyauth digest>").
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes the TXT record created by Present.
	CleanUp(ctx context.Context, fqdn, value string) error
}

// Issuer orchestrates central DNS-01 issuance. It verifies the DNS provider can
// create TXT records (else ErrNoTXTSupport, the clean fallback signal), builds a
// DNSSolver around that provider, and delegates the ACME flow to the seam.
type Issuer struct {
	acme   ACMEClient
	logger *slog.Logger
}

// NewIssuer constructs an Issuer over the given ACME client. A nil logger
// defaults to slog.Default().
func NewIssuer(acme ACMEClient, logger *slog.Logger) *Issuer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Issuer{acme: acme, logger: logger}
}

// Issue obtains a certificate for req via DNS-01 using dnsProvider (decrypted
// provider record + its JSON config). If the provider cannot create TXT records
// it returns ErrNoTXTSupport without touching the CA, so the caller can fall
// back to Caddy/HTTP-01 cleanly. A CA rate limit is surfaced as *RateLimitError.
func (i *Issuer) Issue(ctx context.Context, req IssueRequest, p provider.Provider, config json.RawMessage) (*CertResult, error) {
	if req.Host == "" {
		return nil, fmt.Errorf("tls: issue request has no host")
	}

	info := p.Info()
	if !info.SupportsTXT() {
		i.logger.WarnContext(ctx, "dns provider lacks TXT support; DNS-01 unavailable, caller must fall back to HTTP-01",
			slog.String("provider", info.ID),
			slog.String("host", req.Host),
		)
		return nil, fmt.Errorf("provider %q: %w", info.ID, ErrNoTXTSupport)
	}

	// Per-host is the default; a wildcard is opt-in and carries an explicit
	// shared-private-key warning (§7). Surface it on every wildcard issuance so it
	// is never silent — logged here and audited by the caller.
	if req.Wildcard {
		i.logger.WarnContext(ctx, "issuing wildcard certificate (opt-in)",
			slog.String("host", req.Host),
			slog.String("warning", WildcardSharedKeyWarning),
		)
	}

	names := req.Names()
	solver := &providerSolver{
		provider:  p,
		config:    config,
		logger:    i.logger,
		createdID: make(map[string]string),
	}

	i.logger.InfoContext(ctx, "issuing certificate via DNS-01",
		slog.String("provider", info.ID),
		slog.String("host", req.Host),
		slog.Int("names", len(names)),
	)

	res, err := i.acme.ObtainViaDNS01(ctx, names, solver)
	if err != nil {
		err = classifyACMEError(err)
		var rl *RateLimitError
		if asRateLimit(err, &rl) {
			i.logger.ErrorContext(ctx, "ACME rate limited",
				slog.String("host", req.Host),
				slog.String("unblock_url", rl.UnblockURL),
			)
		}
		return nil, fmt.Errorf("tls: obtaining certificate for %s: %w", req.Host, err)
	}

	if res.Host == "" {
		res.Host = req.Host
	}
	if len(res.Names) == 0 {
		res.Names = names
	}
	return res, nil
}

// asRateLimit is a thin errors.As wrapper kept here so issuer.go does not need to
// import errors solely for the type assertion in logging.
func asRateLimit(err error, target **RateLimitError) bool {
	for e := err; e != nil; {
		if rl, ok := e.(*RateLimitError); ok {
			*target = rl
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
