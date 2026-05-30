package tls

import (
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/acme"
)

// ErrNoTXTSupport is returned when DNS-01 issuance is attempted against a DNS
// provider that does not support TXT records. The caller is expected to fall
// back cleanly to the Caddy/HTTP-01 mode (§7) rather than failing silently.
var ErrNoTXTSupport = errors.New("tls: dns provider does not support TXT records (DNS-01 unavailable, fall back to HTTP-01)")

// ErrACMENotConfigured is returned by the ACME client when issuance is attempted
// before the operator has set the ACME contact email (acme_email). It is NOT a
// failure to retry or audit per host: the renewer treats it as "skip quietly
// until configured", so a fresh install with no ACME email doesn't spam the log
// on every scan. The dashboard surfaces the missing config as a warning instead.
var ErrACMENotConfigured = errors.New("tls: ACME not configured — set the ACME contact email in Settings to enable certificate issuance")

// RateLimitError is a special error surfaced when Let's Encrypt (or any ACME CA)
// responds with a 429 / rateLimited problem. It carries the human-verification
// unblock link so the dashboard can render it as a clickable action (§7). Callers
// detect it with errors.As(err, &tls.RateLimitError{}).
type RateLimitError struct {
	// Detail is the CA's human-readable explanation of the limit hit.
	Detail string
	// UnblockURL is the link the CA provides for human verification / unblocking
	// (the ProblemDetails Instance field). Empty if the CA gave none.
	UnblockURL string
	// Err is the underlying ACME error, preserved for unwrapping.
	Err error
}

func (e *RateLimitError) Error() string {
	if e.UnblockURL != "" {
		return fmt.Sprintf("tls: ACME rate limited: %s (unblock: %s)", e.Detail, e.UnblockURL)
	}
	return fmt.Sprintf("tls: ACME rate limited: %s", e.Detail)
}

func (e *RateLimitError) Unwrap() error { return e.Err }

// classifyACMEError inspects an error returned by the ACME client. If it is a
// rate-limit / 429 problem it is wrapped into a *RateLimitError carrying the
// unblock link; otherwise the original error is returned unchanged.
//
// It recognizes lego's *acme.ProblemDetails (the structured form) and falls back
// to a plain HTTP-429 status check, so a hand-written fake ACME client can
// reproduce the path without importing lego internals.
func classifyACMEError(err error) error {
	if err == nil {
		return nil
	}

	var pd *acme.ProblemDetails
	if errors.As(err, &pd) {
		if isRateLimited(pd) {
			return &RateLimitError{
				Detail:     pd.Detail,
				UnblockURL: pd.Instance,
				Err:        err,
			}
		}
		return err
	}

	// Fakes / non-lego callers can signal a rate limit via this lightweight
	// interface without depending on lego's concrete problem type.
	var rl interface {
		IsRateLimited() bool
		UnblockLink() string
		RateLimitDetail() string
	}
	if errors.As(err, &rl) && rl.IsRateLimited() {
		return &RateLimitError{
			Detail:     rl.RateLimitDetail(),
			UnblockURL: rl.UnblockLink(),
			Err:        err,
		}
	}

	return err
}

func isRateLimited(pd *acme.ProblemDetails) bool {
	return pd.HTTPStatus == 429 || pd.Type == acme.RateLimitedErr
}
