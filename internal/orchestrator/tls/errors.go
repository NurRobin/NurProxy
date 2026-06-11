package tls

import (
	"errors"
	"fmt"
	"regexp"
	"time"

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
	// RetryAfter is when the CA says issuance may be retried, parsed from the
	// Detail ("...retry after 2026-06-06 10:08:13 UTC..."). Nil when the CA gave
	// no parseable timestamp. The dashboard can render this as a friendly
	// "retry after <date>" instead of the raw CA sentence (§7).
	RetryAfter *time.Time
	// Err is the underlying ACME error, preserved for unwrapping.
	Err error
}

func (e *RateLimitError) Error() string {
	msg := fmt.Sprintf("tls: ACME rate limited: %s", e.Detail)
	if e.RetryAfter != nil {
		msg += fmt.Sprintf(" (retry after %s)", e.RetryAfter.UTC().Format("2006-01-02 15:04 MST"))
	}
	if e.UnblockURL != "" {
		msg += fmt.Sprintf(" (unblock: %s)", e.UnblockURL)
	}
	return msg
}

// retryAfterRe extracts the "retry after <timestamp> UTC" instant Let's Encrypt
// embeds in its rate-limit detail strings, e.g.
// "...retry after 2026-06-06 10:08:13 UTC: see https://...".
var retryAfterRe = regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC`)

// parseRetryAfter pulls the retry-after instant out of a CA rate-limit detail
// string, returning nil when there is none (other limit types omit it).
func parseRetryAfter(detail string) *time.Time {
	m := retryAfterRe.FindStringSubmatch(detail)
	if m == nil {
		return nil
	}
	t, err := time.Parse("2006-01-02 15:04:05", m[1])
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
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
				RetryAfter: parseRetryAfter(pd.Detail),
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
			RetryAfter: parseRetryAfter(rl.RateLimitDetail()),
			Err:        err,
		}
	}

	return err
}

func isRateLimited(pd *acme.ProblemDetails) bool {
	return pd.HTTPStatus == 429 || pd.Type == acme.RateLimitedErr
}
