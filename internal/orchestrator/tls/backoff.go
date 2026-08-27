package tls

import (
	"math/rand/v2"
	"time"
)

// Rate-limit backoff policy (#70). Distinct from the transient-retry backoff in
// issueWithRetry (seconds, within one attempt): this schedules the NEXT scan
// attempt after the CA said "rate limited", so the unit is hours. The 12h scan
// interval means anything below it only takes effect once; growing 1h → 24h
// keeps early retries plausible (per-hostname limits clear within the hour)
// while a hard weekly limit stops burning quota after a few attempts. vars so
// tests can shrink them; production never mutates them.
var (
	rateLimitBaseBackoff = 1 * time.Hour
	rateLimitMaxBackoff  = 24 * time.Hour
)

// NextRateLimitBackoff computes when issuance for a host may be retried after
// its attempts-th consecutive rate limit (attempts >= 1): now + min(base*2^(n-1),
// cap), plus up to 10% jitter so hosts limited together do not retry together.
// When the CA supplied a later retry-after instant, that wins — retrying before
// it is guaranteed to fail and burn quota.
func NextRateLimitBackoff(now time.Time, attempts int, retryAfter *time.Time) time.Time {
	if attempts < 1 {
		attempts = 1
	}
	d := rateLimitBaseBackoff
	for i := 1; i < attempts && d < rateLimitMaxBackoff; i++ {
		d *= 2
	}
	if d > rateLimitMaxBackoff {
		d = rateLimitMaxBackoff
	}
	d += time.Duration(rand.Int64N(int64(d) / 10))
	next := now.Add(d)
	if retryAfter != nil && retryAfter.After(next) {
		next = *retryAfter
	}
	return next
}
