// Package webhook delivers notifier events as JSON POSTs to an operator-
// configured URL (#72 MVP). Optional HMAC-SHA256 signing lets the receiver
// authenticate the payload; short retries smooth transient receiver blips.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/notifier"
)

// SignatureHeader carries the hex HMAC-SHA256 of the request body, keyed with
// the operator's webhook secret ("sha256=<hex>"). Absent when no secret is set.
const SignatureHeader = "X-NurProxy-Signature"

// requestTimeout bounds one delivery attempt.
const requestTimeout = 10 * time.Second

// maxAttempts is how often a delivery is tried before the event is dropped
// (the dispatcher logs the drop). Webhooks are best-effort; a receiver that
// is down for longer misses events by design.
const maxAttempts = 3

// Sink posts events to a webhook URL. Config is resolved lazily per delivery
// so settings changes (URL, secret) take effect without a restart — and an
// empty URL simply skips delivery (the "notifier off" state).
type Sink struct {
	// resolve returns the current (url, secret). Empty url disables delivery.
	resolve func() (url, secret string)
	client  *http.Client
}

// New builds a webhook sink. resolve is consulted on every delivery.
func New(resolve func() (url, secret string)) *Sink {
	return &Sink{
		resolve: resolve,
		client:  &http.Client{Timeout: requestTimeout},
	}
}

// Notify posts the event as JSON. A 2xx response is success; anything else is
// retried (with a short pause) up to maxAttempts within ctx.
func (s *Sink) Notify(ctx context.Context, ev notifier.Event) error {
	url, secret := s.resolve()
	if strings.TrimSpace(url) == "" {
		return nil // no webhook configured — the disabled state, not an error
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhook: encoding event: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := s.post(ctx, url, secret, body); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
			continue
		}
		return nil
	}
	return lastErr
}

func (s *Sink) post(ctx context.Context, url, secret string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nurproxy-webhook")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: delivering: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: receiver returned %d", resp.StatusCode)
	}
	return nil
}
