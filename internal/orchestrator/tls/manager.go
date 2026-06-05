package tls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// DefaultRenewWindow is how far ahead of expiry central renewal acts. A
// certificate is renewed once it is within this window of its NotAfter, i.e.
// at least 30 days before it expires (§7). This leaves a wide margin for the
// orchestrator to be down, for ACME rate limits, and for the re-push to reach
// an agent that is temporarily offline.
const DefaultRenewWindow = 30 * 24 * time.Hour

// DefaultRenewInterval is how often the renewal loop wakes up to scan for
// certificates entering the renew window. The window is large (30 days) so the
// scan cadence does not need to be tight; once a day is ample and cheap.
const DefaultRenewInterval = 12 * time.Hour

// Issuance retry policy. A single attempt is fragile: DNS-01 issuance crosses the
// public internet to the ACME CA, and a transient blip (TLS handshake timeout,
// packet loss, "no route to host" on a flaky uplink) fails the whole attempt —
// after which the on-create fast path would otherwise wait up to a full
// DefaultRenewInterval before trying again. Retrying a few times with exponential
// backoff turns an intermittently-reachable CA (observed ~50% success on a lossy
// link) into reliable issuance. Rate-limit and not-configured errors are NOT
// retried (they will not clear within this window; retrying only burns quota).
// vars (not consts) so tests can shrink the backoff; production never mutates them.
var (
	issueMaxAttempts = 4
	issueBaseBackoff = 2 * time.Second
	issueMaxBackoff  = 30 * time.Second
)

// RenewTarget is one certificate the renewer should re-issue: the host (primary
// FQDN), the full name set the existing cert covers, whether it is a wildcard,
// and the DNS provider plus decrypted config to drive DNS-01 against. The
// orchestrator resolves the provider per host (the renewer itself is
// provider-agnostic and DB-agnostic so it stays unit-testable).
type RenewTarget struct {
	// Host is the certificate's primary FQDN.
	Host string
	// Names is every DNS name the existing certificate covers (re-issued as-is so
	// SAN batching survives renewal). The primary is first.
	Names []string
	// IsWildcard echoes the stored cert's wildcard flag so the re-issue keeps the
	// same scope (and the same shared-key trade-off the operator opted into).
	IsWildcard bool
	// Provider is the DNS provider plugin for this host's zone.
	Provider provider.Provider
	// Config is the decrypted provider config (with the zone id merged in) used to
	// create the _acme-challenge TXT record.
	Config json.RawMessage
}

// RenewalStore is the seam the renewer uses to find work and persist results.
// The orchestrator implements it over its DB + zone/provider resolution; tests
// hand-write a fake. It is intentionally narrow so the renewer never touches the
// database directly.
type RenewalStore interface {
	// DueForRenewal returns the work the renewer should act on within window: both
	// existing certificates entering the renew window AND domains that need a
	// central-TLS certificate but have none yet (first issuance). Every target is
	// already resolved to its DNS provider. A host whose zone/provider can no
	// longer be resolved should be omitted (logged by the implementer) rather than
	// aborting the whole scan.
	DueForRenewal(ctx context.Context, window time.Duration) ([]RenewTarget, error)
	// TargetForHost resolves the issuance target for a single host on demand (the
	// on-create fast path): the host's zone/provider plus the name set. It returns
	// (nil, nil) when the host needs no central cert right now — unresolvable
	// zone/provider, a non-central TLS policy, or a current cert already on file —
	// so the caller treats it as a no-op.
	TargetForHost(ctx context.Context, host string) (*RenewTarget, error)
	// SaveRenewed persists a freshly issued bundle, overwriting the prior cert for
	// the host in place (the encrypted-at-rest store keys on host).
	SaveRenewed(ctx context.Context, res *CertResult, isWildcard bool) error
}

// Reloader is invoked after a certificate is renewed and saved, to re-push the
// new bundle to the agent(s) serving the host and trigger a reload. It rides the
// agent-initiated stream (the orchestrator never probes the agent inbound, §7):
// the implementer looks up which agent serves the host and calls the same
// instant-push path a config change uses, so the agent installs the new cert
// (InstallCerts) and reloads. A nil Reloader makes renewal store-only.
type Reloader interface {
	// RepushCertForHost re-pushes the renewed cert bundle for host to whichever
	// agent currently serves it. Best-effort: an offline agent picks the new cert
	// up on its next reconcile/reconnect, so a transient error here must not fail
	// the renewal (the new bundle is already stored).
	RepushCertForHost(ctx context.Context, host string) error
}

// AuditSink records renewal events to the orchestrator's audit log (every config
// change is audited with source + actor, invariant #5). A nil sink disables
// auditing (used in narrow tests).
type AuditSink interface {
	Audit(entityType, entityID, action, details string)
}

// Renewer runs central certificate renewal on a timer: it scans the store for
// certificates within the renew window, re-issues each via the central DNS-01
// Issuer, saves the new bundle encrypted at rest, then re-pushes + reloads the
// serving agent over its stream. It is the timed counterpart to first-issue
// (§7). Per-host scope and the wildcard flag are carried straight from the
// stored cert, so renewal never widens scope or silently turns a per-host cert
// into a wildcard.
type Renewer struct {
	store    RenewalStore
	issuer   *Issuer
	reloader Reloader
	audit    AuditSink
	logger   *slog.Logger

	window   time.Duration
	interval time.Duration
}

// RenewerConfig configures a Renewer. Zero values fall back to the defaults
// (DefaultRenewWindow / DefaultRenewInterval, slog.Default).
type RenewerConfig struct {
	Window   time.Duration
	Interval time.Duration
	Reloader Reloader
	Audit    AuditSink
	Logger   *slog.Logger
}

// NewRenewer builds a Renewer over the given store and issuer.
func NewRenewer(store RenewalStore, issuer *Issuer, cfg RenewerConfig) *Renewer {
	if cfg.Window <= 0 {
		cfg.Window = DefaultRenewWindow
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultRenewInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Renewer{
		store:    store,
		issuer:   issuer,
		reloader: cfg.Reloader,
		audit:    cfg.Audit,
		logger:   cfg.Logger,
		window:   cfg.Window,
		interval: cfg.Interval,
	}
}

// Start runs the renewal loop until ctx is canceled. It runs one scan
// immediately, then on the interval. It returns when ctx is done.
func (r *Renewer) Start(ctx context.Context) {
	if err := r.RunOnce(ctx); err != nil {
		r.logger.ErrorContext(ctx, "tls: initial renewal scan failed", slog.Any("error", err))
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.RunOnce(ctx); err != nil {
				r.logger.ErrorContext(ctx, "tls: renewal scan failed", slog.Any("error", err))
			}
		}
	}
}

// RunOnce executes a single renewal scan: re-issue every certificate within the
// renew window, save it, and re-push it to the serving agent. One host's failure
// is logged + audited but does not abort the rest of the scan (a transient ACME
// error or rate limit on one host must not block renewing the others).
func (r *Renewer) RunOnce(ctx context.Context) error {
	targets, err := r.store.DueForRenewal(ctx, r.window)
	if err != nil {
		return fmt.Errorf("tls: listing certificates due for renewal: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}

	r.logger.InfoContext(ctx, "tls: renewing certificates within window",
		slog.Int("count", len(targets)),
		slog.Duration("window", r.window),
	)

	var firstErr error
	for i := range targets {
		t := targets[i]
		if err := r.renewOne(ctx, t); err != nil {
			// ACME not configured yet: nothing to retry per host. Stop the scan
			// quietly — issuance resumes once the operator sets the contact email
			// (the dashboard surfaces that as a warning).
			if errors.Is(err, ErrACMENotConfigured) {
				r.logger.InfoContext(ctx, "tls: skipping issuance — ACME contact email not configured")
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
			r.logger.ErrorContext(ctx, "tls: renewal failed for host",
				slog.String("host", t.Host),
				slog.Any("error", err),
			)
			r.auditEvent("certificate", t.Host, "renew_failed", err.Error())
			continue
		}
	}
	return firstErr
}

// EnsureCertForHost issues, saves, and pushes a certificate for a single host on
// demand — the fast path so a freshly created central-TLS domain gets HTTPS in
// about a minute instead of waiting for the next scan. It is best-effort and
// idempotent: a host that needs no cert (non-central policy, unresolvable
// zone/provider, or a current cert already on file) is a no-op, and the periodic
// scan still covers anything this misses. Safe to call from a goroutine.
func (r *Renewer) EnsureCertForHost(ctx context.Context, host string) error {
	if host == "" {
		return nil
	}
	target, err := r.store.TargetForHost(ctx, host)
	if err != nil {
		return fmt.Errorf("tls: resolving issue target for %s: %w", host, err)
	}
	if target == nil {
		return nil // nothing to issue (no central cert needed / already have one)
	}
	r.logger.InfoContext(ctx, "tls: issuing certificate on demand", slog.String("host", host))
	if err := r.renewOne(ctx, *target); err != nil {
		// Not configured yet: a no-op, not a failure — the periodic scan retries
		// once the operator sets the contact email.
		if errors.Is(err, ErrACMENotConfigured) {
			r.logger.InfoContext(ctx, "tls: on-demand issuance skipped — ACME contact email not configured", slog.String("host", host))
			return nil
		}
		r.auditEvent("certificate", host, "issue_failed", err.Error())
		return err
	}
	return nil
}

// issueWithRetry obtains a certificate, retrying transient failures with
// exponential backoff (issueMaxAttempts / issueBaseBackoff / issueMaxBackoff).
// It does NOT retry a CA rate limit (it will not clear within the backoff window
// and retrying burns quota) nor ErrACMENotConfigured (nothing to retry until the
// operator configures the contact email); both are returned immediately. The
// context bounds total time, so a caller-imposed deadline still caps the work.
func (r *Renewer) issueWithRetry(ctx context.Context, req IssueRequest, p provider.Provider, config json.RawMessage) (*CertResult, error) {
	var lastErr error
	for attempt := 1; attempt <= issueMaxAttempts; attempt++ {
		res, err := r.issuer.Issue(ctx, req, p, config)
		if err == nil {
			return res, nil
		}
		lastErr = err

		// Permanent / expected conditions: do not retry.
		if errors.Is(err, ErrACMENotConfigured) {
			return nil, err
		}
		var rl *RateLimitError
		if asRateLimit(err, &rl) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, err
		}
		if attempt == issueMaxAttempts {
			break
		}

		backoff := issueBaseBackoff << (attempt - 1)
		if backoff > issueMaxBackoff {
			backoff = issueMaxBackoff
		}
		r.logger.WarnContext(ctx, "tls: issuance attempt failed, retrying",
			slog.String("host", req.Host),
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", issueMaxAttempts),
			slog.Duration("backoff", backoff),
			slog.Any("error", err),
		)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, lastErr
}

// renewOne re-issues, saves, and re-pushes a single certificate. The re-issue
// reuses the exact name set and wildcard flag of the existing cert so scope never
// drifts. A reload-push failure is non-fatal: the new bundle is already stored
// and an offline agent picks it up on reconnect.
func (r *Renewer) renewOne(ctx context.Context, t RenewTarget) error {
	if t.Host == "" {
		return errors.New("tls: renew target has no host")
	}

	req := IssueRequest{Host: t.Host, Wildcard: t.IsWildcard}
	// Preserve SANs: everything in Names beyond the computed primary becomes a SAN
	// so the renewed cert covers exactly what the old one did.
	req.SANs = sansFromNames(t.Host, t.IsWildcard, t.Names)

	res, err := r.issueWithRetry(ctx, req, t.Provider, t.Config)
	if err != nil {
		return fmt.Errorf("re-issuing %s: %w", t.Host, err)
	}

	if err := r.store.SaveRenewed(ctx, res, t.IsWildcard); err != nil {
		return fmt.Errorf("saving renewed %s: %w", t.Host, err)
	}
	r.auditEvent("certificate", t.Host, "renewed", fmt.Sprintf("re-issued %d name(s), re-pushing to serving agent", len(res.Names)))

	if r.reloader != nil {
		if err := r.reloader.RepushCertForHost(ctx, t.Host); err != nil {
			// Non-fatal: the cert is stored; the agent will pick it up on its next
			// reconcile/reconnect. Log + audit so it is visible.
			r.logger.WarnContext(ctx, "tls: re-push of renewed cert failed (stored; agent will sync later)",
				slog.String("host", t.Host),
				slog.Any("error", err),
			)
			r.auditEvent("certificate", t.Host, "renew_repush_deferred", err.Error())
		}
	}
	return nil
}

// sansFromNames returns the SAN list (everything except the primary name) for a
// re-issue, so renewal reproduces the original cert's coverage. The primary is
// the host itself, or *.<host> for a wildcard.
func sansFromNames(host string, wildcard bool, names []string) []string {
	primary := host
	if wildcard {
		primary = "*." + trimWildcard(host)
	}
	sans := make([]string, 0, len(names))
	for _, n := range names {
		if n == primary {
			continue
		}
		sans = append(sans, n)
	}
	if len(sans) == 0 {
		return nil
	}
	return sans
}

func trimWildcard(host string) string {
	if len(host) > 2 && host[0] == '*' && host[1] == '.' {
		return host[2:]
	}
	return host
}

func (r *Renewer) auditEvent(entityType, entityID, action, details string) {
	if r.audit != nil {
		r.audit.Audit(entityType, entityID, action, details)
	}
}
