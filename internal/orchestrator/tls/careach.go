package tls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Central TLS issues certificates FROM the orchestrator, so it depends entirely
// on the orchestrator host's egress to the ACME CA (#91). When that path is
// broken (firewalled VM, PMTU blackhole, DNS failure) every issuance fails with
// a generic timeout that looks like per-domain flakiness — while the agents'
// internet is fine. This file makes that failure mode first-class: a periodic
// reachability probe of the ACME directory surfaced in /health, and a
// classifier so issuance errors caused by CA egress are audited distinctly.

// caProbeTimeout bounds one reachability probe. Generous enough for a slow but
// working path; a PMTU-blackholed handshake hangs far longer than this.
const caProbeTimeout = 10 * time.Second

// DefaultCAProbeInterval is how often the background prober re-checks the CA.
// Reachability rarely flaps faster, and each probe is one tiny GET.
const DefaultCAProbeInterval = 10 * time.Minute

// CAStatus is one reachability observation of the ACME directory endpoint.
type CAStatus struct {
	// OK reports whether the directory answered a well-formed HTTP response.
	OK bool
	// Detail is the failure description when OK is false ("" when reachable).
	Detail string
	// URL is the directory endpoint that was probed.
	URL string
	// CheckedAt is when this observation was made; zero before the first probe.
	CheckedAt time.Time
}

// CAProber periodically checks whether the orchestrator can reach the ACME
// directory endpoint and caches the result for the health endpoint. The
// directory URL is resolved lazily on every probe (like issuance resolves it
// from settings), so switching production/staging post-boot is picked up.
type CAProber struct {
	// resolveURL returns the directory URL to probe; empty means LE production.
	resolveURL func() string
	client     *http.Client

	mu     sync.RWMutex
	status CAStatus
}

// NewCAProber builds a prober. resolveURL may return "" for LE production.
func NewCAProber(resolveURL func() string) *CAProber {
	if resolveURL == nil {
		resolveURL = func() string { return "" }
	}
	return &CAProber{
		resolveURL: resolveURL,
		client:     &http.Client{Timeout: caProbeTimeout},
	}
}

// Status returns the last observation (zero-value CAStatus before any probe).
func (p *CAProber) Status() CAStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

// Probe performs one reachability check and records + returns the result. Any
// well-formed HTTP response counts as reachable — even a 4xx/5xx proves the
// network path works; issuance-level problems are the issuer's to report.
func (p *CAProber) Probe(ctx context.Context) CAStatus {
	dirURL := strings.TrimSpace(p.resolveURL())
	if dirURL == "" {
		dirURL = LEDirectoryProduction
	}
	st := CAStatus{URL: dirURL, CheckedAt: time.Now().UTC()}

	ctx, cancel := context.WithTimeout(ctx, caProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	if err != nil {
		st.Detail = fmt.Sprintf("invalid ACME directory URL: %v", err)
	} else if resp, rErr := p.client.Do(req); rErr != nil {
		st.Detail = fmt.Sprintf("cannot reach ACME CA: %v (orchestrator egress problem — agents are unaffected)", rErr)
	} else {
		_ = resp.Body.Close()
		st.OK = true
	}

	p.mu.Lock()
	p.status = st
	p.mu.Unlock()
	return st
}

// Start probes once immediately and then on every interval until ctx is done.
// Interval <= 0 falls back to DefaultCAProbeInterval.
func (p *CAProber) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCAProbeInterval
	}
	p.Probe(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Probe(ctx)
		}
	}
}

// IsCAUnreachable reports whether an issuance error is a network-level failure
// to reach the ACME CA — as opposed to an ACME-protocol error (rate limit,
// validation failure), which proves the CA WAS reached. Detection is
// deliberately conservative: net/url transport errors, net.Error timeouts, DNS
// failures, and the handful of connect-failure strings Go's dialer produces.
func IsCAUnreachable(err error) bool {
	if err == nil {
		return false
	}
	// Rate limits and not-configured are protocol/config level, never egress.
	var rl *RateLimitError
	if errors.As(err, &rl) || errors.Is(err, ErrACMENotConfigured) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	var nErr net.Error
	if errors.As(err, &nErr) && nErr.Timeout() {
		return true
	}
	msg := err.Error()
	for _, sig := range []string{
		"TLS handshake timeout",
		"no route to host",
		"connection refused",
		"i/o timeout",
		"no such host",
		"network is unreachable",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}
