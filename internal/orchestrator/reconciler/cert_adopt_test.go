package reconciler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestFirstIssuanceWaitsForAdoption checks that a new central-TLS domain whose
// serving agent reports an adoptable certificate on disk gets no ACME order
// during the adoption grace period (#80), and that anything else still issues.
func TestFirstIssuanceWaitsForAdoption(t *testing.T) {
	now := time.Now().UTC()
	adoptable := models.DiscoveredCert{
		Fingerprint: strings.Repeat("ab", 32), Names: []string{"*.example.com"}, Source: "certbot",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
		CertPath: "/etc/letsencrypt/live/example.com/fullchain.pem",
	}
	unreadable := adoptable
	unreadable.Error = "private key not readable by the agent: permission denied"

	tests := []struct {
		name      string
		certs     []models.DiscoveredCert
		wantIssue bool
	}{
		{name: "adoptable certificate holds issuance", certs: []models.DiscoveredCert{adoptable}, wantIssue: false},
		{name: "unadoptable certificate does not", certs: []models.DiscoveredCert{unreadable}, wantIssue: true},
		{name: "nothing on disk", wantIssue: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registerMockProvider(t)
			d := testDB(t)
			setupScenario(t, d)
			if err := d.UpdateAgentDetection("agent-1", &models.ProxyDetection{Installed: true, DiscoveredCerts: tc.certs}); err != nil {
				t.Fatal(err)
			}
			store := NewCertRenewalStore(d)

			targets, err := store.DueForRenewal(context.Background(), tls.DefaultRenewWindow)
			if err != nil {
				t.Fatalf("DueForRenewal: %v", err)
			}
			if got := len(targets) == 1; got != tc.wantIssue {
				t.Errorf("scan targets = %+v, want issuance %v", targets, tc.wantIssue)
			}
			one, err := store.TargetForHost(context.Background(), "app.example.com")
			if err != nil {
				t.Fatalf("TargetForHost: %v", err)
			}
			if got := one != nil; got != tc.wantIssue {
				t.Errorf("TargetForHost = %+v, want issuance %v", one, tc.wantIssue)
			}
		})
	}
}

// TestWatchAdoptionHolds_issuesWhenHoldEnds checks that a held host is issued
// as soon as its hold ends, here because the operator skipped adoption,
// rather than at the next periodic renewal scan.
func TestWatchAdoptionHolds_issuesWhenHoldEnds(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	_, _, _, _, dom := setupScenario(t, d)
	now := time.Now().UTC()
	if err := d.UpdateAgentDetection("agent-1", &models.ProxyDetection{DiscoveredCerts: []models.DiscoveredCert{{
		Fingerprint: strings.Repeat("ab", 32), Names: []string{"app.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
	}}}); err != nil {
		t.Fatal(err)
	}
	store := NewCertRenewalStore(d)
	if held := store.heldHosts(now); !held["app.example.com"] {
		t.Fatalf("heldHosts = %v, want app.example.com", held)
	}

	issued := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.WatchAdoptionHolds(ctx, 20*time.Millisecond, func(_ context.Context, host string) error {
		issued <- host
		return nil
	})
	select {
	case host := <-issued:
		t.Fatalf("issued %q while still held", host)
	case <-time.After(100 * time.Millisecond):
	}
	if err := d.SkipCertAdoption(dom.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case host := <-issued:
		if host != "app.example.com" {
			t.Errorf("issued %q", host)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no issuance after the hold ended")
	}
	if held := store.heldHosts(time.Now().UTC()); len(held) != 0 {
		t.Errorf("skipped domain still held: %v", held)
	}
}

// TestAwaitingAdoption_graceEnds checks the hold is bounded by the domain's age.
func TestAwaitingAdoption_graceEnds(t *testing.T) {
	registerMockProvider(t)
	d := testDB(t)
	_, _, _, _, dom := setupScenario(t, d)
	now := time.Now().UTC()
	if err := d.UpdateAgentDetection("agent-1", &models.ProxyDetection{DiscoveredCerts: []models.DiscoveredCert{{
		Fingerprint: strings.Repeat("ab", 32), Names: []string{"app.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
	}}}); err != nil {
		t.Fatal(err)
	}
	store := NewCertRenewalStore(d)

	young := *dom
	young.CreatedAt = now.Add(-time.Minute)
	if !store.awaitingAdoption(&young, "app.example.com", now) {
		t.Error("a new domain should wait for adoption")
	}
	old := *dom
	old.CreatedAt = now.Add(-tls.AdoptionGrace - time.Minute)
	if store.awaitingAdoption(&old, "app.example.com", now) {
		t.Error("the hold must end after the grace period")
	}
	certOnly := young
	certOnly.ServerID = ""
	if store.awaitingAdoption(&certOnly, "app.example.com", now) {
		t.Error("a domain without a serving agent has nothing to adopt from")
	}
}
