package reconciler

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/provider/dryrun"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// CertRenewalStore adapts the orchestrator DB + zone/provider resolution to the
// tls.RenewalStore seam, so the central Renewer can find certificates entering
// the renew window and persist re-issued bundles without importing the DB
// itself. It resolves each due certificate's host to the DNS provider whose zone
// it lives in (the same provider used to create its A/CNAME records), which is
// exactly the provider DNS-01 must drive to renew it.
type CertRenewalStore struct {
	db *db.DB
	// dnsDryRun wraps the resolved DNS provider in the sandbox decorator so the
	// renewer's DNS-01 challenge runs against the in-memory store (#93).
	dnsDryRun bool
}

// NewCertRenewalStore builds the store adapter over the given DB.
func NewCertRenewalStore(database *db.DB) *CertRenewalStore {
	return &CertRenewalStore{db: database}
}

// SetDryRunDNS toggles DNS sandbox mode for resolved providers, matching the
// reconciler so the renewer never performs real DNS calls in dry-run.
func (s *CertRenewalStore) SetDryRunDNS(on bool) { s.dnsDryRun = on }

// DueForRenewal returns the issuance work for one scan: existing certificates
// within window of expiry (renewal) PLUS central-TLS domains that have no cert
// yet (first issuance, §7 — the timed counterpart the renewer was always meant
// to drive). Each target is resolved to the DNS provider for its zone. A host
// whose zone/provider can no longer be resolved is logged and skipped (never
// aborting the whole scan) — its host may have been deleted, and there is nothing
// to issue against.
func (s *CertRenewalStore) DueForRenewal(_ context.Context, window time.Duration) ([]tls.RenewTarget, error) {
	zones, err := s.db.ListZones()
	if err != nil {
		return nil, fmt.Errorf("listing zones for renewal resolution: %w", err)
	}

	certs, err := s.db.CertificatesDueForRenewal(window)
	if err != nil {
		return nil, fmt.Errorf("listing certificates due for renewal: %w", err)
	}

	domains, dErr := s.db.ListDomains(db.DomainFilter{})
	if dErr != nil {
		return nil, fmt.Errorf("listing domains for renewal resolution: %w", dErr)
	}
	zoneNames := make(map[string]string, len(zones))
	for i := range zones {
		zoneNames[zones[i].ID] = zones[i].Name
	}

	// centralHosts is the set of FQDNs a stored cert can currently be consumed
	// for: every non-deleting domain that resolves to the host AND wants central
	// TLS (the same host→domain matching gatherCerts uses, and the same policy
	// resolution the renderers use). It gates the renewal pass below.
	centralHosts := make(map[string]bool)
	for i := range domains {
		dom := &domains[i]
		if dom.Status == models.DomainStatusDeleting {
			continue
		}
		zoneName, ok := zoneNames[dom.ZoneID]
		if !ok {
			continue
		}
		if caddygen.TLSPolicyForDomain(*dom) != proxymodel.TLSPolicyCentral {
			continue
		}
		centralHosts[dom.FQDN(zoneName)] = true
	}

	var targets []tls.RenewTarget
	seen := make(map[string]bool)

	// 1) Existing certs entering the renew window — re-issue keeping the exact name
	//    set and wildcard scope. A cert with no current central-TLS consumer is
	//    orphaned (its domain was deleted or switched policy): skip it rather than
	//    drive ACME forever for a host nobody serves. Skip, never delete — cert
	//    removal belongs to the teardown path, not the renewer.
	for i := range certs {
		c := &certs[i]
		if !certHasCentralConsumer(c, centralHosts) {
			log.Printf("reconciler: renewal: no central-TLS domain consumes cert host %q, skipping renewal", c.Host)
			continue
		}
		t, ok := s.resolveTarget(c.Host, append([]string(nil), c.Names...), c.IsWildcard, zones)
		if !ok {
			log.Printf("reconciler: renewal: cannot resolve zone/provider for cert host %q, skipping", c.Host)
			continue
		}
		targets = append(targets, t)
		seen[c.Host] = true
	}

	// 2) Central-TLS domains with no cert yet — first issuance. Without this a brand
	//    new domain would never get a cert (the file backends then render plaintext;
	//    built-in Caddy hides it via self-ACME). Skip domains being deleted and any
	//    host already covered by the renewal pass above.
	for i := range domains {
		dom := &domains[i]
		if dom.Status == models.DomainStatusDeleting {
			continue
		}
		zoneName, ok := zoneNames[dom.ZoneID]
		if !ok {
			continue
		}
		fqdn := dom.FQDN(zoneName)
		if seen[fqdn] {
			continue
		}
		if caddygen.TLSPolicyForDomain(*dom) != proxymodel.TLSPolicyCentral {
			continue // self-acme / off domains need no provided cert
		}
		if _, gErr := s.db.GetCertificate(fqdn); gErr == nil {
			continue // already have a cert (renewal pass owns expiry)
		}
		t, ok := s.resolveTarget(fqdn, []string{fqdn}, false, zones)
		if !ok {
			log.Printf("reconciler: first-issuance: cannot resolve zone/provider for %q, skipping", fqdn)
			continue
		}
		t.FirstIssue = true // re-checked under the per-host lock so a concurrent on-create issuance isn't double-driven
		targets = append(targets, t)
		seen[fqdn] = true
	}

	return targets, nil
}

// TargetForHost resolves the issuance target for a single host on demand (the
// on-create fast path). It returns (nil, nil) when nothing should be issued: the
// host's zone/provider cannot be resolved, or a certificate is already on file
// (the periodic scan owns renewal). The caller is responsible for only invoking
// this for hosts whose domain actually wants a central cert.
func (s *CertRenewalStore) TargetForHost(_ context.Context, host string) (*tls.RenewTarget, error) {
	if host == "" {
		return nil, nil
	}
	if _, err := s.db.GetCertificate(host); err == nil {
		return nil, nil // already have a cert; let the scan handle renewal
	}
	zones, err := s.db.ListZones()
	if err != nil {
		return nil, fmt.Errorf("listing zones: %w", err)
	}
	t, ok := s.resolveTarget(host, []string{host}, false, zones)
	if !ok {
		return nil, nil // no zone/provider covers this host — nothing to issue against
	}
	return &t, nil
}

// resolveTarget builds a RenewTarget for a host by finding its zone and that
// zone's DNS provider (the same provider that creates the host's records, which
// DNS-01 must drive). Returns ok=false when the zone or provider cannot be
// resolved.
func (s *CertRenewalStore) resolveTarget(host string, names []string, isWildcard bool, zones []models.Zone) (tls.RenewTarget, bool) {
	zone := zoneForHost(host, isWildcard, zones)
	if zone == nil {
		return tls.RenewTarget{}, false
	}
	prov, pErr := s.db.GetProvider(zone.ProviderID)
	if pErr != nil {
		return tls.RenewTarget{}, false
	}
	dnsProvider, gErr := provider.Get(prov.Type)
	if gErr != nil {
		return tls.RenewTarget{}, false
	}
	if s.dnsDryRun {
		dnsProvider = dryrun.Wrap(dnsProvider, nil)
	}
	return tls.RenewTarget{
		Host:       host,
		Names:      names,
		IsWildcard: isWildcard,
		Provider:   dnsProvider,
		Config:     mergeZoneIDIntoConfig(prov.Config, zone.ExternalID),
	}, true
}

// SaveRenewed overwrites the stored certificate for the host in place with the
// freshly issued bundle, re-encrypting the key at rest and recording the new
// expiry parsed from the leaf so the next scan computes the window correctly.
func (s *CertRenewalStore) SaveRenewed(_ context.Context, res *tls.CertResult, isWildcard bool) error {
	if res == nil || res.Host == "" {
		return fmt.Errorf("reconciler: renewal: nil/empty cert result")
	}
	cert := &models.Certificate{
		ID:         res.Host, // host-keyed; upsert is ON CONFLICT(host)
		Host:       res.Host,
		Names:      res.Names,
		IsWildcard: isWildcard,
		CertPEM:    string(res.CertPEM),
		KeyPEM:     string(res.KeyPEM),
	}
	if notAfter, err := tls.LeafNotAfter(res.CertPEM); err == nil {
		cert.ExpiresAt = notAfter
	}
	cert.IssuedAt = time.Now().UTC()
	if err := s.db.UpsertCertificate(cert); err != nil {
		return fmt.Errorf("reconciler: renewal: saving renewed cert for %q: %w", res.Host, err)
	}
	return nil
}

// certHasCentralConsumer reports whether any name the stored certificate covers
// is currently consumed: a live central-TLS domain's FQDN equals it, or — for a
// wildcard name — sits beneath its apex. centralHosts is the precomputed FQDN
// set of those domains. A cert covering none of them has no consumer left and
// must not be re-issued (DueForRenewal skips it).
func certHasCentralConsumer(c *models.Certificate, centralHosts map[string]bool) bool {
	names := append([]string{c.Host}, c.Names...)
	for _, name := range names {
		if name == "" {
			continue
		}
		wildcard := strings.HasPrefix(name, "*.")
		if wildcard {
			name = strings.TrimPrefix(name, "*.")
		} else if c.IsWildcard && name == c.Host {
			// A wildcard cert is keyed at its apex (see zoneForHost): the bare host
			// stands for "*.host" too.
			wildcard = true
		}
		if centralHosts[name] {
			return true
		}
		if !wildcard {
			continue
		}
		suffix := "." + name
		for h := range centralHosts {
			if strings.HasSuffix(h, suffix) {
				return true
			}
		}
	}
	return false
}

// zoneForHost picks the zone a certificate host belongs to. For a per-host cert
// the host is an FQDN inside the zone; for a wildcard the host is the apex the
// "*." applies to. In both cases the longest matching zone suffix wins (so
// "a.sub.example.com" prefers "sub.example.com" over "example.com").
func zoneForHost(host string, _ bool, zones []models.Zone) *models.Zone {
	var best *models.Zone
	for i := range zones {
		z := &zones[i]
		if host == z.Name || strings.HasSuffix(host, "."+z.Name) {
			if best == nil || len(z.Name) > len(best.Name) {
				best = z
			}
		}
	}
	return best
}
