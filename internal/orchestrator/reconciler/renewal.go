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
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// CertRenewalStore adapts the orchestrator DB + zone/provider resolution to the
// tls.RenewalStore seam, so the central Renewer can find certificates entering
// the renew window and persist re-issued bundles without importing the DB
// itself. It resolves each due certificate's host to the DNS provider whose zone
// it lives in (the same provider used to create its A/CNAME records), which is
// exactly the provider DNS-01 must drive to renew it.
type CertRenewalStore struct {
	db *db.DB
}

// NewCertRenewalStore builds the store adapter over the given DB.
func NewCertRenewalStore(database *db.DB) *CertRenewalStore {
	return &CertRenewalStore{db: database}
}

// DueForRenewal lists certificates within window of expiry, each resolved to the
// DNS provider for its zone. A certificate whose zone/provider can no longer be
// resolved is logged and skipped (never aborting the whole scan) — its host may
// have been deleted, and there is nothing to renew against.
func (s *CertRenewalStore) DueForRenewal(_ context.Context, window time.Duration) ([]tls.RenewTarget, error) {
	certs, err := s.db.CertificatesDueForRenewal(window)
	if err != nil {
		return nil, fmt.Errorf("listing certificates due for renewal: %w", err)
	}

	zones, err := s.db.ListZones()
	if err != nil {
		return nil, fmt.Errorf("listing zones for renewal resolution: %w", err)
	}

	targets := make([]tls.RenewTarget, 0, len(certs))
	for i := range certs {
		c := &certs[i]
		zone := zoneForHost(c.Host, c.IsWildcard, zones)
		if zone == nil {
			log.Printf("reconciler: renewal: no zone covers cert host %q, skipping", c.Host)
			continue
		}
		prov, pErr := s.db.GetProvider(zone.ProviderID)
		if pErr != nil {
			log.Printf("reconciler: renewal: cannot load provider for zone %s (host %q): %v", zone.ID, c.Host, pErr)
			continue
		}
		dnsProvider, gErr := provider.Get(prov.Type)
		if gErr != nil {
			log.Printf("reconciler: renewal: provider %s not registered (host %q): %v", prov.Type, c.Host, gErr)
			continue
		}
		targets = append(targets, tls.RenewTarget{
			Host:       c.Host,
			Names:      append([]string(nil), c.Names...),
			IsWildcard: c.IsWildcard,
			Provider:   dnsProvider,
			Config:     mergeZoneIDIntoConfig(prov.Config, zone.ExternalID),
		})
	}
	return targets, nil
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
