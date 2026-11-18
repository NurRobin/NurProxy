package db

import (
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// SkipCertAdoption records that the operator wants a new certificate for the
// domain instead of adopting one found on an agent's disk (#80), which ends
// the first-issuance hold for it.
func (d *DB) SkipCertAdoption(domainID int64) error {
	res, err := d.sql.Exec(`UPDATE domains SET cert_adoption_skipped = 1 WHERE id = ?`, domainID)
	if err != nil {
		return fmt.Errorf("skipping cert adoption: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("domain not found: %d", domainID)
	}
	return nil
}

// CertAdoptionSkipped reports whether SkipCertAdoption was called for the
// domain.
func (d *DB) CertAdoptionSkipped(domainID int64) (bool, error) {
	var skipped int
	err := d.sql.QueryRow(`SELECT cert_adoption_skipped FROM domains WHERE id = ?`, domainID).Scan(&skipped)
	if err != nil {
		return false, fmt.Errorf("reading cert adoption skip: %w", err)
	}
	return skipped != 0, nil
}

// CertAdoptionHold is the first-issuance hold of a new central-TLS domain
// (#80): while the domain is younger than tls.AdoptionGrace, the operator has
// not skipped adoption, and its serving agent reports an adoptable
// certificate for host, no certificate is ordered. It returns when the hold
// ends and the certificate that causes it. Lookup errors never hold issuance.
// Whether a certificate is already on file is the caller's concern.
func (d *DB) CertAdoptionHold(dom *models.Domain, host string, now time.Time) (until time.Time, cert models.DiscoveredCert, agentName string, held bool) {
	until = dom.CreatedAt.Add(tls.AdoptionGrace)
	if dom.CreatedAt.IsZero() || !now.Before(until) || dom.ServerID == "" {
		return time.Time{}, models.DiscoveredCert{}, "", false
	}
	if skipped, err := d.CertAdoptionSkipped(dom.ID); err != nil || skipped {
		return time.Time{}, models.DiscoveredCert{}, "", false
	}
	srv, err := d.GetServer(dom.ServerID)
	if err != nil {
		return time.Time{}, models.DiscoveredCert{}, "", false
	}
	agent, err := d.GetAgent(srv.AgentID)
	if err != nil || agent.ProxyDetection == nil {
		return time.Time{}, models.DiscoveredCert{}, "", false
	}
	for _, dc := range agent.ProxyDetection.DiscoveredCerts {
		if ok, _ := tls.AdoptableFor(dc, host, now); ok {
			return until.UTC(), dc, agent.Name, true
		}
	}
	return time.Time{}, models.DiscoveredCert{}, "", false
}
