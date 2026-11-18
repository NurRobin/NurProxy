package reconciler

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// certForDomain returns the certificate a domain's host is served with, or nil
// when none is stored yet. A domain without the wildcard opt-in uses the cert
// stored under its FQDN. A wildcard domain uses its zone's "*.<zone>" cert,
// see selectDomainCert for the precedence.
func (r *Reconciler) certForDomain(dom *models.Domain, fqdn, zoneName string) *models.Certificate {
	own := r.lookupCert(fqdn)
	if dom == nil {
		return own
	}
	wildHost := caddygen.WildcardCertHost(*dom, zoneName)
	if wildHost == "" {
		return own
	}
	return selectDomainCert(own, r.lookupCert(wildHost), time.Now())
}

// lookupCert reads the stored cert for host. A missing row is nil; any other
// failure is logged and also nil, so one unreadable cert never fails a push.
func (r *Reconciler) lookupCert(host string) *models.Certificate {
	cert, err := r.db.GetCertificate(host)
	if err != nil {
		if !errors.Is(err, db.ErrCertNotFound) {
			log.Printf("reconciler: cannot read certificate for %s: %v", host, err)
		}
		return nil
	}
	return cert
}

// selectDomainCert picks the cert for a wildcard domain from its own per-host
// cert and the zone wildcard cert:
//
//   - an imported per-host cert wins while it is outside the renew window: the
//     operator provided it for exactly this host. Central renewal does not take
//     it over for a wildcard domain, so once it nears expiry the wildcard cert
//     replaces it;
//   - otherwise the zone wildcard cert;
//   - while the wildcard cert is not issued yet, any per-host cert left from
//     before the opt-in keeps the host on HTTPS.
func selectDomainCert(own, wildcard *models.Certificate, now time.Time) *models.Certificate {
	if own != nil && own.Source == models.CertSourceImported &&
		(own.ExpiresAt.IsZero() || own.ExpiresAt.After(now.Add(tls.DefaultRenewWindow))) {
		return own
	}
	if wildcard != nil {
		return wildcard
	}
	return own
}

// isZoneWildcardCert reports whether c is a shared zone wildcard cert, stored
// under "*.<zone>" rather than under one domain's FQDN.
func isZoneWildcardCert(c *models.Certificate) bool {
	return c.IsWildcard && strings.HasPrefix(c.Host, "*.")
}

// pruneUnusedWildcardCerts deletes "*.<zone>" certs no domain uses any more:
// the last opted-in domain of the zone was deleted, opted out, or moved to
// another zone, and the zone has no catch-all "*" domain, which is served from
// the same cert. The check runs inside the delete statement
// (DeleteWildcardCertIfUnused), so a cert with a live user is never removed.
// Imported certs are the operator's and are left alone. A cert whose zone no
// longer resolves is kept and logged rather than guessed at.
func (r *Reconciler) pruneUnusedWildcardCerts() {
	certs, err := r.db.ListCertificates()
	if err != nil {
		log.Printf("reconciler: cannot list certificates for wildcard cleanup: %v", err)
		return
	}
	var zones []models.Zone
	for i := range certs {
		c := &certs[i]
		if !strings.HasPrefix(c.Host, "*.") || c.Source != models.CertSourceACME {
			continue
		}
		if zones == nil {
			if zones, err = r.db.ListZones(); err != nil {
				log.Printf("reconciler: cannot list zones for wildcard cleanup: %v", err)
				return
			}
		}
		apex := strings.TrimPrefix(c.Host, "*.")
		var zoneID string
		for j := range zones {
			if zones[j].Name == apex {
				zoneID = zones[j].ID
				break
			}
		}
		if zoneID == "" {
			log.Printf("reconciler: keeping wildcard certificate %s: no zone %q found", c.Host, apex)
			continue
		}
		deleted, dErr := r.db.DeleteWildcardCertIfUnused(c.Host, zoneID)
		if dErr != nil {
			log.Printf("reconciler: wildcard cleanup for %s failed: %v", c.Host, dErr)
			continue
		}
		if deleted {
			r.audit("certificate", c.Host, "deleted", "no domain of the zone uses the wildcard certificate any more")
		}
	}
}

// usesZoneCert reports whether dom is served from the cert stored under host
// ("*.<zone>"): it opted into the zone wildcard cert, or it is the zone's
// catch-all "*" domain whose own FQDN is that host.
func usesZoneCert(dom *models.Domain, zoneName, host string) bool {
	return caddygen.WildcardCertHost(*dom, zoneName) == host || dom.FQDN(zoneName) == host
}

// agentsUsingWildcard returns the ids of the agents serving a domain that uses
// the cert stored under host ("*.<zone>"), opted-in or catch-all, so a renewed
// cert reaches every agent that installed a copy of it.
func (r *Reconciler) agentsUsingWildcard(host string) ([]string, error) {
	domains, err := r.db.ListDomains(db.DomainFilter{})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var agents []string
	zoneNames := make(map[string]string)
	for i := range domains {
		dom := &domains[i]
		if dom.Status == models.DomainStatusDeleting {
			continue
		}
		zoneName, ok := zoneNames[dom.ZoneID]
		if !ok {
			zone, zErr := r.db.GetZone(dom.ZoneID)
			if zErr != nil {
				continue
			}
			zoneName = zone.Name
			zoneNames[dom.ZoneID] = zoneName
		}
		if !usesZoneCert(dom, zoneName, host) {
			continue
		}
		srv, sErr := r.db.GetServer(dom.ServerID)
		if sErr != nil || seen[srv.AgentID] {
			continue
		}
		seen[srv.AgentID] = true
		agents = append(agents, srv.AgentID)
	}
	return agents, nil
}

// markDomainApplied records a successful apply of desired. A wildcard domain
// counts its zone wildcard cert as issued, so it is not reported as degraded
// for lacking a cert under its own FQDN.
func (r *Reconciler) markDomainApplied(desired desiredRoute, fqdn string) error {
	dom := desired.domain
	var fallback []string
	if wildHost := caddygen.WildcardCertHost(*dom, desired.zoneName); wildHost != "" {
		fallback = append(fallback, wildHost)
	}
	return r.db.MarkDomainApplied(dom.ID, fqdn, caddygen.TLSPolicyForDomain(*dom) == proxymodel.TLSPolicyCentral, fallback...)
}
