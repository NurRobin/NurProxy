package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// defaultDomainDNSCleanupMaxWait bounds how long an old domain record waits for
// the record at the new name. After a rename the old name has no route on the
// agent any more, so a new name that cannot be created (a DNS conflict the
// operator has to resolve) must not keep the old record alive forever.
const defaultDomainDNSCleanupMaxWait = time.Hour

// runDomainDNSPhases reads what renamed domains need from their old records,
// converges every domain's record, then deletes records released by renames
// and zone moves (#151). The cleanup runs last, so the record at the new name
// has had its chance to be created and a record taken back has left the queue.
func (r *Reconciler) runDomainDNSPhases(ctx context.Context) {
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()
	r.snapshotDomainDNSCleanups(ctx)
	if err := r.reconcileDNS(ctx); err != nil {
		log.Printf("reconciler: DNS phase failed: %v", err)
	}
	if err := r.reconcileDomainDNSCleanups(ctx); err != nil {
		log.Printf("reconciler: domain DNS cleanup phase failed: %v", err)
	}
}

// ReconcileDNSNow runs the domain DNS phases at once. The API calls it after a
// rename or zone move, so the new name gets its record without waiting up to a
// full cycle while the old vhost is already gone.
func (r *Reconciler) ReconcileDNSNow(ctx context.Context) {
	r.runDomainDNSPhases(ctx)
}

// snapshotDomainDNSCleanups reads, once per queued record, the proxy state the
// record at the new name inherits. Only providers that can proxy are asked; a
// record that is gone, or whose provider is gone, counts as not proxied. A
// read error leaves the snapshot empty for the next cycle and is recorded on
// the row, so it shows in health.
func (r *Reconciler) snapshotDomainDNSCleanups(ctx context.Context) {
	cleanups, err := r.db.ListDomainDNSCleanups()
	if err != nil {
		log.Printf("reconciler: cannot list domain DNS cleanups: %v", err)
		return
	}
	for i := range cleanups {
		c := &cleanups[i]
		if c.Proxied != nil {
			continue
		}
		proxied, rErr := r.readReleasedProxied(ctx, c)
		if rErr != nil {
			log.Printf("reconciler: cannot read the proxy state of old record %s at %s, retrying next cycle: %v", c.RecordID, c.FQDN, rErr)
			if fErr := r.db.RecordDomainDNSCleanupFailure(c.ID, "reading proxy state: "+rErr.Error()); fErr != nil {
				log.Printf("reconciler: %v", fErr)
			}
			continue
		}
		if sErr := r.db.SetDomainDNSCleanupProxied(c.ID, proxied); sErr != nil {
			log.Printf("reconciler: %v", sErr)
		}
	}
}

func (r *Reconciler) readReleasedProxied(ctx context.Context, c *db.DomainDNSCleanup) (bool, error) {
	oldProvider, oldConfig, err := r.resolveDomainCleanupProvider(c)
	if err != nil {
		log.Printf("reconciler: provider of old record %s at %s unresolvable, not inheriting its proxy state: %v", c.RecordID, c.FQDN, err)
		return false, nil
	}
	if !oldProvider.Info().SupportsProxied {
		return false, nil
	}
	rec, err := oldProvider.GetRecord(ctx, oldConfig, c.RecordID)
	switch {
	case err == nil:
		return rec.Proxied, nil
	case errors.Is(err, provider.ErrRecordNotFound):
		return false, nil
	default:
		return false, err
	}
}

// newRecordProxied is the proxy state for a record the reconciler is about to
// create for dom: the operator's explicit setting if there is one, else the
// snapshot of the record the domain released by its last rename or zone move
// (when the new zone can proxy at all), else DNS-only. A non-empty wait means
// the snapshot is not read yet and the create should wait for it, at most for
// the cleanup wait bound.
func (r *Reconciler) newRecordProxied(dom *models.Domain, newProvider provider.Provider) (proxied bool, wait string) {
	if dom.Proxied != nil {
		return *dom.Proxied, ""
	}
	if !newProvider.Info().SupportsProxied {
		return false, ""
	}
	c, err := r.db.LatestDomainDNSCleanup(dom.ID)
	if err != nil {
		return false, fmt.Sprintf("cannot read the DNS cleanup queue: %v", err)
	}
	if c == nil {
		return false, ""
	}
	if c.Proxied != nil {
		return *c.Proxied, ""
	}
	if time.Now().UTC().After(c.CreatedAt.Add(r.domainDNSCleanupMaxWait)) {
		log.Printf("reconciler: proxy state of old record %s at %s still unknown after %s, creating the new record DNS-only", c.RecordID, c.FQDN, r.domainDNSCleanupMaxWait)
		return false, ""
	}
	return false, fmt.Sprintf("the proxy state of the old record %s at %s has not been read yet", c.RecordID, c.FQDN)
}

// cleanupAction is what the cleanup phase does with one queued record.
type cleanupAction int

const (
	cleanupWait   cleanupAction = iota // keep the row, look again next cycle
	cleanupDrop                        // leave the record at the provider, drop the row
	cleanupDelete                      // delete the record at the provider
	cleanupForget                      // record already deleted; drop the row quietly
)

// ownStillWaiting reports whether the row's domain still exists and has no
// record at its new name, so the row's proxied snapshot is still needed.
func (s *cleanupScope) ownStillWaiting(c *db.DomainDNSCleanup) bool {
	own, ok := s.byID[c.DomainID]
	return ok && own.Status != models.DomainStatusDeleting && own.DNSRecordID == "" && !own.CertOnly
}

// cleanupScope is the domain state one cleanup pass decides against.
type cleanupScope struct {
	domains []models.Domain
	byID    map[int64]*models.Domain
	zones   map[string]models.Zone
	now     time.Time
}

func (r *Reconciler) loadCleanupScope() (*cleanupScope, error) {
	domains, err := r.db.ListDomains(db.DomainFilter{})
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	zones, err := r.db.ListZones()
	if err != nil {
		return nil, fmt.Errorf("listing zones: %w", err)
	}
	s := &cleanupScope{domains: domains, byID: make(map[int64]*models.Domain, len(domains)),
		zones: make(map[string]models.Zone, len(zones)), now: time.Now().UTC()}
	for i := range domains {
		s.byID[domains[i].ID] = &domains[i]
	}
	for _, z := range zones {
		s.zones[z.ID] = z
	}
	return s, nil
}

// sameProviderZone reports whether a domain's zone row stands for the provider
// zone the record lives in: the same row, or another row (possibly of another
// provider row) for the same external zone. Record ids are only unique there.
func (s *cleanupScope) sameProviderZone(zoneID string, c *db.DomainDNSCleanup) bool {
	if zoneID == c.ZoneID {
		return true
	}
	z, ok := s.zones[zoneID]
	return ok && c.ZoneExternalID != "" && z.ExternalID == c.ZoneExternalID
}

// decide returns what to do with c and why. Nothing is ever deleted that a
// live domain may still use: a record any domain holds (in the same provider
// zone), or a record at a name any domain serves, whatever its zone or
// provider. Owned records otherwise wait for the domain's record at its new
// name (bounded); adopted ones wait too, so their proxy snapshot stays
// available, and are then dropped without touching the provider.
func (s *cleanupScope) decide(c *db.DomainDNSCleanup, maxWait time.Duration) (cleanupAction, string) {
	if c.Deleted {
		if s.ownStillWaiting(c) {
			return cleanupWait, ""
		}
		return cleanupForget, ""
	}
	for i := range s.domains {
		d := &s.domains[i]
		if d.Status == models.DomainStatusDeleting {
			continue
		}
		if d.DNSRecordID == c.RecordID && s.sameProviderZone(d.ZoneID, c) {
			return cleanupDrop, fmt.Sprintf("record %s at %s is in use by domain %d; left in place", c.RecordID, c.FQDN, d.ID)
		}
	}
	for i := range s.domains {
		d := &s.domains[i]
		z, ok := s.zones[d.ZoneID]
		if d.Status == models.DomainStatusDeleting || !ok || !sameRecordContent(d.FQDN(z.Name), c.FQDN) {
			continue
		}
		if d.DNSRecordID == "" {
			return cleanupWait, fmt.Sprintf("domain %d uses %s again and may take the record back", d.ID, c.FQDN)
		}
		return cleanupDrop, fmt.Sprintf("domain %d serves %s again (record %s); old record %s left in place, delete it at the provider if it is no longer needed", d.ID, c.FQDN, d.DNSRecordID, c.RecordID)
	}
	if s.ownStillWaiting(c) && s.now.Before(c.CreatedAt.Add(maxWait)) {
		return cleanupWait, "no record at the new name yet"
	}
	if !c.Owned {
		return cleanupDrop, fmt.Sprintf("kept operator-owned record %s at %s (domain renamed)", c.RecordID, c.FQDN)
	}
	return cleanupDelete, ""
}

// reconcileDomainDNSCleanups works through the domain records released by a
// rename or zone move (#151), following the anchor cleanup rules: adopted
// records are never touched at the provider, and owned ones are deleted
// through the provider and zone they were created in. A queue row is removed
// only once the delete succeeded or the record is already gone, so every other
// failure is retried next cycle. Right before deleting, the record is read
// back and left alone if its name or target is no longer what was released.
func (r *Reconciler) reconcileDomainDNSCleanups(ctx context.Context) error {
	cleanups, err := r.db.ListDomainDNSCleanups()
	if err != nil {
		return fmt.Errorf("listing domain DNS cleanups: %w", err)
	}
	if len(cleanups) == 0 {
		return nil
	}
	scope, err := r.loadCleanupScope()
	if err != nil {
		return err
	}
	failing := 0
	for i := range cleanups {
		c := &cleanups[i]
		entityID := fmt.Sprintf("%d", c.DomainID)
		action, why := scope.decide(c, r.domainDNSCleanupMaxWait)
		switch action {
		case cleanupWait:
			if why != "" {
				log.Printf("reconciler: keeping old DNS record %s at %s for domain %d: %s", c.RecordID, c.FQDN, c.DomainID, why)
			}
			continue
		case cleanupForget:
			r.removeDomainDNSCleanup(c)
			continue
		case cleanupDrop:
			auditAction := "dns_left_in_use"
			if !c.Owned {
				auditAction = "dns_left_adopted"
			}
			r.auditDNS("domain", entityID, auditAction, why)
			r.finishDomainDNSCleanup(c, scope)
			continue
		}

		dnsProvider, provConfig, rErr := r.resolveDomainCleanupProvider(c)
		if rErr != nil {
			r.failDomainDNSCleanup(c, rErr.Error())
			failing++
			continue
		}
		rec, gErr := dnsProvider.GetRecord(ctx, provConfig, c.RecordID)
		switch {
		case errors.Is(gErr, provider.ErrRecordNotFound):
			r.auditDNS("domain", entityID, "dns_delete_skipped",
				fmt.Sprintf("record %s at old name %s already absent", c.RecordID, c.FQDN))
			r.finishDomainDNSCleanup(c, scope)
			continue
		case gErr != nil:
			r.failDomainDNSCleanup(c, "reading record before delete: "+gErr.Error())
			failing++
			continue
		case !sameRecordContent(rec.Name, c.FQDN) || (c.Content != "" && !sameRecordContent(rec.Content, c.Content)):
			r.auditDNS("domain", entityID, "dns_left_changed",
				fmt.Sprintf("record %s is now %s -> %s, not the released %s -> %s; left in place", c.RecordID, rec.Name, rec.Content, c.FQDN, c.Content))
			r.finishDomainDNSCleanup(c, scope)
			continue
		}
		dErr := dnsProvider.DeleteRecord(ctx, provConfig, c.RecordID)
		switch {
		case dErr == nil:
			r.auditDNS("domain", entityID, "dns_deleted",
				fmt.Sprintf("deleted record %s at old name %s (domain renamed)", c.RecordID, c.FQDN))
		case errors.Is(dErr, provider.ErrRecordNotFound):
			r.auditDNS("domain", entityID, "dns_delete_skipped",
				fmt.Sprintf("record %s at old name %s already absent", c.RecordID, c.FQDN))
		default:
			r.failDomainDNSCleanup(c, dErr.Error())
			failing++
			continue
		}
		r.finishDomainDNSCleanup(c, scope)
	}
	if failing > 0 {
		log.Printf("reconciler: %d old domain DNS record deletion(s) failing, retrying next cycle", failing)
	}
	return nil
}

// resolveDomainCleanupProvider returns the DNS provider and zone config the
// record was created through, from the snapshot taken when it was released.
func (r *Reconciler) resolveDomainCleanupProvider(c *db.DomainDNSCleanup) (provider.Provider, json.RawMessage, error) {
	return r.resolveAnchorCleanupProvider(&db.AgentAnchorCleanup{
		RecordType: "CNAME", RecordID: c.RecordID, ZoneID: c.ZoneID,
		ProviderID: c.ProviderID, ZoneExternalID: c.ZoneExternalID,
	})
}

// failDomainDNSCleanup keeps the queue row for the next cycle. The audit entry
// is written only when the error changes, so a provider that stays down does
// not add one audit row per cycle.
func (r *Reconciler) failDomainDNSCleanup(c *db.DomainDNSCleanup, msg string) {
	log.Printf("reconciler: failed to delete old DNS record %s at %s for domain %d, retrying next cycle: %s", c.RecordID, c.FQDN, c.DomainID, msg)
	if msg != c.LastError {
		r.auditDNS("domain", fmt.Sprintf("%d", c.DomainID), "dns_delete_failed",
			fmt.Sprintf("old record %s at %s: %s", c.RecordID, c.FQDN, msg))
	}
	if err := r.db.RecordDomainDNSCleanupFailure(c.ID, msg); err != nil {
		log.Printf("reconciler: %v", err)
	}
}

func (r *Reconciler) removeDomainDNSCleanup(c *db.DomainDNSCleanup) {
	if err := r.db.RemoveDomainDNSCleanup(c.ID); err != nil {
		log.Printf("reconciler: %v", err)
	}
}

// finishDomainDNSCleanup ends the provider work for c. While the domain still
// has no record at its new name, the row stays (marked deleted) so the record
// created later can still inherit its proxied snapshot.
func (r *Reconciler) finishDomainDNSCleanup(c *db.DomainDNSCleanup, scope *cleanupScope) {
	if !scope.ownStillWaiting(c) {
		r.removeDomainDNSCleanup(c)
		return
	}
	if err := r.db.MarkDomainDNSCleanupDeleted(c.ID); err != nil {
		log.Printf("reconciler: %v", err)
	}
}
