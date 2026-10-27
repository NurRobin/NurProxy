package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// persistAgentAnchor stores a created/adopted anchor record on the agent row.
// It returns the ownership actually stored (adopting a record that was still
// queued for cleanup keeps its original ownership) and whether the agent row
// was updated. When the agent was renamed or deleted meanwhile, the DB layer
// queues an owned record for cleanup instead and ok is false.
func (r *Reconciler) persistAgentAnchor(a *models.Agent, recordType, recordID, zoneID string, owned bool) (stored, ok bool) {
	stored, err := r.db.SetAgentAnchorRecord(a.ID, a.FQDN, recordType, recordID, zoneID, owned)
	switch {
	case err == nil:
		return stored, true
	case errors.Is(err, db.ErrAnchorStale):
		log.Printf("reconciler: agent %s changed FQDN or was deleted while resolving its %s record %s; not storing it", a.ID, recordType, recordID)
		if stored {
			r.auditDNS("agent", a.ID, anchorAction(recordType, "cleanup_queued"),
				fmt.Sprintf("%s record %s at %s queued for deletion: agent anchor moved", recordType, recordID, a.FQDN))
		}
		return stored, false
	default:
		log.Printf("reconciler: failed to persist %s record id for agent %s: %v", recordType, a.ID, err)
		return false, false
	}
}

// defaultAnchorRenameGrace keeps an anchor released by a rename for an hour, so
// CNAMEs NurProxy does not manage (operator records pointing at the old agent
// name) have time to be moved before the old address disappears.
const defaultAnchorRenameGrace = time.Hour

// anchorCleanupWarnEvery rate-limits the log warning about failing cleanups.
const anchorCleanupWarnEvery = time.Hour

// reconcileAgentAnchorCleanups works through the anchor records released by
// agent renames and deletions. Adopted records are never touched at the
// provider: they are audited and dropped from the queue. Owned records are
// deleted through the provider and zone they were created in; the queue row is
// removed only once the delete succeeded or the record is already gone, so any
// other failure is retried next cycle (same rule as domain teardown).
//
// A record released by a rename (or created for a name the agent already left)
// is only deleted once nothing NurProxy can see still depends on it: the grace
// period has passed, the agent has its new anchor of that type, and no domain
// record of the agent still points at the old name. Until then the row simply
// waits; that is not a failure.
func (r *Reconciler) reconcileAgentAnchorCleanups(ctx context.Context) error {
	cleanups, err := r.db.ListAgentAnchorCleanups()
	if err != nil {
		return fmt.Errorf("listing anchor cleanups: %w", err)
	}
	if len(cleanups) == 0 {
		return nil
	}
	agents, err := r.db.ListAgents()
	if err != nil {
		return fmt.Errorf("listing agents for anchor cleanup: %w", err)
	}
	agentsByID := make(map[string]*models.Agent, len(agents))
	for i := range agents {
		agentsByID[agents[i].ID] = &agents[i]
	}
	// Per agent + old name: why the old name is still in use ("" = it isn't).
	// Checked at most once per cycle, since A and AAAA share the answer.
	stillTargeted := map[string]string{}

	now := time.Now().UTC()
	var failing []db.AgentAnchorCleanup
	for i := range cleanups {
		c := &cleanups[i]
		if !c.Owned {
			r.auditDNS("agent", c.AgentID, anchorAction(c.RecordType, "left_adopted"),
				fmt.Sprintf("kept operator-owned %s record %s at %s (agent %s)", c.RecordType, c.RecordID, c.FQDN, c.Reason))
			r.removeAnchorCleanup(c)
			continue
		}
		if c.Reason != "delete" {
			if wait := r.renamedAnchorStillNeeded(ctx, c, agentsByID[c.AgentID], now, stillTargeted); wait != "" {
				log.Printf("reconciler: keeping old %s record %s at %s for agent %s: %s", c.RecordType, c.RecordID, c.FQDN, c.AgentID, wait)
				continue
			}
		}

		dnsProvider, provConfig, rErr := r.resolveAnchorCleanupProvider(c)
		if rErr != nil {
			r.failAnchorCleanup(c, rErr.Error())
			failing = append(failing, *c)
			continue
		}
		dErr := dnsProvider.DeleteRecord(ctx, provConfig, c.RecordID)
		switch {
		case dErr == nil:
			r.auditDNS("agent", c.AgentID, anchorAction(c.RecordType, "deleted"),
				fmt.Sprintf("deleted %s record %s at %s (agent %s)", c.RecordType, c.RecordID, c.FQDN, c.Reason))
		case errors.Is(dErr, provider.ErrRecordNotFound):
			r.auditDNS("agent", c.AgentID, anchorAction(c.RecordType, "delete_skipped"),
				fmt.Sprintf("%s record %s at %s already absent", c.RecordType, c.RecordID, c.FQDN))
		default:
			r.failAnchorCleanup(c, dErr.Error())
			failing = append(failing, *c)
			continue
		}
		r.removeAnchorCleanup(c)
	}
	r.warnFailingAnchorCleanups(failing, now)
	return nil
}

// renamedAnchorStillNeeded returns why an owned anchor released by a rename
// must stay for now, or "" when it may be deleted. agent is nil when the agent
// row is gone; its domains went with it, so only the grace period applies.
func (r *Reconciler) renamedAnchorStillNeeded(ctx context.Context, c *db.AgentAnchorCleanup, agent *models.Agent, now time.Time, stillTargeted map[string]string) string {
	if now.Before(c.CreatedAt.Add(r.anchorRenameGrace)) {
		return "grace period after rename"
	}
	if agent == nil {
		return ""
	}

	// The agent must have its own anchor of this family at its current name
	// first, or names that CNAME to it would stop resolving. A family the agent
	// no longer reports an address for will never get one; don't wait for it.
	ip, current := agent.PublicIP, agent.DNSRecordID
	if c.RecordType == "AAAA" {
		ip, current = agent.PublicIP6, agent.DNSRecordID6
	}
	if ip != "" && (current == "" || current == c.RecordID) {
		return "agent has no " + c.RecordType + " record at " + agent.FQDN + " yet"
	}

	key := c.AgentID + "|" + c.FQDN
	reason, checked := stillTargeted[key]
	if !checked {
		reason = r.domainRecordsTargeting(ctx, c.AgentID, c.FQDN)
		stillTargeted[key] = reason
	}
	return reason
}

// domainRecordsTargeting checks the agent's live domain records at the
// provider and returns why the old name is (or may still be) in use: a record
// whose content is still oldFQDN, or one that could not be read. "" means none.
func (r *Reconciler) domainRecordsTargeting(ctx context.Context, agentID, oldFQDN string) string {
	domains, err := r.db.ListDomains(db.DomainFilter{AgentID: agentID})
	if err != nil {
		return fmt.Sprintf("cannot list domains: %v", err)
	}
	for i := range domains {
		dom := &domains[i]
		if dom.Status == models.DomainStatusDeleting || dom.DNSRecordID == "" {
			continue
		}
		zone, prov, dnsProvider, ok := r.resolveDNS(dom.ZoneID)
		if !ok {
			return fmt.Sprintf("cannot resolve DNS provider for domain %d", dom.ID)
		}
		rec, gErr := dnsProvider.GetRecord(ctx, mergeZoneIDIntoConfig(prov.Config, zone.ExternalID), dom.DNSRecordID)
		if gErr != nil {
			if errors.Is(gErr, provider.ErrRecordNotFound) {
				continue
			}
			return fmt.Sprintf("cannot read DNS record of domain %d: %v", dom.ID, gErr)
		}
		if sameRecordContent(rec.Content, oldFQDN) {
			return fmt.Sprintf("domain %d (%s) still points at %s", dom.ID, dom.FQDN(zone.Name), oldFQDN)
		}
	}
	return ""
}

// warnFailingAnchorCleanups logs a summary of anchor deletions that keep
// failing (provider or zone gone, provider errors), at most once per
// anchorCleanupWarnEvery, so a row that can never resolve is not silent.
func (r *Reconciler) warnFailingAnchorCleanups(failing []db.AgentAnchorCleanup, now time.Time) {
	if len(failing) == 0 || now.Before(r.anchorWarnAt.Add(anchorCleanupWarnEvery)) {
		return
	}
	r.anchorWarnAt = now
	oldest := failing[0] // rows are listed oldest first
	log.Printf("reconciler: WARN %d agent anchor record deletion(s) failing; oldest: %s record %s at %s (agent %s, queued %s, %d attempt(s)): %s",
		len(failing), oldest.RecordType, oldest.RecordID, oldest.FQDN, oldest.AgentID,
		oldest.CreatedAt.Format(time.RFC3339), oldest.Attempts, oldest.LastError)
}

// resolveAnchorCleanupProvider returns the DNS provider and zone config the
// record was created through: the provider/zone snapshot taken when the record
// was released, or, when that is missing, the zone row as it is now.
func (r *Reconciler) resolveAnchorCleanupProvider(c *db.AgentAnchorCleanup) (provider.Provider, json.RawMessage, error) {
	if c.ProviderID == "" {
		if c.ZoneID == "" {
			return nil, nil, fmt.Errorf("no zone recorded for %s record %s", c.RecordType, c.RecordID)
		}
		zone, prov, dnsProvider, ok := r.resolveDNS(c.ZoneID)
		if !ok {
			return nil, nil, fmt.Errorf("zone/provider for zone %s unresolvable", c.ZoneID)
		}
		return dnsProvider, mergeZoneIDIntoConfig(prov.Config, zone.ExternalID), nil
	}
	prov, err := r.db.GetProvider(c.ProviderID)
	if err != nil {
		return nil, nil, fmt.Errorf("provider %s unresolvable: %v", c.ProviderID, err)
	}
	dnsProvider, err := provider.Get(prov.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("DNS provider %s not registered: %v", prov.Type, err)
	}
	return r.wrapDNS(dnsProvider), mergeZoneIDIntoConfig(prov.Config, c.ZoneExternalID), nil
}

// failAnchorCleanup keeps the queue row for the next cycle. The audit entry is
// written only when the error changes, so a provider that stays down does not
// add one audit row per cycle.
func (r *Reconciler) failAnchorCleanup(c *db.AgentAnchorCleanup, msg string) {
	log.Printf("reconciler: failed to delete %s record %s at %s for agent %s, retrying next cycle: %s", c.RecordType, c.RecordID, c.FQDN, c.AgentID, msg)
	if msg != c.LastError {
		r.auditDNS("agent", c.AgentID, anchorAction(c.RecordType, "delete_failed"),
			fmt.Sprintf("%s record %s at %s: %s", c.RecordType, c.RecordID, c.FQDN, msg))
	}
	if err := r.db.RecordAgentAnchorCleanupFailure(c.ID, msg); err != nil {
		log.Printf("reconciler: %v", err)
	}
	c.Attempts++
	c.LastError = msg
}

func (r *Reconciler) removeAnchorCleanup(c *db.AgentAnchorCleanup) {
	if err := r.db.RemoveAgentAnchorCleanup(c.ID); err != nil {
		log.Printf("reconciler: %v", err)
	}
}

// anchorAction builds the audit action for an anchor record, matching the
// "a_record_created" / "aaaa_record_adopted" names used when it was made.
func anchorAction(recordType, suffix string) string {
	return strings.ToLower(recordType) + "_record_" + suffix
}
