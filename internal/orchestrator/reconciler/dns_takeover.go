package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// ErrDNSTakeoverRefused is models.ErrDNSTakeoverRefused.
var ErrDNSTakeoverRefused = models.ErrDNSTakeoverRefused

// DNSTakeoverIncompleteError reports a takeover that changed records at the
// provider before it failed, so the operator knows the name's DNS is no longer
// what it was. Deletes and the create are separate provider calls; there is no
// transaction to roll back.
type DNSTakeoverIncompleteError struct {
	FQDN    string
	Target  string
	Deleted []provider.Record
	// Left holds records at the name that were not deleted (the one whose
	// delete failed and those after it). Empty when the create failed.
	Left []provider.Record
	Err  error
}

func (e *DNSTakeoverIncompleteError) Error() string {
	if len(e.Left) > 0 {
		return fmt.Sprintf("DNS takeover for %s is incomplete: %s were already deleted, then deleting %s failed: %v. "+
			"The deleted records are not restored. Retry the takeover to delete the rest and create the CNAME → %s.",
			e.FQDN, describeRecords(e.Deleted), describeRecords(e.Left), e.Err, e.Target)
	}
	return fmt.Sprintf("DNS takeover for %s is incomplete: the old records (%s) were already deleted, but creating the CNAME → %s failed: %v. "+
		"%s has no DNS record now. Retry the takeover: the name is free and it creates the CNAME.",
		e.FQDN, describeRecords(e.Deleted), e.Target, e.Err, e.FQDN)
}

func (e *DNSTakeoverIncompleteError) Unwrap() error { return e.Err }

// domainDNSLock returns the mutex that serializes every DNS write for one
// domain: the reconcile pass, the immediate pass after a rename, and the admin
// takeover. Without it a pass that read the domain before a takeover could
// see the name free between the takeover's delete and create and add a second
// record, or adopt the taken-over record again as unmanaged.
func (r *Reconciler) domainDNSLock(domainID int64) *sync.Mutex {
	l, _ := r.domainDNSLocks.LoadOrStore(domainID, &sync.Mutex{})
	return l.(*sync.Mutex)
}

// takeoverTarget is everything a takeover of one domain works with.
type takeoverTarget struct {
	dom      *models.Domain
	agentID  string
	provider provider.Provider
	config   json.RawMessage
	existing []provider.Record
	plan     *models.DNSTakeoverPlan
}

// resolveTakeover loads the domain, its zone's provider and the records at its
// name, and works out what a takeover would do. It changes nothing.
//
// With apply set the caller holds the domain's DNS lock and the failover
// decision for the target is stored (selectDNSTarget); without it, for the
// preview, it is only computed (decideDNSTarget).
func (r *Reconciler) resolveTakeover(ctx context.Context, domID int64, apply bool) (*takeoverTarget, error) {
	dom, err := r.db.GetDomain(domID)
	if err != nil {
		return nil, fmt.Errorf("domain %d: %w", domID, err)
	}
	if dom.CertOnly {
		return nil, fmt.Errorf("%w: domain %d is cert-only; NurProxy does not manage its public DNS", ErrDNSTakeoverRefused, domID)
	}
	if dom.Status == models.DomainStatusDeleting {
		return nil, fmt.Errorf("%w: domain %d is being deleted", ErrDNSTakeoverRefused, domID)
	}

	zone, err := r.db.GetZone(dom.ZoneID)
	if err != nil {
		return nil, fmt.Errorf("resolving zone for domain %d: %w", domID, err)
	}
	prov, err := r.db.GetProvider(zone.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("resolving provider for zone %s: %w", zone.ID, err)
	}
	dnsProvider, err := provider.Get(prov.Type)
	if err != nil {
		return nil, fmt.Errorf("DNS provider %s not registered: %w", prov.Type, err)
	}
	dnsProvider = r.wrapDNS(dnsProvider)
	provConfig := mergeZoneIDIntoConfig(prov.Config, zone.ExternalID)

	fqdn := dom.FQDN(zone.Name)
	srv, err := r.db.GetServer(dom.ServerID)
	if err != nil {
		return nil, fmt.Errorf("resolving server for domain %d: %w", domID, err)
	}
	// The currently active agent: the primary, or a backup after a failover
	// (#74).
	var agent *models.Agent
	if apply {
		agent, err = r.selectDNSTarget(dom)
	} else {
		var t *dnsTarget
		if t, err = r.decideDNSTarget(dom); err == nil {
			agent = t.agent
		}
	}
	if err != nil {
		return nil, fmt.Errorf("resolving the DNS target for domain %d: %w", domID, err)
	}
	target := agent.FQDN

	existing, err := lookupRecordsByName(ctx, dnsProvider, provConfig, fqdn)
	if err != nil {
		return nil, fmt.Errorf("looking up existing DNS records for %s: %w", fqdn, err)
	}

	plan := &models.DNSTakeoverPlan{DomainID: dom.ID, FQDN: fqdn, Target: target, Delete: []models.DNSRecordInfo{}}
	if adopt := matchingRecord(existing, "CNAME", target); adopt != nil {
		plan.Action = models.DNSTakeoverAdopt
		plan.Proxied = desiredProxied(dom, adopt.Proxied)
	} else {
		plan.Action = models.DNSTakeoverCreate
		if len(existing) > 0 {
			plan.Action = models.DNSTakeoverReplace
		}
		// The new CNAME inherits the proxy state of what it replaces (any
		// proxied record at the name means the name was behind Cloudflare),
		// unless the operator set one explicitly.
		wasProxied := false
		for _, rec := range existing {
			wasProxied = wasProxied || rec.Proxied
			plan.Delete = append(plan.Delete, recordInfo(rec))
		}
		plan.Proxied = desiredProxied(dom, wasProxied)
	}
	return &takeoverTarget{dom: dom, agentID: srv.AgentID, provider: dnsProvider, config: provConfig, existing: existing, plan: plan}, nil
}

func recordInfo(rec provider.Record) models.DNSRecordInfo {
	return models.DNSRecordInfo{ID: rec.ID, Type: strings.ToUpper(rec.Type), Name: rec.Name, Content: rec.Content, Proxied: rec.Proxied}
}

// PreviewDomainDNSTakeover reports what TakeoverDomainDNS would do for the
// domain right now, in particular every record it would delete, without
// changing anything at the provider or in the database.
func (r *Reconciler) PreviewDomainDNSTakeover(ctx context.Context, domID int64) (*models.DNSTakeoverPlan, error) {
	t, err := r.resolveTakeover(ctx, domID, false)
	if err != nil {
		return nil, err
	}
	return t.plan, nil
}

// TakeoverDomainDNS forcibly aligns a domain's public DNS record with NurProxy's
// desired CNAME → agent FQDN, using the zone provider's stored credentials. It is
// the explicit, audited admin override of the default "never overwrite a record we
// didn't create" stance (ensureDomainCNAME): on a conflict it DELETES every
// record at the name (MX, TXT and the like included, since a CNAME cannot share
// its name) and creates the CNAME, clears the domain's DNS error, and re-pushes
// the agent's routes so the now-resolvable domain re-renders WITH its (already
// issued) certificate. It is the supported path to migrate an existing domain
// whose public DNS predates NurProxy (an A record, or a CNAME pointing somewhere
// else). PreviewDomainDNSTakeover shows the same plan without acting on it.
//
// Takeover transfers ownership of the record to NurProxy: the domain's record
// is stored as managed (dns_managed=true) in every case, including when a
// matching CNAME the operator created is adopted, so deleting the domain later
// also deletes that record at the provider.
//
// expectDelete, when not nil, is the set of record ids the caller saw in the
// preview and agreed to delete: if the records at the name are not exactly
// those any more, nothing is changed and models.ErrDNSTakeoverPlanChanged is
// returned. nil skips the check.
//
// The deletes and the create are separate provider calls. When one of them
// fails after a record was deleted, the returned *DNSTakeoverIncompleteError
// says which records are gone; a retry finishes the job. The domain's DNS lock
// is held throughout, so the reconciler and the teardown cannot write the
// domain's record in the gap. A rename can still land meanwhile; the record is
// then stored only while the domain keeps the name it was taken over for.
func (r *Reconciler) TakeoverDomainDNS(ctx context.Context, domID int64, expectDelete []string) (*models.DNSTakeoverPlan, error) {
	lk := r.domainDNSLock(domID)
	lk.Lock()
	defer lk.Unlock()

	t, err := r.resolveTakeover(ctx, domID, true)
	if err != nil {
		return nil, err
	}
	dom, plan := t.dom, t.plan
	domRef := fmt.Sprintf("%d", dom.ID)
	if expectDelete != nil && !sameIDSet(expectDelete, plan.Delete) {
		return nil, fmt.Errorf("%w: %s now has %s; preview again before taking over", models.ErrDNSTakeoverPlanChanged, plan.FQDN, describeOrNone(t.existing))
	}

	if plan.Action == models.DNSTakeoverAdopt {
		adopt := matchingRecord(t.existing, "CNAME", plan.Target)
		if dErr := r.db.SetDomainDNSRecordIfNamed(dom.ID, dom.Subdomain, dom.ZoneID, adopt.ID, true); dErr != nil {
			if errors.Is(dErr, db.ErrDomainRenamed) {
				return nil, fmt.Errorf("domain %d was renamed or deleted during the takeover; nothing was changed at %s", dom.ID, plan.FQDN)
			}
			return nil, fmt.Errorf("storing adopted record id: %w", dErr)
		}
		r.auditDNS("domain", domRef, "dns_takeover", fmt.Sprintf("took ownership of matching CNAME %s -> %s (%s)", plan.FQDN, plan.Target, proxiedWord(adopt.Proxied)))
		if pErr := r.enforceProxied(ctx, dom, plan.FQDN, adopt, t.provider, t.config); pErr != nil {
			return nil, fmt.Errorf("setting proxy state on %s: %w", plan.FQDN, pErr)
		}
	} else {
		for i := range t.existing {
			if dErr := t.provider.DeleteRecord(ctx, t.config, t.existing[i].ID); dErr != nil && !errors.Is(dErr, provider.ErrRecordNotFound) {
				if i == 0 {
					return nil, fmt.Errorf("deleting conflicting record %s (%s); nothing was changed: %w", t.existing[i].ID, t.existing[i].Type, dErr)
				}
				return nil, r.takeoverIncomplete(dom, &DNSTakeoverIncompleteError{
					FQDN: plan.FQDN, Target: plan.Target, Deleted: t.existing[:i], Left: t.existing[i:], Err: dErr,
				})
			}
		}
		recordID, cErr := t.provider.CreateRecord(ctx, t.config, provider.Record{Type: "CNAME", Name: plan.FQDN, Content: plan.Target, TTL: 0, Proxied: plan.Proxied})
		if cErr != nil {
			if len(t.existing) == 0 {
				return nil, fmt.Errorf("creating CNAME for %s: %w", plan.FQDN, cErr)
			}
			return nil, r.takeoverIncomplete(dom, &DNSTakeoverIncompleteError{
				FQDN: plan.FQDN, Target: plan.Target, Deleted: t.existing, Err: cErr,
			})
		}
		if dErr := r.db.SetDomainDNSRecordIfNamed(dom.ID, dom.Subdomain, dom.ZoneID, recordID, true); dErr != nil {
			if errors.Is(dErr, db.ErrDomainRenamed) {
				return nil, r.takeoverLostName(ctx, dom, t, recordID)
			}
			return nil, fmt.Errorf("created CNAME %s for %s but could not store it on the domain: %w", recordID, plan.FQDN, dErr)
		}
		if len(t.existing) == 0 {
			r.auditDNS("domain", domRef, "dns_takeover", fmt.Sprintf("created CNAME %s -> %s (%s); the name was free", plan.FQDN, plan.Target, proxiedWord(plan.Proxied)))
		} else {
			r.auditDNS("domain", domRef, "dns_takeover", fmt.Sprintf("took over DNS for %s: replaced %s with CNAME -> %s (%s)", plan.FQDN, describeRecords(t.existing), plan.Target, proxiedWord(plan.Proxied)))
		}
	}

	// Clear the DNS error; the proxy apply sets the real status next.
	if dErr := r.db.ClearDomainDNSError(dom.ID); dErr != nil {
		return nil, dErr
	}
	if dErr := r.db.ResetDomainPending(dom.ID); dErr != nil {
		return nil, fmt.Errorf("clearing domain status: %w", dErr)
	}
	// Re-push so the now-resolvable domain re-renders WITH its certificate — the
	// create-time push rendered HTTP-only before issuance completed. No-op if the
	// agent isn't connected; the periodic reconcile is the backstop.
	if pErr := r.PushAgentRoutes(t.agentID); pErr != nil {
		log.Printf("reconciler: DNS takeover for %s done, but route re-push failed (next cycle retries): %v", plan.FQDN, pErr)
	}
	return plan, nil
}

// takeoverLostName handles a CNAME the takeover created for a name the domain
// no longer has: it was renamed, moved or deleted while the takeover ran. A
// record kept for a renamed domain goes through the cleanup queue like any
// record a rename released; one for a deleted domain is deleted right away.
// The returned error says what happened to it.
func (r *Reconciler) takeoverLostName(ctx context.Context, dom *models.Domain, t *takeoverTarget, recordID string) error {
	fqdn, target := t.plan.FQDN, t.plan.Target
	_, gErr := r.db.GetDomain(dom.ID)
	if errors.Is(gErr, db.ErrDomainNotFound) {
		if dErr := t.provider.DeleteRecord(ctx, t.config, recordID); dErr != nil && !errors.Is(dErr, provider.ErrRecordNotFound) {
			r.queueStaleCreatedRecord(dom, fqdn, target, recordID, t.plan.Proxied)
			return fmt.Errorf("domain %d was deleted during the takeover; deleting the CNAME %s it created at %s failed (%v), so it is queued for cleanup", dom.ID, recordID, fqdn, dErr)
		}
		r.auditDNS("domain", fmt.Sprintf("%d", dom.ID), "dns_deleted", fmt.Sprintf("deleted record %s at %s created by a takeover that finished after the domain was deleted", recordID, fqdn))
		return fmt.Errorf("domain %d was deleted during the takeover; the CNAME it created at %s was deleted again", dom.ID, fqdn)
	}
	r.queueStaleCreatedRecord(dom, fqdn, target, recordID, t.plan.Proxied)
	return fmt.Errorf("domain %d was renamed during the takeover; the CNAME created at %s is queued for cleanup and the new name gets its record from the next DNS pass", dom.ID, fqdn)
}

// sameIDSet reports whether ids names exactly the records in recs.
func sameIDSet(ids []string, recs []models.DNSRecordInfo) bool {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	if len(want) != len(recs) {
		return false
	}
	for _, rec := range recs {
		if !want[rec.ID] {
			return false
		}
	}
	return true
}

func describeOrNone(recs []provider.Record) string {
	if len(recs) == 0 {
		return "no records"
	}
	return describeRecords(recs)
}

// takeoverIncomplete records a half-done takeover on the domain and in the
// audit log, then returns it.
func (r *Reconciler) takeoverIncomplete(dom *models.Domain, e *DNSTakeoverIncompleteError) error {
	msg := e.Error()
	log.Printf("reconciler: %s", msg)
	r.auditDNS("domain", fmt.Sprintf("%d", dom.ID), "dns_takeover_failed", msg)
	if dErr := r.db.SetDomainDNSError(dom.ID, msg); dErr != nil {
		log.Printf("reconciler: %v", dErr)
	}
	return e
}
