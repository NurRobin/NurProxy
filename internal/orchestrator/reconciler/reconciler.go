// Package reconciler is the core state-sync engine for NurProxy. It
// periodically compares desired state (DB) with actual state (agent routes +
// DNS records) and fixes any drift.
package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/configeq/caddyeq"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// AgentClient defines the operations the reconciler needs from an agent.
type AgentClient interface {
	PushRoute(ctx context.Context, agentURL, token string, route json.RawMessage) error
	DeleteRoute(ctx context.Context, agentURL, token, domain string) error
	SyncRoutes(ctx context.Context, agentURL, token string, routes []json.RawMessage) error
	GetRoutes(ctx context.Context, agentURL, token string) ([]json.RawMessage, error)
	Health(ctx context.Context, agentURL, token string) error
}

// RouteHub is the subset of the agent connection hub the reconciler uses to
// push routes to agents over their live (outbound-initiated) stream.
type RouteHub interface {
	Connected(agentID string) bool
	PublishRoutes(agentID string, routes []json.RawMessage) bool
}

// Reconciler periodically syncs desired state (database) with actual state
// (agent routes and DNS records).
type Reconciler struct {
	db          *db.DB
	agentClient AgentClient
	hub         RouteHub
	interval    time.Duration
	mu          sync.Mutex
	cancel      context.CancelFunc
	running     bool
}

// New creates a Reconciler.
func New(database *db.DB, agentClient AgentClient, interval time.Duration) *Reconciler {
	return &Reconciler{
		db:          database,
		agentClient: agentClient,
		interval:    interval,
	}
}

// SetHub attaches the agent connection hub so the reconciler can push routes to
// agents over their live stream. Without it, the reconciler falls back to the
// inbound agent client.
func (r *Reconciler) SetHub(hub RouteHub) {
	r.hub = hub
}

// PushAgentRoutes computes an agent's desired route set and delivers it over its
// live stream. It's the instant-push entry point: API handlers call it the
// moment a domain changes, so connected agents apply config without waiting for
// the next reconcile tick. A no-op if the agent isn't currently connected.
func (r *Reconciler) PushAgentRoutes(agentID string) error {
	if r.hub == nil || !r.hub.Connected(agentID) {
		return nil
	}
	agent, err := r.db.GetAgent(agentID)
	if err != nil {
		return fmt.Errorf("loading agent %s: %w", agentID, err)
	}
	desired, err := r.buildDesiredRoutes(agent)
	if err != nil {
		return err
	}
	routes := make([]json.RawMessage, 0, len(desired))
	for _, d := range desired {
		routes = append(routes, d.route)
	}
	r.hub.PublishRoutes(agentID, routes)
	return nil
}

// Start launches the periodic reconciliation loop in a background goroutine.
func (r *Reconciler) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true

	go r.loop(ctx)
}

// Stop halts the periodic loop. It is safe to call even if the loop is not
// running.
func (r *Reconciler) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}

	r.cancel()
	r.running = false
}

// Running reports whether the reconciliation loop is active.
func (r *Reconciler) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *Reconciler) loop(ctx context.Context) {
	// Run once immediately, then on the ticker.
	if err := r.RunOnce(ctx); err != nil {
		log.Printf("reconciler: initial cycle failed: %v", err)
	}

	// A timer (reset each cycle) lets us pick up interval changes made through
	// the dashboard settings without restarting the orchestrator.
	timer := time.NewTimer(r.currentInterval())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := r.RunOnce(ctx); err != nil {
				log.Printf("reconciler: cycle failed: %v", err)
			}
			timer.Reset(r.currentInterval())
		}
	}
}

// currentInterval returns the configured reconciler interval, re-reading the
// reconciler_interval setting on each cycle so changes take effect live. It
// falls back to the interval the reconciler was constructed with.
func (r *Reconciler) currentInterval() time.Duration {
	if v, err := r.db.GetSetting("reconciler_interval"); err == nil && v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 5 {
			return time.Duration(secs) * time.Second
		}
	}
	return r.interval
}

// RunOnce executes a single reconciliation cycle. It is safe to call
// concurrently with the periodic loop.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	log.Println("reconciler: starting cycle")

	if err := r.reconcileAgents(ctx); err != nil {
		log.Printf("reconciler: agents phase failed: %v", err)
		// Continue with the other phases even if agents fail.
	}

	// Tear down domains marked for deletion before reconciling the rest, so we
	// don't re-create records/routes for them.
	if err := r.reconcileDeletions(ctx); err != nil {
		log.Printf("reconciler: deletions phase failed: %v", err)
	}

	// Reconcile routes for each adopted agent.
	agents, err := r.db.ListAgents()
	if err != nil {
		return fmt.Errorf("listing agents for route reconciliation: %w", err)
	}
	for i := range agents {
		if agents[i].Status != models.AgentStatusAdopted {
			continue
		}
		if err := r.reconcileRoutes(ctx, &agents[i]); err != nil {
			log.Printf("reconciler: routes for agent %s failed: %v", agents[i].ID, err)
		}
	}

	if err := r.reconcileDNS(ctx); err != nil {
		log.Printf("reconciler: DNS phase failed: %v", err)
	}

	if err := r.reconcileAgentDNS(ctx); err != nil {
		log.Printf("reconciler: agent DNS phase failed: %v", err)
	}

	log.Println("reconciler: cycle complete")
	return nil
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

// reconcileAgents derives each adopted agent's online/offline state from the
// freshness of its last heartbeat — NOT from whether the orchestrator can reach
// the agent inbound. Agents live behind NAT/firewalls and dial home; an inbound
// probe would (wrongly) report every such agent as offline. The agent proves it
// is alive by heartbeating out; if those stop arriving for longer than the
// configured timeout, we mark it offline.
func (r *Reconciler) reconcileAgents(_ context.Context) error {
	agents, err := r.db.ListAgents()
	if err != nil {
		return fmt.Errorf("listing agents: %w", err)
	}

	timeout := r.offlineTimeout()
	now := time.Now().UTC()

	for i := range agents {
		a := &agents[i]
		if a.Status != models.AgentStatusAdopted && a.Status != models.AgentStatusOffline {
			continue
		}

		stale := a.LastSeen == nil || now.Sub(a.LastSeen.UTC()) > timeout

		if stale {
			if a.Status != models.AgentStatusOffline {
				if dbErr := r.db.UpdateAgentStatus(a.ID, models.AgentStatusOffline); dbErr != nil {
					log.Printf("reconciler: failed to mark agent %s offline: %v", a.ID, dbErr)
				}
				r.audit("agent", a.ID, "status_change", fmt.Sprintf("marked offline: no heartbeat for > %s", timeout))
			}
			continue
		}

		// Heartbeat is fresh. The heartbeat handler normally flips offline->adopted
		// on receipt; this covers the case where last_seen was refreshed by another
		// path (e.g. a live event stream) while the row still read offline.
		if a.Status == models.AgentStatusOffline {
			if dbErr := r.db.UpdateAgentStatus(a.ID, models.AgentStatusAdopted); dbErr != nil {
				log.Printf("reconciler: failed to mark agent %s adopted: %v", a.ID, dbErr)
			}
			r.audit("agent", a.ID, "status_change", "agent came back online")
		}
	}

	return nil
}

// offlineTimeout is how long an agent may go without a heartbeat before it is
// considered offline. It reads the agent_offline_timeout setting (seconds),
// clamped to a sane floor so a misconfiguration can't make agents flap.
func (r *Reconciler) offlineTimeout() time.Duration {
	const def = 90 * time.Second
	const floor = 15 * time.Second
	if v, err := r.db.GetSetting("agent_offline_timeout"); err == nil && v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			d := time.Duration(secs) * time.Second
			if d < floor {
				return floor
			}
			return d
		}
	}
	return def
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// buildDesiredRoutes computes the route set an agent should be serving, keyed by
// FQDN, straight from the database. It is shared by the inbound reconcile path
// and by PushAgentRoutes (which delivers the same set over the agent's stream),
// so both paths always agree on desired state.
func (r *Reconciler) buildDesiredRoutes(agent *models.Agent) (map[string]desiredRoute, error) {
	domains, err := r.db.ListDomainsByAgent(agent.ID)
	if err != nil {
		return nil, fmt.Errorf("listing domains for agent %s: %w", agent.ID, err)
	}

	zoneNames := make(map[string]string) // zoneID -> name

	desiredByFQDN := make(map[string]desiredRoute)
	for i := range domains {
		dom := &domains[i]

		// Domains being deleted are handled by reconcileDeletions; do not
		// (re-)push routes for them here.
		if dom.Status == models.DomainStatusDeleting {
			continue
		}

		// Resolve zone name from the domain's zone.
		zoneName, ok := zoneNames[dom.ZoneID]
		if !ok {
			zone, zErr := r.db.GetZone(dom.ZoneID)
			if zErr != nil {
				log.Printf("reconciler: cannot resolve zone %s for domain %d: %v", dom.ZoneID, dom.ID, zErr)
				continue
			}
			zoneName = zone.Name
			zoneNames[dom.ZoneID] = zoneName
		}
		fqdn := dom.FQDN(zoneName)

		// Resolve server address.
		srv, sErr := r.db.GetServer(dom.ServerID)
		if sErr != nil {
			log.Printf("reconciler: cannot resolve server %s for domain %d: %v", dom.ServerID, dom.ID, sErr)
			continue
		}

		route, gErr := caddygen.GenerateRoute(caddygen.ConfigFromDomain(*dom, fqdn, srv.Address))
		if gErr != nil {
			log.Printf("reconciler: cannot generate route for domain %d (%s): %v", dom.ID, fqdn, gErr)
			if dErr := r.db.UpdateDomainStatus(dom.ID, models.DomainStatusError, fmt.Sprintf("route generation failed: %v", gErr)); dErr != nil {
				log.Printf("reconciler: failed to update domain status: %v", dErr)
			}
			continue
		}

		desiredByFQDN[fqdn] = desiredRoute{
			domain: dom,
			fqdn:   fqdn,
			route:  route,
		}
	}

	return desiredByFQDN, nil
}

func (r *Reconciler) reconcileRoutes(ctx context.Context, agent *models.Agent) error {
	desiredByFQDN, err := r.buildDesiredRoutes(agent)
	if err != nil {
		return err
	}

	// Prefer the live stream: if the agent holds an open connection, push the
	// desired set down it and stop. This is the path that works behind NAT (the
	// agent dialed us) and the one to rely on in production; the agent applies
	// the set locally and reports domain status back via its ACK. The inbound
	// diff below is the fallback for same-host / port-forwarded setups where the
	// orchestrator can reach the agent directly.
	if r.hub != nil && r.hub.Connected(agent.ID) {
		routes := make([]json.RawMessage, 0, len(desiredByFQDN))
		for _, d := range desiredByFQDN {
			routes = append(routes, d.route)
		}
		r.hub.PublishRoutes(agent.ID, routes)
		return nil
	}

	// Get actual routes from the agent.
	actualRoutes, err := r.agentClient.GetRoutes(ctx, agent.APIURL, agent.TokenHash)
	if err != nil {
		return fmt.Errorf("getting routes from agent %s: %w", agent.ID, err)
	}

	// Build a map of actual routes keyed by the host(s) in their match.
	actualByFQDN := make(map[string]json.RawMessage)
	for _, raw := range actualRoutes {
		fqdn := extractHostFromRoute(raw)
		if fqdn != "" {
			actualByFQDN[fqdn] = raw
		}
	}

	// Diff: desired vs actual.
	for fqdn, desired := range desiredByFQDN {
		actual, exists := actualByFQDN[fqdn]
		if !exists {
			// Missing on agent — push it.
			log.Printf("reconciler: pushing missing route for %s to agent %s", fqdn, agent.ID)
			if pErr := r.agentClient.PushRoute(ctx, agent.APIURL, agent.TokenHash, desired.route); pErr != nil {
				log.Printf("reconciler: failed to push route for %s: %v", fqdn, pErr)
				if dErr := r.db.UpdateDomainStatus(desired.domain.ID, models.DomainStatusError, fmt.Sprintf("route push failed: %v", pErr)); dErr != nil {
					log.Printf("reconciler: failed to update domain status: %v", dErr)
				}
				r.audit("domain", fmt.Sprintf("%d", desired.domain.ID), "route_push_failed", pErr.Error())
				continue
			}
			r.audit("domain", fmt.Sprintf("%d", desired.domain.ID), "route_pushed", "pushed missing route to agent")
			if dErr := r.db.MarkDomainSynced(desired.domain.ID); dErr != nil {
				log.Printf("reconciler: failed to mark domain synced: %v", dErr)
			}
			continue
		}

		// Route exists — check for config mismatch.
		if routesMatch(desired.route, actual) {
			// All good — keep last_synced fresh so the dashboard reflects the
			// most recent successful reconciliation.
			if dErr := r.db.MarkDomainSynced(desired.domain.ID); dErr != nil {
				log.Printf("reconciler: failed to mark domain synced: %v", dErr)
			}
			continue
		}

		// Config mismatch detected.
		if desired.domain.ManualConfig {
			// Respect manual config — warn but don't overwrite.
			log.Printf("reconciler: drift detected for %s (manual_config=true), skipping correction", fqdn)
			r.audit("domain", fmt.Sprintf("%d", desired.domain.ID), "drift_detected", "manual config — not overwriting")
			continue
		}

		// Push corrected route.
		log.Printf("reconciler: fixing drift for %s on agent %s", fqdn, agent.ID)
		if pErr := r.agentClient.PushRoute(ctx, agent.APIURL, agent.TokenHash, desired.route); pErr != nil {
			log.Printf("reconciler: failed to fix drift for %s: %v", fqdn, pErr)
			if dErr := r.db.UpdateDomainStatus(desired.domain.ID, models.DomainStatusError, fmt.Sprintf("drift fix failed: %v", pErr)); dErr != nil {
				log.Printf("reconciler: failed to update domain status: %v", dErr)
			}
			r.audit("domain", fmt.Sprintf("%d", desired.domain.ID), "drift_fix_failed", pErr.Error())
			continue
		}
		r.audit("domain", fmt.Sprintf("%d", desired.domain.ID), "drift_fixed", "pushed corrected route to agent")
		if dErr := r.db.MarkDomainSynced(desired.domain.ID); dErr != nil {
			log.Printf("reconciler: failed to mark domain synced: %v", dErr)
		}
	}

	// Check for unmanaged routes (on agent but not in DB).
	for fqdn := range actualByFQDN {
		if _, desired := desiredByFQDN[fqdn]; !desired {
			log.Printf("reconciler: WARNING unmanaged route %s on agent %s", fqdn, agent.ID)
			r.audit("agent", agent.ID, "unmanaged_route", fmt.Sprintf("unmanaged route detected: %s", fqdn))
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

func (r *Reconciler) reconcileDNS(ctx context.Context) error {
	domains, err := r.db.ListDomains(db.DomainFilter{})
	if err != nil {
		return fmt.Errorf("listing domains: %w", err)
	}

	for i := range domains {
		dom := &domains[i]

		// Skip domains not in an actionable state.
		if dom.Status == models.DomainStatusDeleting {
			continue
		}

		// Resolve zone -> provider chain.
		zone, zErr := r.db.GetZone(dom.ZoneID)
		if zErr != nil {
			log.Printf("reconciler: cannot get zone %s for domain %d: %v", dom.ZoneID, dom.ID, zErr)
			continue
		}

		prov, pErr := r.db.GetProvider(zone.ProviderID)
		if pErr != nil {
			log.Printf("reconciler: cannot get provider %s for zone %s: %v", zone.ProviderID, zone.ID, pErr)
			continue
		}

		dnsProvider, pErr := provider.Get(prov.Type)
		if pErr != nil {
			log.Printf("reconciler: DNS provider %s not registered: %v", prov.Type, pErr)
			continue
		}

		// Merge zone's external ID into provider config for DNS API calls.
		provConfig := mergeZoneIDIntoConfig(prov.Config, zone.ExternalID)

		fqdn := dom.FQDN(zone.Name)

		// Resolve: domain -> server -> agent -> agent.FQDN for CNAME target.
		srv, sErr := r.db.GetServer(dom.ServerID)
		if sErr != nil {
			log.Printf("reconciler: cannot get server %s for domain %d: %v", dom.ServerID, dom.ID, sErr)
			continue
		}

		agent, aErr := r.db.GetAgent(srv.AgentID)
		if aErr != nil {
			log.Printf("reconciler: cannot get agent %s for domain %d: %v", srv.AgentID, dom.ID, aErr)
			continue
		}

		expectedTarget := agent.FQDN

		if dom.DNSRecordID == "" {
			// No record yet — create it.
			recordID, cErr := dnsProvider.CreateRecord(ctx, provConfig, provider.Record{
				Type:    "CNAME",
				Name:    fqdn,
				Content: expectedTarget,
				TTL:     0,
			})
			if cErr != nil {
				log.Printf("reconciler: failed to create DNS record for %s: %v", fqdn, cErr)
				if dErr := r.db.UpdateDomainStatus(dom.ID, models.DomainStatusError, fmt.Sprintf("DNS create failed: %v", cErr)); dErr != nil {
					log.Printf("reconciler: failed to update domain status: %v", dErr)
				}
				r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_create_failed", cErr.Error())
				continue
			}

			if dErr := r.db.UpdateDomainDNSRecord(dom.ID, recordID); dErr != nil {
				log.Printf("reconciler: failed to store DNS record ID for domain %d: %v", dom.ID, dErr)
			}
			r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_created", fmt.Sprintf("created CNAME %s -> %s", fqdn, expectedTarget))
			continue
		}

		// Record exists — verify content.
		rec, gErr := dnsProvider.GetRecord(ctx, provConfig, dom.DNSRecordID)
		if gErr != nil {
			// Record not found — recreate.
			log.Printf("reconciler: DNS record %s not found for domain %d, recreating: %v", dom.DNSRecordID, dom.ID, gErr)
			recordID, cErr := dnsProvider.CreateRecord(ctx, provConfig, provider.Record{
				Type:    "CNAME",
				Name:    fqdn,
				Content: expectedTarget,
				TTL:     0,
			})
			if cErr != nil {
				log.Printf("reconciler: failed to recreate DNS record for %s: %v", fqdn, cErr)
				if dErr := r.db.UpdateDomainStatus(dom.ID, models.DomainStatusError, fmt.Sprintf("DNS recreate failed: %v", cErr)); dErr != nil {
					log.Printf("reconciler: failed to update domain status: %v", dErr)
				}
				r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_recreate_failed", cErr.Error())
				continue
			}
			if dErr := r.db.UpdateDomainDNSRecord(dom.ID, recordID); dErr != nil {
				log.Printf("reconciler: failed to store DNS record ID: %v", dErr)
			}
			r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_recreated", fmt.Sprintf("recreated CNAME %s -> %s", fqdn, expectedTarget))
			continue
		}

		// Record exists and was retrieved — check content.
		if rec.Content != expectedTarget {
			log.Printf("reconciler: DNS drift for %s: have %s, want %s", fqdn, rec.Content, expectedTarget)
			if uErr := dnsProvider.UpdateRecord(ctx, provConfig, dom.DNSRecordID, provider.Record{
				Type:    "CNAME",
				Name:    fqdn,
				Content: expectedTarget,
				TTL:     0,
			}); uErr != nil {
				log.Printf("reconciler: failed to update DNS record for %s: %v", fqdn, uErr)
				if dErr := r.db.UpdateDomainStatus(dom.ID, models.DomainStatusError, fmt.Sprintf("DNS update failed: %v", uErr)); dErr != nil {
					log.Printf("reconciler: failed to update domain status: %v", dErr)
				}
				r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_update_failed", uErr.Error())
				continue
			}
			r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_updated", fmt.Sprintf("updated CNAME %s: %s -> %s", fqdn, rec.Content, expectedTarget))
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Agent A records (FQDN -> public IP) and DDNS
// ---------------------------------------------------------------------------

// reconcileAgentDNS ensures every adopted agent has an A record for its FQDN
// pointing at its current public IP. In DDNS mode the record is updated whenever
// the IP changes; in static mode it is created once and left untouched (an admin
// can force an update through the API).
func (r *Reconciler) reconcileAgentDNS(ctx context.Context) error {
	agents, err := r.db.ListAgents()
	if err != nil {
		return fmt.Errorf("listing agents: %w", err)
	}

	for i := range agents {
		a := &agents[i]
		if a.Status != models.AgentStatusAdopted && a.Status != models.AgentStatusOffline {
			continue
		}
		if a.PublicIP == "" {
			continue // nothing to point the record at yet
		}

		// Find the zone (among the agent's assigned zones) that the FQDN lives in.
		zones, zErr := r.db.ListAgentZones(a.ID)
		if zErr != nil {
			log.Printf("reconciler: cannot list zones for agent %s: %v", a.ID, zErr)
			continue
		}
		zone := matchZoneForFQDN(a.FQDN, zones)
		if zone == nil {
			// FQDN not covered by any assigned zone — we can't create its A record,
			// and every domain CNAME pointing at this FQDN will dangle. Surface a
			// clear, actionable error instead of failing silently.
			msg := fmt.Sprintf("FQDN %q is not inside any assigned DNS zone — set the agent's anchor to a host within one of its zones (e.g. host.%s) or assign the matching zone", a.FQDN, firstZoneName(zones))
			r.setAgentDNSError(a, msg)
			continue
		}
		// FQDN is inside a managed zone — clear any prior "outside zone" error.
		r.setAgentDNSError(a, "")

		prov, pErr := r.db.GetProvider(zone.ProviderID)
		if pErr != nil {
			log.Printf("reconciler: cannot get provider %s for agent %s: %v", zone.ProviderID, a.ID, pErr)
			continue
		}
		dnsProvider, gErr := provider.Get(prov.Type)
		if gErr != nil {
			log.Printf("reconciler: provider %s not registered: %v", prov.Type, gErr)
			continue
		}
		provConfig := mergeZoneIDIntoConfig(prov.Config, zone.ExternalID)

		rec := provider.Record{Type: "A", Name: a.FQDN, Content: a.PublicIP, TTL: 0}

		if a.DNSRecordID == "" {
			recordID, cErr := dnsProvider.CreateRecord(ctx, provConfig, rec)
			if cErr != nil {
				log.Printf("reconciler: failed to create A record for agent %s: %v", a.ID, cErr)
				r.audit("agent", a.ID, "a_record_create_failed", cErr.Error())
				continue
			}
			a.DNSRecordID = recordID
			if uErr := r.db.UpdateAgentDNSRecord(a.ID, recordID); uErr != nil {
				log.Printf("reconciler: failed to persist A record id for agent %s: %v", a.ID, uErr)
			}
			r.audit("agent", a.ID, "a_record_created", fmt.Sprintf("created A %s -> %s", a.FQDN, a.PublicIP))
			continue
		}

		// Static mode: created once, never auto-updated.
		if a.DNSMode != models.DNSModeDDNS {
			continue
		}

		// DDNS mode: update only when the IP actually changed.
		existing, gErr := dnsProvider.GetRecord(ctx, provConfig, a.DNSRecordID)
		if gErr != nil {
			// The provider gives a generic error for transient failures and
			// genuine 404s alike. Recreating here would risk duplicate records
			// on a transient error, so skip and retry next cycle instead.
			log.Printf("reconciler: cannot read A record %s for agent %s, skipping this cycle: %v", a.DNSRecordID, a.ID, gErr)
			continue
		}

		if existing.Content == a.PublicIP {
			continue // already up to date — avoid an unnecessary API call
		}

		if uErr := dnsProvider.UpdateRecord(ctx, provConfig, a.DNSRecordID, rec); uErr != nil {
			log.Printf("reconciler: failed to update A record for agent %s: %v", a.ID, uErr)
			r.audit("agent", a.ID, "a_record_update_failed", uErr.Error())
			continue
		}
		r.audit("agent", a.ID, "ddns_updated", fmt.Sprintf("updated A %s: %s -> %s", a.FQDN, existing.Content, a.PublicIP))
	}

	return nil
}

// setAgentDNSError persists an orchestrator-side DNS error for the agent, but
// only when it actually changed — avoiding a write (and audit-log spam) on every
// reconcile cycle for a steady-state condition. It keeps the in-memory agent in
// sync so later phases in the same cycle see the new value.
func (r *Reconciler) setAgentDNSError(a *models.Agent, msg string) {
	if a.DNSError == msg {
		return
	}
	if err := r.db.SetAgentDNSError(a.ID, msg); err != nil {
		log.Printf("reconciler: failed to set dns_error for agent %s: %v", a.ID, err)
		return
	}
	a.DNSError = msg
	if msg != "" {
		r.audit("agent", a.ID, "dns_error", msg)
	} else {
		r.audit("agent", a.ID, "dns_error_cleared", "FQDN now resolves to an assigned zone")
	}
}

// firstZoneName returns a representative zone name for use in hints, or a
// placeholder when the agent has no assigned zones.
func firstZoneName(zones []models.Zone) string {
	if len(zones) > 0 {
		return zones[0].Name
	}
	return "example.com"
}

// matchZoneForFQDN returns the zone whose name is the longest suffix of fqdn
// (so "host.sub.example.com" prefers "sub.example.com" over "example.com").
func matchZoneForFQDN(fqdn string, zones []models.Zone) *models.Zone {
	var best *models.Zone
	for i := range zones {
		z := &zones[i]
		if fqdn == z.Name || strings.HasSuffix(fqdn, "."+z.Name) {
			if best == nil || len(z.Name) > len(best.Name) {
				best = z
			}
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Deletions
// ---------------------------------------------------------------------------

// reconcileDeletions tears down domains whose status is "deleting": it removes
// the CNAME record at the DNS provider, removes the route from the agent, then
// deletes the domain row from the database.
func (r *Reconciler) reconcileDeletions(ctx context.Context) error {
	domains, err := r.db.ListDomains(db.DomainFilter{Status: string(models.DomainStatusDeleting)})
	if err != nil {
		return fmt.Errorf("listing domains to delete: %w", err)
	}

	for i := range domains {
		dom := &domains[i]

		// Best-effort DNS record cleanup.
		if dom.DNSRecordID != "" {
			if zone, prov, dnsProvider, ok := r.resolveDNS(dom.ZoneID); ok {
				provConfig := mergeZoneIDIntoConfig(prov.Config, zone.ExternalID)
				if dErr := dnsProvider.DeleteRecord(ctx, provConfig, dom.DNSRecordID); dErr != nil {
					log.Printf("reconciler: failed to delete DNS record %s for domain %d: %v", dom.DNSRecordID, dom.ID, dErr)
					r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_delete_failed", dErr.Error())
					// Keep the domain around so we retry next cycle.
					continue
				}
				r.audit("domain", fmt.Sprintf("%d", dom.ID), "dns_deleted", fmt.Sprintf("deleted record %s", dom.DNSRecordID))
			}
		}

		// Best-effort route cleanup on the owning agent.
		if zone, err := r.db.GetZone(dom.ZoneID); err == nil {
			fqdn := dom.FQDN(zone.Name)
			if srv, sErr := r.db.GetServer(dom.ServerID); sErr == nil {
				if agent, aErr := r.db.GetAgent(srv.AgentID); aErr == nil {
					if rErr := r.agentClient.DeleteRoute(ctx, agent.APIURL, agent.TokenHash, fqdn); rErr != nil {
						// Agent may be offline; the route will be flagged as
						// unmanaged later. Don't block domain deletion on it.
						log.Printf("reconciler: failed to delete route %s on agent %s: %v", fqdn, agent.ID, rErr)
					}
				}
			}
		}

		// Finally remove the domain row.
		if dErr := r.db.DeleteDomain(dom.ID); dErr != nil {
			log.Printf("reconciler: failed to delete domain row %d: %v", dom.ID, dErr)
			continue
		}
		r.audit("domain", fmt.Sprintf("%d", dom.ID), "deleted", "domain removed after cleanup")
	}

	return nil
}

// resolveDNS resolves a zone ID to its zone, provider, and DNS provider plugin.
// It returns ok=false (after logging) if any step fails.
func (r *Reconciler) resolveDNS(zoneID string) (*models.Zone, *models.Provider, provider.Provider, bool) {
	zone, err := r.db.GetZone(zoneID)
	if err != nil {
		log.Printf("reconciler: cannot get zone %s: %v", zoneID, err)
		return nil, nil, nil, false
	}
	prov, err := r.db.GetProvider(zone.ProviderID)
	if err != nil {
		log.Printf("reconciler: cannot get provider %s for zone %s: %v", zone.ProviderID, zone.ID, err)
		return nil, nil, nil, false
	}
	dnsProvider, err := provider.Get(prov.Type)
	if err != nil {
		log.Printf("reconciler: DNS provider %s not registered: %v", prov.Type, err)
		return nil, nil, nil, false
	}
	return zone, prov, dnsProvider, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type desiredRoute struct {
	domain *models.Domain
	fqdn   string
	route  json.RawMessage
}

// mergeZoneIDIntoConfig injects the zone's external ID into the provider config
// so the DNS provider can target the correct zone.
func mergeZoneIDIntoConfig(providerConfig string, zoneExternalID string) json.RawMessage {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(providerConfig), &cfg); err != nil {
		cfg = make(map[string]interface{})
	}
	cfg["zone_id"] = zoneExternalID
	merged, _ := json.Marshal(cfg)
	return json.RawMessage(merged)
}

// extractHostFromRoute pulls the first host out of a Caddy route JSON blob.
func extractHostFromRoute(raw json.RawMessage) string {
	var partial struct {
		Match []struct {
			Host []string `json:"host"`
		} `json:"match"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil {
		return ""
	}
	if len(partial.Match) > 0 && len(partial.Match[0].Host) > 0 {
		return partial.Match[0].Host[0]
	}
	return ""
}

// routesMatch compares two Caddy route JSON blobs for semantic equality. It
// delegates to the shared caddyeq comparator (the single source of truth for
// Caddy semantic equality, also used to gate version writes in §4/§11), so the
// reconciler's reload-suppression and the store's phantom-version suppression
// stay in lock-step.
func routesMatch(a, b json.RawMessage) bool {
	return caddyeq.Equal(string(a), string(b))
}

// audit is a convenience wrapper that logs to both the audit table and stderr.
func (r *Reconciler) audit(entityType, entityID, action, details string) {
	log.Printf("reconciler: audit %s/%s %s: %s", entityType, entityID, action, details)
	entry := &models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      "reconciler",
		Source:     models.AuditSourceSystem,
		Details:    details,
	}
	if err := r.db.InsertAuditLog(entry); err != nil {
		log.Printf("reconciler: failed to insert audit log: %v", err)
	}
}
