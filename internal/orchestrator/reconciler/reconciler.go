// Package reconciler is the core state-sync engine for NurProxy. It
// periodically compares desired state (DB) with actual state (agent routes +
// DNS records) and fixes any drift.
package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
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

// Reconciler periodically syncs desired state (database) with actual state
// (agent routes and DNS records).
type Reconciler struct {
	db          *db.DB
	agentClient AgentClient
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

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil {
				log.Printf("reconciler: cycle failed: %v", err)
			}
		}
	}
}

// RunOnce executes a single reconciliation cycle. It is safe to call
// concurrently with the periodic loop.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	log.Println("reconciler: starting cycle")

	if err := r.reconcileAgents(ctx); err != nil {
		log.Printf("reconciler: agents phase failed: %v", err)
		// Continue with the other phases even if agents fail.
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

	log.Println("reconciler: cycle complete")
	return nil
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

func (r *Reconciler) reconcileAgents(ctx context.Context) error {
	agents, err := r.db.ListAgents()
	if err != nil {
		return fmt.Errorf("listing agents: %w", err)
	}

	for i := range agents {
		a := &agents[i]
		if a.Status != models.AgentStatusAdopted && a.Status != models.AgentStatusOffline {
			continue
		}

		err := r.agentClient.Health(ctx, a.APIURL, a.TokenHash)
		if err != nil {
			// Agent unreachable — mark offline if not already.
			if a.Status != models.AgentStatusOffline {
				if dbErr := r.db.UpdateAgentStatus(a.ID, models.AgentStatusOffline); dbErr != nil {
					log.Printf("reconciler: failed to mark agent %s offline: %v", a.ID, dbErr)
				}
				r.audit("agent", a.ID, "status_change", fmt.Sprintf("marked offline: %v", err))
			}
			continue
		}

		// Agent is reachable.
		if a.Status == models.AgentStatusOffline {
			// Came back online.
			if dbErr := r.db.UpdateAgentStatus(a.ID, models.AgentStatusAdopted); dbErr != nil {
				log.Printf("reconciler: failed to mark agent %s adopted: %v", a.ID, dbErr)
			}
			r.audit("agent", a.ID, "status_change", "agent came back online")
		}

		// Update last_seen.
		if dbErr := r.db.UpdateAgentHeartbeat(a.ID, a.PublicIP); dbErr != nil {
			log.Printf("reconciler: failed to update heartbeat for agent %s: %v", a.ID, dbErr)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

func (r *Reconciler) reconcileRoutes(ctx context.Context, agent *models.Agent) error {
	// Get desired routes from DB.
	domains, err := r.db.ListDomainsByAgent(agent.ID)
	if err != nil {
		return fmt.Errorf("listing domains for agent %s: %w", agent.ID, err)
	}

	// Look up provider zone names for FQDN construction.
	type providerCache struct {
		zoneName string
	}
	provCache := make(map[string]providerCache)

	// Build the expected set of routes keyed by FQDN.
	desiredByFQDN := make(map[string]desiredRoute)
	for i := range domains {
		dom := &domains[i]

		// Resolve zone name from the domain's provider.
		pc, ok := provCache[dom.ProviderID]
		if !ok {
			prov, pErr := r.db.GetProvider(dom.ProviderID)
			if pErr != nil {
				log.Printf("reconciler: cannot resolve provider %s for domain %d: %v", dom.ProviderID, dom.ID, pErr)
				continue
			}
			pc = providerCache{zoneName: prov.ZoneName}
			provCache[dom.ProviderID] = pc
		}
		fqdn := dom.FQDN(pc.zoneName)

		// Resolve server address.
		srv, sErr := r.db.GetServer(dom.ServerID)
		if sErr != nil {
			log.Printf("reconciler: cannot resolve server %s for domain %d: %v", dom.ServerID, dom.ID, sErr)
			continue
		}

		cfg := caddygen.DomainConfig{
			FQDN:                  fqdn,
			UpstreamAddr:          srv.Address,
			UpstreamPort:          dom.Port,
			WebSocket:             dom.ProxyConfig.WebSocket,
			ForceHTTPS:            dom.ProxyConfig.ForceHTTPS,
			MaxBodySize:           dom.ProxyConfig.MaxBodySize,
			CustomRequestHeaders:  dom.ProxyConfig.CustomRequestHeaders,
			CustomResponseHeaders: dom.ProxyConfig.CustomResponseHeaders,
			UpstreamScheme:        dom.ProxyConfig.UpstreamScheme,
			RawCaddy:              dom.ProxyConfig.RawCaddy,
		}

		route, gErr := caddygen.GenerateRoute(cfg)
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
			if dErr := r.db.UpdateDomainStatus(desired.domain.ID, models.DomainStatusActive, ""); dErr != nil {
				log.Printf("reconciler: failed to update domain status: %v", dErr)
			}
			continue
		}

		// Route exists — check for config mismatch.
		if routesMatch(desired.route, actual) {
			// All good.
			if desired.domain.Status != models.DomainStatusActive {
				if dErr := r.db.UpdateDomainStatus(desired.domain.ID, models.DomainStatusActive, ""); dErr != nil {
					log.Printf("reconciler: failed to update domain status: %v", dErr)
				}
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
		if dErr := r.db.UpdateDomainStatus(desired.domain.ID, models.DomainStatusActive, ""); dErr != nil {
			log.Printf("reconciler: failed to update domain status: %v", dErr)
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

		// Resolve the provider.
		prov, pErr := r.db.GetProvider(dom.ProviderID)
		if pErr != nil {
			log.Printf("reconciler: cannot get provider %s for domain %d: %v", dom.ProviderID, dom.ID, pErr)
			continue
		}

		dnsProvider, pErr := provider.Get(prov.Type)
		if pErr != nil {
			log.Printf("reconciler: DNS provider %s not registered: %v", prov.Type, pErr)
			continue
		}

		provConfig := json.RawMessage(prov.Config)

		// Resolve: domain → server → agent → agent.FQDN for CNAME target.
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

		fqdn := dom.FQDN(prov.ZoneName)
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
// Helpers
// ---------------------------------------------------------------------------

type desiredRoute struct {
	domain *models.Domain
	fqdn   string
	route  json.RawMessage
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

// routesMatch compares two route JSON blobs for semantic equality.
// It normalises by unmarshalling into maps and re-marshalling.
func routesMatch(a, b json.RawMessage) bool {
	var ma, mb interface{}
	if err := json.Unmarshal(a, &ma); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &mb); err != nil {
		return false
	}
	ja, _ := json.Marshal(ma)
	jb, _ := json.Marshal(mb)
	return string(ja) == string(jb)
}

// audit is a convenience wrapper that logs to both the audit table and stderr.
func (r *Reconciler) audit(entityType, entityID, action, details string) {
	log.Printf("reconciler: audit %s/%s %s: %s", entityType, entityID, action, details)
	entry := &models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      "reconciler",
		Details:    details,
	}
	if err := r.db.InsertAuditLog(entry); err != nil {
		log.Printf("reconciler: failed to insert audit log: %v", err)
	}
}

