package api

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/dnsname"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/ratelimit"
)

// registerLimiter blunts abuse of the unauthenticated /agents/register endpoint:
// too many register attempts from one IP within the window trip a temporary
// lockout, so an attacker can't hammer the endpoint (each attempt runs a linear
// token-hash scan via CreateAgent's uniqueness check and writes a pending row).
// It lives at package scope because the endpoint's handler is the only caller
// and the Server's constructor (server.go) is owned by another unit; keying on
// the peer IP makes a single shared limiter correct regardless of Server count.
//
// 10 attempts per IP within 15 min → locked out for 15 min. A legitimate agent
// registers once (and retries a handful of times at most), so this is generous
// for real adoption while still capping a flood.
var registerLimiter = ratelimit.New(10, 15*time.Minute, 15*time.Minute)

// maxProxyDetectionEntries bounds each variable-length slice the agent supplies
// in its register payload's ProxyDetection. The body is already capped at a few
// MiB (readJSON), but that still permits tens of thousands of tiny entries; this
// caps what a single registration can persist into the agent row. Far above any
// real host's interface/log/upstream/conflict count.
const maxProxyDetectionEntries = 256

// GET /api/v1/agents
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	if agents == nil {
		agents = []models.Agent{}
	}

	// Build response with zones included
	type agentResponse struct {
		models.Agent
		Zones []models.Zone `json:"zones"`
	}
	resp := make([]agentResponse, len(agents))
	for i, a := range agents {
		zones, err := s.db.ListAgentZones(a.ID)
		if err != nil {
			zones = []models.Zone{}
		}
		if zones == nil {
			zones = []models.Zone{}
		}
		a.VersionStatus = s.agentVersionStatus(a.Version)
		resp[i] = agentResponse{
			Agent: a,
			Zones: zones,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/agents/register — called BY the agent during adoption.
// No auth required (agent doesn't have a token yet — it's registering one).
func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	// Per-IP rate limit: this endpoint is unauthenticated and does real work per
	// call (a uniqueness scan + a pending-row insert), so cap how fast one peer
	// can hit it. Each attempt consumes budget (there is no credential to verify
	// and clear on), so N attempts from one IP trip the lockout.
	ip := clientIP(r)
	if ok, retryAfter := registerLimiter.Allow(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many registration attempts; try again later")
		return
	}
	registerLimiter.Fail(ip)

	var req struct {
		ID                string                    `json:"id"`
		FQDN              string                    `json:"fqdn"`
		Token             string                    `json:"token"`
		APIURL            string                    `json:"api_url"`
		PublicIP          string                    `json:"public_ip"`
		PublicIP6         string                    `json:"public_ip6"`
		Version           string                    `json:"version"`
		ProxyDetection    *models.ProxyDetection    `json:"proxy_detection"`
		ProxyCapabilities *models.ProxyCapabilities `json:"proxy_capabilities"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.ID == "" || req.FQDN == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, "id, fqdn, and token are required")
		return
	}

	// Validate the FQDN at the boundary so a malformed anchor name is rejected
	// here rather than failing later at the DNS provider or in route rendering.
	req.FQDN = strings.TrimSpace(strings.ToLower(req.FQDN))
	if err := dnsname.ValidateSubdomain(req.FQDN); err != nil {
		writeError(w, http.StatusBadRequest, "invalid FQDN: "+err.Error())
		return
	}

	// Bound the variable-length detection slices a single registration can
	// persist (the body cap still permits many tiny entries).
	if d := req.ProxyDetection; d != nil {
		if len(d.LogPaths) > maxProxyDetectionEntries ||
			len(d.PortConflicts) > maxProxyDetectionEntries ||
			len(d.DiscoveredUpstreams) > maxProxyDetectionEntries ||
			len(d.Networks) > maxProxyDetectionEntries {
			writeError(w, http.StatusBadRequest, "proxy_detection has too many entries")
			return
		}
	}

	// Check for duplicate FQDN
	if existing, err := s.db.GetAgentByFQDN(req.FQDN); err == nil && existing != nil {
		writeError(w, http.StatusConflict, "agent with this FQDN already registered")
		return
	}

	// Hash the token before storing
	tokenHash := auth.HashToken(req.Token)

	agent := &models.Agent{
		ID:        req.ID,
		Name:      req.FQDN, // default name to FQDN until adoption
		FQDN:      req.FQDN,
		APIURL:    req.APIURL,
		TokenHash: tokenHash,
		PublicIP:  req.PublicIP,
		PublicIP6: req.PublicIP6,
		Status:    models.AgentStatusPending,
		Version:   req.Version,
		// Assume healthy until the agent reports otherwise via heartbeat, so a
		// freshly registered agent doesn't surface a spurious "Caddy down" error.
		CaddyRunning: true,
		// Phase-0 read-only detection (§13.0/§2.1/§9), carried on the agent's
		// outbound register payload. Stored as-is; refreshed by heartbeats.
		ProxyDetection: req.ProxyDetection,
		// Capability matrix (§8) for the agent's selected backend, including
		// module-probed options. Stored as-is; refreshed by heartbeats.
		ProxyCapabilities: req.ProxyCapabilities,
	}
	if req.ProxyDetection != nil {
		now := time.Now().UTC()
		agent.ProxyDetectedAt = &now
	}

	if err := s.db.CreateAgent(agent); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "agent already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	s.auditAs(r, models.AuditSourceAgent, "agent", agent.ID, "register", agent.FQDN)

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":     agent.ID,
		"status": string(agent.Status),
	})
}

// PUT /api/v1/agents/{id}/adopt
func (s *Server) handleAdoptAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	if agent.Status != models.AgentStatusPending {
		writeError(w, http.StatusBadRequest, "agent is not in pending state")
		return
	}

	var req struct {
		Name         string         `json:"name"`
		FQDN         string         `json:"fqdn"`
		ZoneIDs      []string       `json:"zone_ids"`
		DNSMode      models.DNSMode `json:"dns_mode"`
		DDNSInterval int            `json:"ddns_interval"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != "" {
		agent.Name = req.Name
	}
	if err := s.applyFQDNChange(agent, req.FQDN); err != nil {
		writeError(w, err.code, err.msg)
		return
	}
	if req.DNSMode != "" {
		agent.DNSMode = req.DNSMode
	}
	if req.DDNSInterval > 0 {
		agent.DDNSInterval = req.DDNSInterval
	}
	agent.Status = models.AgentStatusAdopted

	if err := s.db.UpdateAgent(agent); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to adopt agent")
		return
	}

	if len(req.ZoneIDs) > 0 {
		if err := s.db.SetAgentZones(id, req.ZoneIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to set agent zones")
			return
		}
	}

	s.audit(r, "agent", id, "adopt", agent.Name)

	writeJSON(w, http.StatusOK, agent)
}

// PUT /api/v1/agents/{id}/reject
func (s *Server) handleRejectAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	if agent.Status != models.AgentStatusPending {
		writeError(w, http.StatusBadRequest, "agent is not in pending state")
		return
	}

	if err := s.db.DeleteAgent(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reject agent")
		return
	}

	s.audit(r, "agent", id, "reject", agent.FQDN)

	writeJSON(w, http.StatusOK, map[string]string{"message": "agent rejected"})
}

// PUT /api/v1/agents/{id}
func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	var req struct {
		Name         *string         `json:"name"`
		FQDN         *string         `json:"fqdn"`
		ZoneIDs      *[]string       `json:"zone_ids"`
		DNSMode      *models.DNSMode `json:"dns_mode"`
		DDNSInterval *int            `json:"ddns_interval"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name != nil {
		agent.Name = *req.Name
	}
	if req.FQDN != nil {
		if err := s.applyFQDNChange(agent, *req.FQDN); err != nil {
			writeError(w, err.code, err.msg)
			return
		}
	}
	if req.DNSMode != nil {
		agent.DNSMode = *req.DNSMode
	}
	if req.DDNSInterval != nil {
		agent.DDNSInterval = *req.DDNSInterval
	}

	if err := s.db.UpdateAgent(agent); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update agent")
		return
	}

	if req.ZoneIDs != nil {
		if err := s.db.SetAgentZones(id, *req.ZoneIDs); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to set agent zones")
			return
		}
	}

	s.audit(r, "agent", id, "update", agent.Name)

	writeJSON(w, http.StatusOK, agent)
}

// DELETE /api/v1/agents/{id}
func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	if err := s.db.DeleteAgent(id); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	s.audit(r, "agent", id, "delete", "")

	writeJSON(w, http.StatusOK, map[string]string{"message": "agent deleted"})
}

// GET /api/v1/agents/{id}/status
func (s *Server) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only read its own status")
		return
	}

	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":                 agent.ID,
		"status":             agent.Status,
		"last_seen":          agent.LastSeen,
		"public_ip":          agent.PublicIP,
		"version":            agent.Version,
		"version_status":     s.agentVersionStatus(agent.Version),
		"caddy_running":      agent.CaddyRunning,
		"proxy_mode":         agent.ProxyMode,
		"last_error":         agent.LastError,
		"proxy_detection":    agent.ProxyDetection,
		"proxy_detected_at":  agent.ProxyDetectedAt,
		"proxy_capabilities": agent.ProxyCapabilities,
		"proxy_permissions":  agent.ProxyPermissions,
	})
}

// fqdnError carries an HTTP status + message out of applyFQDNChange.
type fqdnError struct {
	code int
	msg  string
}

func (e *fqdnError) Error() string { return e.msg }

// applyFQDNChange validates and applies an FQDN (anchor hostname) override onto
// the agent in place. A blank fqdn or one equal to the current value is a no-op.
// When the anchor actually moves, it clears the stored A- and AAAA-record ids
// (so the reconciler recreates both at the new name and the old records don't
// leak at the prior name) and any stale last_error.
func (s *Server) applyFQDNChange(agent *models.Agent, fqdn string) *fqdnError {
	fqdn = strings.TrimSpace(strings.ToLower(fqdn))
	if fqdn == "" || fqdn == agent.FQDN {
		return nil
	}
	if !validFQDN(fqdn) {
		return &fqdnError{http.StatusBadRequest, "invalid FQDN: must be a hostname like edge1.example.com"}
	}
	if existing, err := s.db.GetAgentByFQDN(fqdn); err == nil && existing != nil && existing.ID != agent.ID {
		return &fqdnError{http.StatusConflict, "another agent already uses this FQDN"}
	}
	agent.FQDN = fqdn
	agent.DNSRecordID = ""  // anchor moved — recreate the A record at the new name
	agent.DNSRecordID6 = "" // and the AAAA record, else the old one leaks at the prior name
	agent.DNSError = ""     // clear any stale "FQDN outside zone" error
	return nil
}

// validFQDN reports whether s is a syntactically valid multi-label DNS hostname
// (e.g. edge1.example.com). It is deliberately permissive but rejects schemes,
// ports, whitespace, single-label names, and malformed labels.
func validFQDN(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false // require at least one dot, so it lives inside a zone
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			isLetter := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLetter && !isDigit && c != '-' {
				return false
			}
		}
	}
	return true
}

// POST /api/v1/agents/{id}/heartbeat — called BY the agent.
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")

	// Verify the calling agent matches the target ID
	callerID, _ := r.Context().Value(ctxAgentID).(string)
	if callerID != id {
		writeError(w, http.StatusForbidden, "agent can only heartbeat for itself")
		return
	}

	var req struct {
		PublicIP  string `json:"public_ip"`
		PublicIP6 string `json:"public_ip6"`
		Version   string `json:"version"`
		// CaddyRunning and LastError are the agent's self-report. CaddyRunning is
		// a pointer so an older agent that omits it doesn't get read as "down".
		CaddyRunning *bool  `json:"caddy_running"`
		LastError    string `json:"last_error"`
		// ProxyMode is the agent's CURRENT live reverse-proxy mode ("built-in" |
		// "existing"), re-reported each beat (§19) so the dashboard reflects a
		// hot-switch. Empty leaves the stored mode untouched (older agent).
		ProxyMode string `json:"proxy_mode"`
		// ProxyDetection is the agent's read-only Phase-0 detection, re-reported on
		// each beat (§13.0/§2.1/§9). Stored on the agent row; nil leaves it as-is.
		ProxyDetection *models.ProxyDetection `json:"proxy_detection"`
		// ProxyCapabilities is the agent's capability matrix (§8) for its selected
		// backend, re-reported each beat. Stored on the agent row; nil leaves it
		// as-is (so a transient probe failure doesn't erase a known-good matrix).
		ProxyCapabilities *models.ProxyCapabilities `json:"proxy_capabilities"`
		// ProxyPermissions is the agent's §12 permission self-test (config writable?
		// service reloadable? + remediation), re-probed each beat in existing mode.
		// Stored on the agent row; built-in mode reports nil and we clear the column.
		ProxyPermissions *models.ProxyPermissions `json:"proxy_permissions"`
		// ArtifactChecksums is the agent's per-beat report of each managed
		// artifact's on-disk/live checksum (§11). The orchestrator compares each
		// against the accepted state and flags drift (on-disk != accepted), never
		// overwriting while unresolved. Empty/omitted leaves drift state untouched.
		ArtifactChecksums []proxymodel.ArtifactChecksum `json:"artifact_checksums"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Snapshot the prior state so we can detect and audit transitions.
	prev, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	caddyRunning := prev.CaddyRunning
	if req.CaddyRunning != nil {
		caddyRunning = *req.CaddyRunning
	}

	if err := s.db.UpdateAgentHealth(id, req.PublicIP, req.PublicIP6, req.LastError, caddyRunning, req.ProxyMode); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Persist the agent's read-only proxy detection (§13.0). It's a narrow update
	// so it doesn't clobber operator-owned fields or the health self-report just
	// written above. Only update when the agent actually reported detection.
	if req.ProxyDetection != nil {
		if uerr := s.db.UpdateAgentDetection(id, req.ProxyDetection); uerr != nil {
			log.Printf("failed to update agent %s detection: %v", id, uerr)
		}
	}

	// Persist the agent's reported capability matrix (§8). Like detection, it's a
	// narrow update that doesn't clobber the health self-report; only update when
	// the agent actually reported capabilities (nil leaves the stored copy as-is).
	if req.ProxyCapabilities != nil {
		if uerr := s.db.UpdateAgentCapabilities(id, req.ProxyCapabilities); uerr != nil {
			log.Printf("failed to update agent %s capabilities: %v", id, uerr)
		}
	}

	// Persist the §12 permission self-test reported this beat. Unlike detection, we
	// store it unconditionally (including nil → SQL NULL): an existing-mode agent
	// always reports a result, and built-in mode reporting nil is the correct
	// "no permission state" — so the stored value always tracks the agent's truth,
	// and a granted permission clears the dashboard warning on the next beat.
	if uerr := s.db.UpdateAgentPermissions(id, req.ProxyPermissions); uerr != nil {
		log.Printf("failed to update agent %s permissions: %v", id, uerr)
	}

	// A heartbeat is proof of life: an agent the orchestrator had marked offline
	// is back. Adoption state itself is owned by the operator, so we only flip
	// the offline<->adopted axis here, never pending->adopted.
	if prev.Status == models.AgentStatusOffline {
		if uerr := s.db.UpdateAgentStatus(id, models.AgentStatusAdopted); uerr != nil {
			log.Printf("failed to mark agent %s back online: %v", id, uerr)
		} else {
			s.audit(r, "agent", id, "status_change", "agent came back online (heartbeat)")
		}
	}

	// Audit health-state changes so operators can see, e.g., Caddy going down.
	if req.CaddyRunning != nil && prev.CaddyRunning != caddyRunning {
		s.audit(r, "agent", id, "caddy_state", fmt.Sprintf("caddy_running=%t", caddyRunning))
	}
	// NOTE: a recurring agent health error (e.g. an existing-mode reload-permission
	// denial re-probed every beat) is live telemetry, not an audit event — it is
	// surfaced as current state via the agent's last_error + proxy_permissions, and
	// auditing it on every beat just spams the timeline. So we deliberately do NOT
	// audit agent_error here; the audit log records actions and real transitions
	// (adopt/reject/update/delete, online/offline, caddy_state, proxy_mode switch).
	// Audit a live proxy-mode change (e.g. a §19 hot-switch to existing nginx) so
	// operators see the backend flip in the timeline. Only when the agent actually
	// reported a mode and it differs from what we had.
	if req.ProxyMode != "" && prev.ProxyMode != req.ProxyMode {
		s.audit(r, "agent", id, "proxy_mode", fmt.Sprintf("proxy_mode=%s", req.ProxyMode))
	}

	// Re-read the fresh row (UpdateAgentHealth + the offline->adopted flip both
	// wrote to it) before any further mutation, so we don't clobber them.
	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get agent status")
		return
	}

	// Update version if it changed.
	if req.Version != "" && agent.Version != req.Version {
		agent.Version = req.Version
		if uerr := s.db.UpdateAgent(agent); uerr != nil {
			log.Printf("failed to update agent version: %v", uerr)
		}
	}

	// Drift detection (§11): compare each reported on-disk checksum against the
	// accepted state. A divergence flags the artifact for review (never
	// overwriting the stored/accepted content); a match clears any prior drift.
	s.reconcileArtifactChecksums(r, id, req.ArtifactChecksums)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    agent.Status,
		"last_seen": agent.LastSeen,
	})
}

// reconcileArtifactChecksums compares the agent's heartbeat-reported on-disk
// checksums against the accepted state in the central store and flags/clears
// drift accordingly (§11, invariant #3). It never overwrites stored content; the
// accepted state is preserved for the operator's review (accept/reject). Only a
// genuine drift transition is audited (source + actor), not every heartbeat
// (invariant #5). Best-effort and resilient: an unknown artifact ID (e.g. a
// manual/adopted artifact the orchestrator hasn't created yet) is skipped, not
// fatal to the heartbeat.
func (s *Server) reconcileArtifactChecksums(r *http.Request, agentID string, checksums []proxymodel.ArtifactChecksum) {
	for _, c := range checksums {
		if c.ArtifactID == "" {
			continue
		}
		drifted, changed, err := s.db.ReconcileArtifactChecksum(c.ArtifactID, agentID, c.Checksum, c.Content)
		if err != nil {
			// Unknown/absent artifact is expected before its first apply-ACK lands;
			// log at low volume and move on.
			log.Printf("heartbeat: drift check for artifact %s on agent %s: %v", c.ArtifactID, agentID, err)
			continue
		}
		if !changed {
			continue
		}
		if drifted {
			s.auditAs(r, models.AuditSourceAgent, "config_artifact", c.ArtifactID, "drifted",
				fmt.Sprintf("on-disk content diverged from accepted state (agent %s)", agentID))
		} else {
			s.auditAs(r, models.AuditSourceAgent, "config_artifact", c.ArtifactID, "drift_resolved",
				fmt.Sprintf("on-disk content back in agreement (agent %s)", agentID))
		}
	}
}
