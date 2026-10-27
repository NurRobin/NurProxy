package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/apachegen"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/dnsname"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// GET /api/v1/domains — supports ?agent_id=&server_id=&status= filters.
func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	filter := db.DomainFilter{
		AgentID:  r.URL.Query().Get("agent_id"),
		ServerID: r.URL.Query().Get("server_id"),
		Status:   r.URL.Query().Get("status"),
	}

	domains, err := s.db.ListDomains(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list domains")
		return
	}
	if domains == nil {
		domains = []models.Domain{}
	}
	writeJSON(w, http.StatusOK, domains)
}

// POST /api/v1/domains
func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subdomain   string              `json:"subdomain"`
		ZoneID      string              `json:"zone_id"`
		ServerID    string              `json:"server_id"`
		Port        int                 `json:"port"`
		WebSocket   bool                `json:"websocket"`
		ForceHTTPS  bool                `json:"force_https"`
		SSLMode     models.SSLMode      `json:"ssl_mode"`
		ProxyConfig *models.ProxyConfig `json:"proxy_config"`
		// CertOnly issues + renews a cert for this host and installs it on the
		// agent without serving a vhost (§7). No upstream/port is needed.
		CertOnly bool `json:"cert_only"`
		// Proxied is the Cloudflare orange-cloud setting (#126): omitted/null
		// keeps whatever the live record has, true/false is enforced.
		Proxied *bool `json:"proxied"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Subdomain == "" || req.ZoneID == "" || req.ServerID == "" {
		writeError(w, http.StatusBadRequest, "subdomain, zone_id, and server_id are required")
		return
	}
	if err := dnsname.ValidateSubdomainOrApex(req.Subdomain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A cert-only domain proxies nothing, so no port is required. A served domain
	// needs a valid upstream port.
	if !req.CertOnly && (req.Port <= 0 || req.Port > 65535) {
		writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	// Validate zone exists
	if _, err := s.db.GetZone(req.ZoneID); err != nil {
		writeError(w, http.StatusBadRequest, "zone not found")
		return
	}

	// Validate server exists
	if _, err := s.db.GetServer(req.ServerID); err != nil {
		writeError(w, http.StatusBadRequest, "server not found")
		return
	}

	if err := s.db.ValidateDomainProxied(req.ZoneID, req.CertOnly, req.Proxied); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check subdomain uniqueness within zone
	existing, _ := s.db.ListDomains(db.DomainFilter{})
	for _, d := range existing {
		if d.Subdomain == req.Subdomain && d.ZoneID == req.ZoneID {
			writeError(w, http.StatusConflict, "subdomain already exists for this zone")
			return
		}
	}

	sslMode := req.SSLMode
	if sslMode == "" {
		sslMode = models.SSLModeAuto
	}

	dom := &models.Domain{
		Subdomain:  req.Subdomain,
		ZoneID:     req.ZoneID,
		ServerID:   req.ServerID,
		Port:       req.Port,
		WebSocket:  req.WebSocket,
		ForceHTTPS: req.ForceHTTPS,
		SSLMode:    sslMode,
		CertOnly:   req.CertOnly,
		Proxied:    req.Proxied,
		Status:     models.DomainStatusPending,
	}

	if req.ProxyConfig != nil {
		dom.ProxyConfig = *req.ProxyConfig
	}

	if err := s.db.CreateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create domain")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(dom.ID, 10), "create", dom.Subdomain)
	if err := s.db.ClaimDomainRoute(dom); err != nil {
		log.Printf("create: cannot drop colliding route tombstones for domain %d: %v", dom.ID, err)
	}
	s.triggerAgentPush(dom.ServerID)
	s.triggerCertIssuance(dom)

	writeJSON(w, http.StatusCreated, dom)
}

// triggerCertIssuance kicks central TLS first-issuance for a freshly created
// domain so HTTPS comes up promptly instead of waiting for the next renewal scan
// (§7). It runs in the background (DNS-01 is slow) and is best-effort: a domain
// that wants no central cert (self-acme / off) is skipped here, and the periodic
// scan is the backstop if the async attempt fails. A no-op when no issuer is
// wired (tests / headless without ACME) or the domain's zone can't be resolved.
func (s *Server) triggerCertIssuance(dom *models.Domain) {
	if s.issuer == nil || dom == nil {
		return
	}
	if caddygen.TLSPolicyForDomain(*dom) != proxymodel.TLSPolicyCentral {
		return // self-acme / off: no central cert to issue
	}
	zone, err := s.db.GetZone(dom.ZoneID)
	if err != nil {
		return
	}
	host := dom.FQDN(zone.Name)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.issuer.EnsureCertForHost(ctx, host); err != nil {
			log.Printf("tls: on-create issuance for %s failed (renewal scan will retry): %v", host, err)
		}
	}()
}

// dnsReconciler is implemented by the reconciler wired in as DNS takeover: it
// runs the domain DNS phases on demand.
type dnsReconciler interface {
	ReconcileDNSNow(ctx context.Context)
}

// triggerDNSReconcile runs a DNS pass in the background after a rename or zone
// move, so the new name gets its record (and the old one its cleanup) right
// away instead of up to a reconcile interval later, while the agent has
// already dropped the old vhost. Best-effort; the periodic cycle is the
// backstop.
func (s *Server) triggerDNSReconcile() {
	rec, ok := s.takeover.(dnsReconciler)
	if !ok {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		rec.ReconcileDNSNow(ctx)
	}()
}

// GET /api/v1/domains/{id}
func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	writeJSON(w, http.StatusOK, dom)
}

// PUT /api/v1/domains/{id}
func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	// Snapshot the stored domain before any requested field is applied: a move
	// must tombstone the OLD host on the OLD agent even when the same request
	// also renames the domain.
	before := *dom

	var req struct {
		Subdomain   *string             `json:"subdomain"`
		ZoneID      *string             `json:"zone_id"`
		ServerID    *string             `json:"server_id"`
		Port        *int                `json:"port"`
		WebSocket   *bool               `json:"websocket"`
		ForceHTTPS  *bool               `json:"force_https"`
		SSLMode     *models.SSLMode     `json:"ssl_mode"`
		ProxyConfig *models.ProxyConfig `json:"proxy_config"`
		// Proxied: absent leaves the setting alone, null clears it back to
		// "keep existing", true/false sets it (#126).
		Proxied models.OptionalBool `json:"proxied"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Subdomain != nil {
		if err := dnsname.ValidateSubdomainOrApex(*req.Subdomain); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		dom.Subdomain = *req.Subdomain
	}
	if req.ZoneID != nil {
		if _, err := s.db.GetZone(*req.ZoneID); err != nil {
			writeError(w, http.StatusBadRequest, "zone not found")
			return
		}
		dom.ZoneID = *req.ZoneID
	}
	if req.ServerID != nil {
		if _, err := s.db.GetServer(*req.ServerID); err != nil {
			writeError(w, http.StatusBadRequest, "server not found")
			return
		}
		dom.ServerID = *req.ServerID
	}
	if req.Port != nil {
		dom.Port = *req.Port
	}
	if req.WebSocket != nil {
		dom.WebSocket = *req.WebSocket
	}
	if req.ForceHTTPS != nil {
		dom.ForceHTTPS = *req.ForceHTTPS
	}
	if req.SSLMode != nil {
		dom.SSLMode = *req.SSLMode
	}
	if req.ProxyConfig != nil {
		dom.ProxyConfig = *req.ProxyConfig
	}
	if req.Proxied.Set {
		dom.Proxied = req.Proxied.Value
	}
	// Checked against the final zone, so moving a proxied domain into a zone
	// whose provider cannot proxy is refused too.
	if err := s.db.ValidateDomainProxied(dom.ZoneID, dom.CertOnly, dom.Proxied); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Mark as pending for reconciler to pick up
	dom.Status = models.DomainStatusPending

	// A move to another agent must leave a route tombstone for the old host on
	// the old agent before any push stops retaining the route's certificate
	// there; otherwise the old vhost survives while its certificate is pruned
	// (#148).
	now := time.Now().UTC()
	var move *db.DomainMove
	if req.ServerID != nil && before.ServerID != dom.ServerID {
		move, err = s.db.BeginDomainMove(&before, dom.ServerID, now)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist managed deletion identity for the old agent")
			return
		}
	}
	// A rename on the same agent leaves the old vhost file behind unless it
	// gets its own tombstone; UpdateDomain releases the old DNS record (#151).
	rename, err := s.db.BeginDomainRename(&before, dom, now)
	if err != nil {
		s.db.AbortDomainMove(move)
		writeError(w, http.StatusInternalServerError, "failed to persist managed deletion identity for the renamed host")
		return
	}

	if err := s.db.UpdateDomain(dom); err != nil {
		s.db.AbortDomainMove(move)
		s.db.AbortDomainRename(rename)
		writeError(w, http.StatusInternalServerError, "failed to update domain")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(dom.ID, 10), "update", dom.Subdomain)
	if models.ProxiedLabel(before.Proxied) != models.ProxiedLabel(dom.Proxied) {
		s.audit(r, "domain", strconv.FormatInt(dom.ID, 10), "proxied_set",
			fmt.Sprintf("%s: %s -> %s", dom.Subdomain, models.ProxiedLabel(before.Proxied), models.ProxiedLabel(dom.Proxied)))
	}

	// The artifact row is keyed to the old agent, so a cross-agent move drops
	// it; the new agent renders and reports a fresh one in its apply-ACK (§3).
	if removed, err := s.db.CompleteDomainMove(move); err != nil {
		log.Printf("move: failed to delete stale artifact for domain %d: %v", dom.ID, err)
	} else if removed {
		s.audit(r, "config_artifact", move.ArtifactID, "remove", "domain moved to another agent")
	}
	if err := s.db.ClaimDomainRoute(dom); err != nil {
		log.Printf("update: cannot drop colliding route tombstones for domain %d: %v", dom.ID, err)
	}
	if dropped, err := s.db.FinishDomainRename(rename); err != nil {
		log.Printf("update: cannot remove the old certificate of renamed domain %d: %v", dom.ID, err)
	} else if dropped {
		s.audit(r, "certificate", rename.OldHost, "deleted", "domain renamed to "+rename.NewHost+"; no remaining domain serves this host")
	}
	if move != nil {
		// Push the old agent so it removes the route at once.
		s.pushAgent(move.OldAgentID)
	}

	s.triggerAgentPush(dom.ServerID)
	if rename != nil {
		s.triggerCertIssuance(dom)
		s.triggerDNSReconcile()
	}

	writeJSON(w, http.StatusOK, dom)
}

// artifactIDForDomainID derives the stable artifact identity for a generated
// (model-backed) domain config, mirroring the reconciler's artifactIDForDomain
// and the agents_stream domainIDFromArtifactID round-trip ("dom-<id>").
func artifactIDForDomainID(domainID int64) string {
	return "dom-" + strconv.FormatInt(domainID, 10)
}

// DELETE /api/v1/domains/{id}
// guardChildDomains refuses to delete a parent (server, agent, or zone) while
// domains still reference it. It writes a 409 listing the blocking subdomains and
// returns true when deletion must abort. Without this guard the DB's ON DELETE
// CASCADE hard-removes those domain rows the instant the parent is deleted, which
// runs BEFORE the reconciler's teardown (reconcileDeletions) and so never deletes
// their managed DNS records or certificates — they leak at the provider with no
// audit. Domains must be deleted first, individually, so each routes through the
// reconciler teardown. The 409 body carries the domain list so a UI/CLI can offer
// an explicit cascade (delete the domains first, then retry) rather than guessing.
func (s *Server) guardChildDomains(w http.ResponseWriter, parent string, filter db.DomainFilter) bool {
	doms, err := s.db.ListDomains(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check for dependent domains")
		return true
	}
	if len(doms) == 0 {
		return false
	}
	names := make([]string, 0, len(doms))
	for _, d := range doms {
		names = append(names, d.Subdomain)
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"error":   fmt.Sprintf("%s still has %d domain(s); delete them first", parent, len(names)),
		"domains": names,
	})
	return true
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	// Persist the exact file-backend tombstone before the immediate push can stop
	// retaining the route's certificate.
	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	var tombstoneAgentID string
	var tombstone *helperprotocol.ManagedDeletion
	if !dom.CertOnly {
		srv, srvErr := s.db.GetServer(dom.ServerID)
		zone, zoneErr := s.db.GetZone(dom.ZoneID)
		if srvErr != nil || zoneErr != nil {
			writeError(w, http.StatusInternalServerError, "failed to resolve managed deletion identity")
			return
		}
		backend := s.backendForDomain(srv)
		if backend == "nginx" || backend == "apache" {
			deletion := helperprotocol.ManagedDeletion{
				ResourceID: artifactIDForDomainID(dom.ID),
				Host:       dom.FQDN(zone.Name),
				Backend:    backend,
			}
			if err := s.db.UpsertManagedRouteTombstone(srv.AgentID, deletion, time.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to persist managed deletion identity")
				return
			}
			tombstoneAgentID, tombstone = srv.AgentID, &deletion
		}
	}

	// Set status to "deleting" — reconciler handles actual cleanup
	if err := s.db.UpdateDomainStatus(id, models.DomainStatusDeleting, ""); err != nil {
		if tombstone != nil {
			_ = s.db.DeleteManagedRouteTombstones(tombstoneAgentID, []helperprotocol.ManagedDeletion{*tombstone})
		}
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(id, 10), "delete", "")
	// A full-sync push now excludes the deleting domain, so a connected agent
	// drops the route at once; DNS record + row cleanup follow in the reconciler.
	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "domain marked for deletion"})
}

// GET /api/v1/domains/{id}/config
func (s *Server) handleGetDomainConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	// If manual config, return the stored override in its own backend's shape: a
	// JSON object for Caddy route JSON, or the native config text (a string) for
	// nginx/apache.
	if dom.ManualConfig && !dom.ProxyConfig.RawConfig.IsZero() {
		rc := dom.ProxyConfig.RawConfig
		backend := rc.Backend
		if backend == "" {
			backend = "caddy"
		}
		out := map[string]interface{}{"manual": true, "backend": backend}
		if backend == "caddy" {
			var raw json.RawMessage
			if err := json.Unmarshal([]byte(rc.Content), &raw); err == nil {
				out["config"] = raw
			} else {
				out["config"] = rc.Content
			}
		} else {
			out["config"] = rc.Content
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	// Prefer the applied artifact: the agent round-trips the config it actually
	// rendered and applied (real cert-store paths, real listener set) into the
	// store via its apply-ACK (§3/B1). Showing those bytes means an operator who
	// edits "the generated config" starts from what is genuinely on disk — a
	// fresh re-render here would have to guess agent-local paths and has already
	// produced manual configs pointing at cert files that do not exist.
	if art, aErr := s.db.GetConfigArtifact(artifactIDForDomainID(id)); aErr == nil && art.Content != "" {
		out := map[string]interface{}{"manual": false, "backend": art.Backend, "applied": true}
		var raw json.RawMessage
		if art.Backend == "caddy" && json.Unmarshal([]byte(art.Content), &raw) == nil {
			out["config"] = raw
		} else {
			out["config"] = art.Content
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	// No applied artifact yet (domain not pushed to its agent so far): fall back
	// to a fresh preview render with the conventional default paths.

	// Get server for upstream address
	srv, err := s.db.GetServer(dom.ServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server not found")
		return
	}

	// Get zone for zone name
	zone, err := s.db.GetZone(dom.ZoneID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "zone not found")
		return
	}

	backend, config, err := s.renderDomainPreview(dom, srv, dom.FQDN(zone.Name))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate config: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"manual":  false,
		"backend": backend,
		"config":  config,
	})
}

// renderDomainPreview renders the auto-generated config for a domain in the
// backend its serving agent actually runs (§5), so the dashboard's advanced view
// matches what the agent applies instead of always showing Caddy JSON. It returns
// the backend name plus the config: a JSON route object for built-in Caddy, or
// the native config text (a string) for nginx/apache. The cert/key paths are the
// agent's conventional cert-store paths so a TLS route previews its real
// listener; the operator adjusts them if their agent uses a custom cert dir.
func (s *Server) renderDomainPreview(dom *models.Domain, srv *models.Server, fqdn string) (backend string, config interface{}, err error) {
	route := caddygen.ConfigFromDomain(*dom, fqdn, srv.Address)
	backend = s.backendForDomain(srv)
	certPath, keyPath := previewCertPaths(fqdn)

	switch backend {
	case "nginx":
		res, rErr := nginxgen.Render(nginxgen.Input{Route: route, CertPath: certPath, KeyPath: keyPath})
		if rErr != nil {
			return backend, nil, rErr
		}
		return backend, joinNginx(res.HTTPPreamble, res.Server), nil
	case "apache":
		res, rErr := apachegen.Render(apachegen.Input{Route: route, CertPath: certPath, KeyPath: keyPath})
		if rErr != nil {
			return backend, nil, rErr
		}
		return backend, joinBlocks(res.Preamble, res.VHost), nil
	default:
		caddyRoute, rErr := caddygen.GenerateRoute(route)
		if rErr != nil {
			return "caddy", nil, rErr
		}
		return "caddy", caddyRoute, nil
	}
}

// backendForDomain reports the proxy backend the domain's serving agent renders
// with: its detected host proxy in existing mode, else the bundled Caddy. Mirrors
// the reconciler's backendForAgent so the preview agrees with what is pushed.
func (s *Server) backendForDomain(srv *models.Server) string {
	agent, err := s.db.GetAgent(srv.AgentID)
	if err != nil {
		return "caddy"
	}
	if agent.ProxyMode == "existing" && agent.ProxyDetection != nil && agent.ProxyDetection.Kind != "" {
		return agent.ProxyDetection.Kind
	}
	return "caddy"
}

// previewCertDir is the conventional agent cert-store directory used to render
// cert paths in the advanced preview, matching the agent's default data dir
// (<data-dir>/certs with data-dir /var/lib/nurproxy-agent — NOT the
// orchestrator's /var/lib/nurproxy). The agent's real directory is derived from
// its own data dir; this default only seeds the preview for a domain that has
// never been applied (once it has, the handler returns the applied artifact
// with the agent's real paths instead).
const previewCertDir = "/var/lib/nurproxy-agent/certs"

// previewCertPaths returns the conventional cert/key paths for a host, matching
// the agent cert store's file-naming: <host>.crt for the leaf+chain and
// <host>.key.plain for the proxy-readable key. That is the common case — an
// agent with an at-rest key encrypts the stored key as <host>.key.enc and
// materializes the plaintext sibling the proxy actually loads. An agent
// without an at-rest key stores the key as plaintext <host>.key and serves
// that path instead; the preview assumes the encrypted layout since it cannot
// know the agent's key configuration (the operator adjusts if needed).
func previewCertPaths(fqdn string) (certPath, keyPath string) {
	base := sanitizeHostForPreview(fqdn)
	return previewCertDir + "/" + base + ".crt", previewCertDir + "/" + base + ".key.plain"
}

// sanitizeHostForPreview mirrors certstore.SanitizeHost for preview file names
// without importing agent-side code into the orchestrator: map a leading wildcard
// label to "_wildcard." and drop path separators.
func sanitizeHostForPreview(host string) string {
	h := strings.TrimSpace(host)
	h = strings.ReplaceAll(h, "*.", "_wildcard.")
	h = strings.ReplaceAll(h, "/", "_")
	h = strings.ReplaceAll(h, "\\", "_")
	h = strings.ReplaceAll(h, "..", "_")
	return h
}

// joinNginx assembles an nginx preview: the http-context preamble (if any)
// followed by the server block, matching how the agent's nginx backend composes
// the artifact.
func joinNginx(preamble, server string) string {
	if preamble == "" {
		return server
	}
	if !strings.HasSuffix(preamble, "\n") {
		preamble += "\n"
	}
	return preamble + "\n" + server
}

// joinBlocks assembles an apache preview: the global-context preamble (if any)
// followed by the VirtualHost block.
func joinBlocks(preamble, vhost string) string {
	if preamble == "" {
		return vhost
	}
	if !strings.HasSuffix(preamble, "\n") {
		preamble += "\n"
	}
	return preamble + "\n" + vhost
}

// PUT /api/v1/domains/{id}/config
func (s *Server) handleUpdateDomainConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	var req struct {
		Config json.RawMessage `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	srv, err := s.db.GetServer(dom.ServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server not found")
		return
	}

	// Store the manual override tagged with the serving agent's backend, so the
	// agent's matching renderer uses it verbatim. Built-in Caddy carries route
	// JSON; nginx/apache carry their native config text (sent as a JSON string).
	backend := s.backendForDomain(srv)
	var content string
	switch backend {
	case "nginx", "apache":
		if err := json.Unmarshal(req.Config, &content); err != nil {
			writeError(w, http.StatusBadRequest, "config for "+backend+" must be the native config as a JSON string")
			return
		}
	default:
		backend = "caddy"
		if !json.Valid(req.Config) {
			writeError(w, http.StatusBadRequest, "invalid JSON config")
			return
		}
		content = string(req.Config)
	}

	dom.ManualConfig = true
	dom.ProxyConfig.RawConfig = models.RawConfig{Backend: backend, Content: content}
	dom.Status = models.DomainStatusPending

	if err := s.db.UpdateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update domain config")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(id, 10), "update_config", "manual config set")
	// Same trap as reset: a drift-accepted (manual) artifact outranks the row in
	// the reconciler, so the OLD manual bytes would keep deploying instead of the
	// config just stored. Remove it so the push below carries the new override.
	s.resetDomainArtifact(r, id)
	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "manual config set"})
}

// resetDomainArtifact returns the domain's current "dom-<id>" artifact to model
// authority before a config edit or reset is pushed.
// The reconciler treats a manual artifact as authoritative and pushes its stored
// bytes verbatim, ignoring the domain row entirely — so after a config reset (or
// a new manual config on the row) the old bytes would be re-pushed, the agent
// would ACK identical content, and AppendConfigArtifactVersion's semantic-equality
// gate would return before the source-updating UPDATE: source stays "manual" and
// the row change never reaches the agent. Resetting source/drift authority breaks
// that loop while retaining the canonical target identity and version history.
func (s *Server) resetDomainArtifact(r *http.Request, domainID int64) {
	artifactID := artifactIDForDomainID(domainID)
	err := s.db.ResetConfigArtifactToDomainModel(artifactID)
	if err != nil {
		// No artifact is the common case (nothing to reset); anything else is a
		// real lookup failure that would leave a stale manual artifact silently
		// overriding the domain row — make it visible.
		if !errors.Is(err, db.ErrArtifactNotFound) {
			log.Printf("resetDomainArtifact: resetting artifact %s: %v", artifactID, err)
		}
		return
	}
	s.audit(r, "config_artifact", artifactID, "reset", "artifact authority reset; agent re-renders from the domain model")
}

// POST /api/v1/domains/{id}/config/reset
func (s *Server) handleResetDomainConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	dom.ManualConfig = false
	dom.ProxyConfig.RawConfig = models.RawConfig{}
	dom.Status = models.DomainStatusPending

	if err := s.db.UpdateDomain(dom); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reset domain config")
		return
	}

	s.audit(r, "domain", strconv.FormatInt(id, 10), "reset_config", "manual config cleared")
	// A drift-accepted (manual) artifact would override the cleared row on the
	// next push; remove it so the push below renders from the domain model again.
	s.resetDomainArtifact(r, id)
	s.triggerAgentPush(dom.ServerID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "config reset to auto-generated"})
}

// POST /api/v1/domains/{id}/dns/takeover — admin override that authorizes NurProxy
// to overwrite a conflicting pre-existing DNS record (an A record, or a CNAME to a
// different target) with the desired CNAME → agent FQDN, using the zone provider's
// own stored credentials. The default reconcile path never touches a record it did
// not create; this is the explicit, audited escape hatch for migrating an existing
// domain whose public DNS predates NurProxy. It also re-pushes the agent's routes so
// the now-resolvable domain re-renders with its certificate.
func (s *Server) handleDomainDNSTakeover(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}
	if s.takeover == nil {
		writeError(w, http.StatusServiceUnavailable, "DNS takeover unavailable (reconciler not wired)")
		return
	}
	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err := s.takeover.TakeoverDomainDNS(r.Context(), id); err != nil {
		writeError(w, http.StatusBadGateway, "DNS takeover failed: "+err.Error())
		return
	}
	s.audit(r, "domain", strconv.FormatInt(id, 10), "dns_takeover", dom.Subdomain)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "DNS takeover applied — the record now points at the agent and routes were re-pushed",
	})
}

// cascadeRequested reports whether the request opts into cascade deletion
// (?cascade=true, #104).
func cascadeRequested(r *http.Request) bool {
	return strings.EqualFold(r.URL.Query().Get("cascade"), "true")
}

// cascadeDeleteParent implements the opt-in cascade (#104): every domain still
// referencing the parent is soft-deleted THROUGH the reconciler (the same
// status=deleting path a direct domain delete takes, so DNS records, certs and
// artifacts are torn down and audited), and the parent removal itself is
// deferred — recorded in pending_parent_deletions and finalized by the
// reconciler once the last domain is gone. Never a raw DB cascade: that is
// exactly the teardown leak the 409 guard exists to prevent.
func (s *Server) cascadeDeleteParent(w http.ResponseWriter, r *http.Request, entityType, entityID string, filter db.DomainFilter) {
	doms, err := s.db.ListDomains(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list dependent domains")
		return
	}

	marked := 0
	pushTargets := map[string]bool{}
	for i := range doms {
		dom := &doms[i]
		if dom.Status == models.DomainStatusDeleting {
			continue // already on its way out
		}
		if err := s.db.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to mark domain for deletion")
			return
		}
		s.audit(r, "domain", strconv.FormatInt(dom.ID, 10), "delete", fmt.Sprintf("cascade via %s %s", entityType, entityID))
		pushTargets[dom.ServerID] = true
		marked++
	}
	if err := s.db.AddPendingParentDeletion(db.PendingParentDeletion{
		EntityType: entityType, EntityID: entityID, Actor: actorFromCtx(r),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record pending deletion")
		return
	}
	s.audit(r, entityType, entityID, "delete_cascade_requested", fmt.Sprintf("%d domain(s) marked for deletion; parent removal deferred to teardown", marked))

	// Connected agents drop the routes immediately; DNS/cert/row cleanup and the
	// parent removal follow in the reconciler.
	for srvID := range pushTargets {
		s.triggerAgentPush(srvID)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"message": fmt.Sprintf("%s deletion deferred: %d domain(s) marked for deletion; the %s is removed once their teardown finishes", entityType, marked, entityType),
		"domains": marked,
	})
}
