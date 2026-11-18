package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/certmodel"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// certUploadTimeout bounds how long an adoption waits for the agent to upload
// the bundle. Reading a few PEM files takes milliseconds; the margin covers a
// slow link.
const certUploadTimeout = 30 * time.Second

// maxCertUploadBody fits a certificate and a key at their size limits plus the
// JSON envelope.
const maxCertUploadBody = 2*certmodel.MaxPEMBytes + 64<<10

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// certUploadBroker pairs an operator's adoption request with the bundle the
// agent uploads in answer. A request is accepted only from the agent it was
// sent to and only for the fingerprint that was asked for.
type certUploadBroker struct {
	mu      sync.Mutex
	pending map[string]*pendingCertUpload
}

type pendingCertUpload struct {
	agentID     string
	fingerprint string
	ch          chan proxymodel.CertUpload
}

func newCertUploadBroker() *certUploadBroker {
	return &certUploadBroker{pending: map[string]*pendingCertUpload{}}
}

// begin registers a pending upload and returns its request ID, the channel
// the upload arrives on, and a func that forgets the request.
func (b *certUploadBroker) begin(agentID, fingerprint string) (string, <-chan proxymodel.CertUpload, func()) {
	id := "certup-" + strings.TrimPrefix(newSessionID(), "tail-")
	p := &pendingCertUpload{agentID: agentID, fingerprint: fingerprint, ch: make(chan proxymodel.CertUpload, 1)}
	b.mu.Lock()
	b.pending[id] = p
	b.mu.Unlock()
	return id, p.ch, func() {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}
}

var (
	errUnknownCertUpload = errors.New("no adoption is waiting for this upload")
	errForeignCertUpload = errors.New("upload does not match the adoption request")
)

// deliver hands an agent's upload to the waiting adoption. Each request is
// answered once.
func (b *certUploadBroker) deliver(agentID string, up proxymodel.CertUpload) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[up.RequestID]
	if !ok {
		return errUnknownCertUpload
	}
	if p.agentID != agentID || p.fingerprint != up.Fingerprint {
		return errForeignCertUpload
	}
	delete(b.pending, up.RequestID)
	p.ch <- up
	return nil
}

// certCandidate is one discovered certificate as the candidates endpoint
// reports it for a domain.
type certCandidate struct {
	models.DiscoveredCert
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	// Serving is true when the agent serves the domain.
	Serving   bool   `json:"serving"`
	Adoptable bool   `json:"adoptable"`
	Reason    string `json:"reason,omitempty"`
}

// certScanHint is a discovery problem on an agent that may hide candidates,
// typically a certificate directory the agent may not read.
type certScanHint struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Path      string `json:"path"`
	Error     string `json:"error"`
}

// servingAgentID returns the agent that serves dom, or "" when the domain has
// no server (certificate-only domains) or it cannot be resolved.
func (s *Server) servingAgentID(dom *models.Domain) string {
	if dom.ServerID == "" {
		return ""
	}
	srv, err := s.db.GetServer(dom.ServerID)
	if err != nil {
		return ""
	}
	return srv.AgentID
}

// GET /api/v1/domains/{id}/certificate/candidates lists the certificates the
// agents found on their hosts that cover the domain's host (#80), the serving
// agent first. Each says whether it can be adopted and, if not, why. Hints
// report directories an agent could not read, which may hide candidates.
func (s *Server) handleDomainCertificateCandidates(w http.ResponseWriter, r *http.Request) {
	dom, host, ok := s.certificateDomain(w, r)
	if !ok {
		return
	}
	agents, err := s.db.ListAgents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	serving := s.servingAgentID(dom)
	now := time.Now().UTC()

	candidates := []certCandidate{}
	hints := []certScanHint{}
	for _, a := range agents {
		if a.ProxyDetection == nil {
			continue
		}
		for _, dc := range a.ProxyDetection.DiscoveredCerts {
			if dc.Fingerprint == "" {
				if dc.Error != "" {
					hints = append(hints, certScanHint{AgentID: a.ID, AgentName: a.Name, Path: dc.CertPath, Error: dc.Error})
				}
				continue
			}
			if !tls.NamesCover(dc.Names, host) {
				continue
			}
			adoptable, reason := tls.AdoptableFor(dc, host, now)
			candidates = append(candidates, certCandidate{
				DiscoveredCert: dc,
				AgentID:        a.ID,
				AgentName:      a.Name,
				Serving:        a.ID == serving,
				Adoptable:      adoptable,
				Reason:         reason,
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Serving != candidates[j].Serving {
			return candidates[i].Serving
		}
		if candidates[i].Adoptable != candidates[j].Adoptable {
			return candidates[i].Adoptable
		}
		return candidates[i].NotAfter.After(candidates[j].NotAfter)
	})

	resp := map[string]any{
		"host":             host,
		"serving_agent_id": serving,
		"candidates":       candidates,
		"hints":            hints,
	}
	if _, err := s.db.GetCertificate(host); err == nil {
		resp["certificate_on_file"] = true
	} else if until, _, _, held := s.db.CertAdoptionHold(dom, host, now); held {
		resp["issuance_deferred_until"] = until
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/domains/{id}/certificate/issue-now
//
// Ends the adoption hold (#80) for the domain: the operator does not want any
// of the certificates found on disk, so NurProxy orders a new one right away
// instead of waiting for the hold to expire.
func (s *Server) handleIssueDomainCertificateNow(w http.ResponseWriter, r *http.Request) {
	dom, host, ok := s.certificateDomain(w, r)
	if !ok {
		return
	}
	if err := s.db.SkipCertAdoption(dom.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update domain")
		return
	}
	s.audit(r, "certificate", host, "cert_adoption_skipped",
		fmt.Sprintf("domain %d: operator chose a new certificate over adopting one from disk", dom.ID))
	_, err := s.db.GetCertificate(host)
	onFile := err == nil
	if !onFile {
		s.triggerCertIssuance(dom)
	}
	msg := "adoption hold ended; issuing a new certificate"
	if onFile {
		msg = "adoption hold ended; a certificate is already on file"
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "certificate_on_file": onFile, "message": msg})
}

// POST /api/v1/domains/{id}/certificate/adopt   body {"fingerprint": "...", "agent_id": "..."}
//
// Adopts a certificate an agent found on its host for the domain (#80). The
// orchestrator asks that agent, over its stream, to upload the bundle with the
// given fingerprint; the agent answers only from the bundles it discovered
// itself. The upload is then validated and stored exactly like a manual
// import: names must cover the host, the key must match, the key is encrypted
// at rest, and central renewal takes over near expiry. agent_id defaults to
// the serving agent; a certificate from any other agent (a host being
// migrated away from) must name that agent explicitly.
func (s *Server) handleAdoptDomainCertificate(w http.ResponseWriter, r *http.Request) {
	dom, host, ok := s.certificateDomain(w, r)
	if !ok {
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
		AgentID     string `json:"agent_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fp := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(req.Fingerprint, ":", "")))
	if !fingerprintRe.MatchString(fp) {
		writeError(w, http.StatusBadRequest, "fingerprint must be the 64-character hex SHA-256 of the certificate")
		return
	}
	if s.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "live streaming not enabled")
		return
	}

	agent, found, err := s.findDiscoveredCert(dom, req.AgentID, fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up agents")
		return
	}
	if agent == nil {
		writeError(w, http.StatusNotFound, "no agent reports a certificate with that fingerprint")
		return
	}
	if ok, reason := tls.AdoptableFor(found, host, time.Now().UTC()); !ok {
		writeError(w, http.StatusConflict, "certificate cannot be adopted: "+reason)
		return
	}
	if !s.hub.Connected(agent.ID) {
		writeError(w, http.StatusConflict, "agent is not connected; it must be online to upload the certificate")
		return
	}

	// Hold the host lock across the upload so no ACME order for the host can
	// complete while the agent is answering.
	unlock, ok := s.lockCertHost(w, host)
	if !ok {
		return
	}
	defer unlock()

	up, err := s.requestCertUpload(r.Context(), agent.ID, fp)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}
	if up.Error != "" {
		writeError(w, http.StatusBadGateway, "agent could not upload the certificate: "+up.Error)
		return
	}
	if got, err := tls.LeafFingerprint(up.CertPEM); err != nil || got != fp {
		writeError(w, http.StatusBadGateway, "agent uploaded a different certificate than requested")
		return
	}
	bundle, err := tls.ValidateImportedBundle([]byte(up.CertPEM), []byte(up.KeyPEM), host, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "certificate rejected: "+err.Error())
		return
	}

	resp, ok := s.storeDomainCertificate(w, dom, host, bundle)
	if !ok {
		return
	}
	s.audit(r, "certificate", host, "cert_adopted",
		fmt.Sprintf("domain %d, adopted from agent %s (%s, %s, sha256 %s), %d name(s), expires %s; ACME renewal takes over from %s",
			dom.ID, agent.Name, found.Source, up.SourcePath, fp[:16], len(bundle.Names),
			bundle.NotAfter.UTC().Format("2006-01-02"), resp["renewal_after"].(time.Time).Format("2006-01-02")))
	s.triggerAgentPush(dom.ServerID)

	resp["message"] = "certificate adopted; pushing to the serving agent"
	resp["fingerprint"] = fp
	resp["agent_id"] = agent.ID
	resp["source_path"] = up.SourcePath
	writeJSON(w, http.StatusOK, resp)
}

// findDiscoveredCert finds the agent reporting fingerprint fp. Without
// agentID only the domain's serving agent is searched: copying a key from
// another host is a deliberate migration step, so the operator must name that
// agent.
func (s *Server) findDiscoveredCert(dom *models.Domain, agentID, fp string) (*models.Agent, models.DiscoveredCert, error) {
	if agentID == "" {
		agentID = s.servingAgentID(dom)
		if agentID == "" {
			return nil, models.DiscoveredCert{}, nil
		}
	}
	agents, err := s.db.ListAgents()
	if err != nil {
		return nil, models.DiscoveredCert{}, err
	}
	for i := range agents {
		a := &agents[i]
		if a.ID != agentID {
			continue
		}
		if a.ProxyDetection == nil {
			continue
		}
		for _, dc := range a.ProxyDetection.DiscoveredCerts {
			if dc.Fingerprint == fp {
				return a, dc, nil
			}
		}
	}
	return nil, models.DiscoveredCert{}, nil
}

// requestCertUpload pushes a cert_upload_request down the agent's stream and
// waits for the matching upload.
func (s *Server) requestCertUpload(ctx context.Context, agentID, fp string) (proxymodel.CertUpload, error) {
	id, ch, forget := s.certUploads.begin(agentID, fp)
	defer forget()
	data, _ := json.Marshal(proxymodel.CertUploadRequest{RequestID: id, Fingerprint: fp})
	if !s.hub.Publish(agentID, agenthub.Event{Type: agenthub.EventCertUploadRequest, Data: data}) {
		return proxymodel.CertUpload{}, errors.New("agent is not connected; it must be online to upload the certificate")
	}
	timer := time.NewTimer(certUploadTimeout)
	defer timer.Stop()
	select {
	case up := <-ch:
		return up, nil
	case <-timer.C:
		return proxymodel.CertUpload{}, errors.New("agent did not upload the certificate in time; is it running a version with certificate discovery?")
	case <-ctx.Done():
		return proxymodel.CertUpload{}, ctx.Err()
	}
}

// POST /api/v1/agents/{id}/certificates/upload   (agent auth)
//
// Receives the bundle an agent uploads in answer to a cert_upload_request.
// The caller must be the agent the request went to; anything else, including
// an unsolicited upload, is refused and the material discarded.
func (s *Server) handleAgentCertUpload(w http.ResponseWriter, r *http.Request) {
	id := pathParam(r, "id")
	if callerID, _ := r.Context().Value(ctxAgentID).(string); callerID != id {
		writeError(w, http.StatusForbidden, "agent can only upload for itself")
		return
	}
	var up proxymodel.CertUpload
	if err := readJSONLimit(r, &up, maxCertUploadBody); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch err := s.certUploads.deliver(id, up); {
	case errors.Is(err, errUnknownCertUpload):
		writeError(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
