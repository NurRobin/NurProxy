package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// PUT /api/v1/domains/{id}/certificate imports an operator-provided certificate
// for the domain's host (#80). It is the migration path for a host that already
// has a valid certificate, typically when Let's Encrypt would refuse a duplicate
// order. The bundle is validated, stored host-keyed with its key encrypted like
// an issued cert, and pushed to the serving agent right away. Central renewal
// replaces it with an ACME cert for the same host once it enters the renew window.
func (s *Server) handleImportDomainCertificate(w http.ResponseWriter, r *http.Request) {
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
	if dom.Status == models.DomainStatusDeleting {
		writeError(w, http.StatusConflict, "domain is being deleted")
		return
	}
	// Only central-TLS domains are served from the certificate store. Importing
	// for self-acme or TLS-off would store a cert nothing ever uses.
	if policy := caddygen.TLSPolicyForDomain(*dom); policy != proxymodel.TLSPolicyCentral {
		writeError(w, http.StatusConflict, fmt.Sprintf("domain TLS policy is %q; imported certificates are only served for central TLS", policy))
		return
	}
	zone, err := s.db.GetZone(dom.ZoneID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot resolve domain zone")
		return
	}
	host := dom.FQDN(zone.Name)

	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	bundle, err := tls.ValidateImportedBundle([]byte(req.CertPEM), []byte(req.KeyPEM), host, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "certificate rejected: "+err.Error())
		return
	}

	now := time.Now().UTC()
	cert := &models.Certificate{
		ID:        host, // host-keyed like issued certs; the upsert replaces any existing one
		Host:      host,
		Names:     bundle.Names,
		CertPEM:   bundle.CertPEM,
		KeyPEM:    bundle.KeyPEM,
		IssuedAt:  now,
		ExpiresAt: bundle.NotAfter,
		Source:    models.CertSourceImported,
	}
	if err := s.db.UpsertCertificate(cert); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store certificate")
		return
	}

	renewFrom := bundle.NotAfter.Add(-tls.DefaultRenewWindow).UTC()
	s.audit(r, "certificate", host, "cert_imported",
		fmt.Sprintf("domain %d, %d name(s), expires %s; ACME renewal takes over from %s",
			dom.ID, len(bundle.Names), bundle.NotAfter.UTC().Format("2006-01-02"), renewFrom.Format("2006-01-02")))

	s.triggerAgentPush(dom.ServerID)

	resp := map[string]any{
		"message":       "certificate imported; pushing to the serving agent",
		"host":          host,
		"names":         bundle.Names,
		"source":        models.CertSourceImported,
		"expires_at":    bundle.NotAfter.UTC(),
		"renewal_after": renewFrom,
	}
	if !renewFrom.After(now) {
		resp["warning"] = "certificate is already inside the renew window; ACME renewal will replace it on the next scan"
	}
	writeJSON(w, http.StatusOK, resp)
}
