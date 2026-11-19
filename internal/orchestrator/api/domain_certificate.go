package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	"github.com/NurRobin/NurProxy/internal/shared/caddygen"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// certHostLocker is implemented by the TLS renewer: it exposes the per-host
// issuance lock so an import never races an ACME order for the same host.
type certHostLocker interface {
	TryLockHost(host string) (unlock func(), ok bool)
}

// PUT /api/v1/domains/{id}/certificate imports an operator-provided certificate
// for the domain's host (#80). It is the migration path for a host that already
// has a valid certificate, typically when Let's Encrypt would refuse a duplicate
// order. The bundle is validated, stored host-keyed with its key encrypted like
// an issued cert, and pushed to the serving agent right away. Central renewal
// replaces it with an ACME cert for the same host once it enters the renew window.
func (s *Server) handleImportDomainCertificate(w http.ResponseWriter, r *http.Request) {
	dom, host, ok := s.certificateDomain(w, r)
	if !ok {
		return
	}

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

	unlock, ok := s.lockCertHost(w, host)
	if !ok {
		return
	}
	defer unlock()

	resp, ok := s.storeDomainCertificate(w, dom, host, bundle)
	if !ok {
		return
	}
	s.audit(r, "certificate", host, "cert_imported",
		fmt.Sprintf("domain %d, %d name(s), expires %s; ACME renewal takes over from %s",
			dom.ID, len(bundle.Names), bundle.NotAfter.UTC().Format("2006-01-02"), resp["renewal_after"].(time.Time).Format("2006-01-02")))
	s.triggerAgentPush(dom.ServerID)
	resp["message"] = "certificate imported; pushing to the serving agent"
	writeJSON(w, http.StatusOK, resp)
}

// certificateDomain resolves the {id} domain for a certificate import or
// adoption and its host. It writes the error response and returns ok=false
// when the domain is missing, being deleted, or not served with central TLS.
func (s *Server) certificateDomain(w http.ResponseWriter, r *http.Request) (*models.Domain, string, bool) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return nil, "", false
	}
	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return nil, "", false
	}
	if dom.Status == models.DomainStatusDeleting {
		writeError(w, http.StatusConflict, "domain is being deleted")
		return nil, "", false
	}
	// Only central-TLS domains are served from the certificate store. Importing
	// for self-acme or TLS-off would store a cert nothing ever uses.
	if policy := caddygen.TLSPolicyForDomain(*dom); policy != proxymodel.TLSPolicyCentral {
		writeError(w, http.StatusConflict, fmt.Sprintf("domain TLS policy is %q; imported certificates are only served for central TLS", policy))
		return nil, "", false
	}
	zone, err := s.db.GetZone(dom.ZoneID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot resolve domain zone")
		return nil, "", false
	}
	return dom, dom.FQDN(zone.Name), true
}

// lockCertHost takes the renewer's per-host lock so an ACME order for the
// same host cannot finish in between and overwrite the stored bundle. It
// refuses rather than waits: an order can take minutes.
func (s *Server) lockCertHost(w http.ResponseWriter, host string) (func(), bool) {
	locker, ok := s.issuer.(certHostLocker)
	if !ok {
		return func() {}, true
	}
	unlock, locked := locker.TryLockHost(host)
	if !locked {
		writeError(w, http.StatusConflict, "certificate issuance for "+host+" is in progress; retry in a minute")
		return nil, false
	}
	return unlock, true
}

// storeDomainCertificate stores a validated bundle for the domain's host as an
// imported certificate and returns the response fields shared by import and
// adoption. The caller holds the host lock, audits and pushes.
func (s *Server) storeDomainCertificate(w http.ResponseWriter, dom *models.Domain, host string, bundle *tls.ImportedBundle) (map[string]any, bool) {
	now := time.Now().UTC()
	cert := &models.Certificate{
		ID:        host, // host-keyed like issued certs; the upsert replaces any existing one
		Host:      host,
		Names:     bundle.Names,
		CertPEM:   bundle.CertPEM,
		KeyPEM:    bundle.KeyPEM,
		IssuedAt:  bundle.NotBefore,
		ExpiresAt: bundle.NotAfter,
		Source:    models.CertSourceImported,
	}
	if err := s.db.ImportCertificateForDomain(dom.ID, cert); err != nil {
		if errors.Is(err, db.ErrDomainDeleting) {
			writeError(w, http.StatusConflict, "domain is being deleted")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "failed to store certificate")
		return nil, false
	}

	renewFrom := bundle.NotAfter.Add(-tls.DefaultRenewWindow).UTC()
	resp := map[string]any{
		"host":          host,
		"names":         bundle.Names,
		"source":        models.CertSourceImported,
		"expires_at":    bundle.NotAfter.UTC(),
		"renewal_after": renewFrom,
	}
	if !renewFrom.After(now) {
		resp["warning"] = "certificate is already inside the renew window; ACME renewal will replace it on the next scan"
	}
	return resp, true
}
