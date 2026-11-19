package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Regression for #151: renaming a domain on the same nginx agent through the
// REST API tombstones the old host under an id of its own (the domain's
// resource stays in the apply), releases the old DNS record into the cleanup
// queue with the old provider snapshot, and drops the old host's certificate.
// A port change in the same request does not change any of that.
func TestUpdateDomainRenameSameAgent(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)
	if err := database.UpdateDomainDNSRecord(domainID, "rec-old", true); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCertificate(&models.Certificate{ID: "cert-old", Host: fqdn, Names: []string{fqdn}, CertPEM: "LEAF", KeyPEM: "KEY"}); err != nil {
		t.Fatal(err)
	}

	w := doRequest(t, handler, http.MethodPut, "/api/v1/domains/"+strconv.FormatInt(domainID, 10),
		map[string]any{"subdomain": "renamed", "port": 9090}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("rename: %d: %s", w.Code, w.Body.String())
	}
	var got models.Domain
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.DNSRecordID != "" || got.DNSManaged || got.Port != 9090 {
		t.Fatalf("response = record %q managed %v port %d", got.DNSRecordID, got.DNSManaged, got.Port)
	}

	deletions, err := database.ListManagedRouteTombstones("agent-1")
	if err != nil || len(deletions) != 1 {
		t.Fatalf("tombstones = %#v, err=%v", deletions, err)
	}
	if d := deletions[0]; d.Host != fqdn || d.Backend != "nginx" ||
		!strings.HasPrefix(d.ResourceID, fmt.Sprintf("dom-%d-was-", domainID)) {
		t.Fatalf("rename tombstone = %#v", d)
	}
	queued, err := database.ListDomainDNSCleanups()
	if err != nil || len(queued) != 1 {
		t.Fatalf("queued cleanups = %+v, err=%v", queued, err)
	}
	if q := queued[0]; q.RecordID != "rec-old" || !q.Owned || q.FQDN != fqdn || q.ProviderID != "prov-1" || q.ZoneExternalID != "ext-1" {
		t.Fatalf("queued cleanup = %+v", q)
	}
	if _, err := database.GetCertificate(fqdn); !errors.Is(err, db.ErrCertNotFound) {
		t.Fatalf("old certificate still stored (err=%v)", err)
	}
}

// A wildcard certificate stored under the old host covers more than that host,
// and an imported one is the operator's bundle that NurProxy cannot issue
// again, so a rename deletes neither.
func TestUpdateDomainRenameKeepsWildcardAndImportedCertificates(t *testing.T) {
	cases := []struct {
		name string
		cert func(host string) *models.Certificate
	}{
		{name: "wildcard", cert: func(host string) *models.Certificate {
			return &models.Certificate{ID: "cert-wild", Host: host, Names: []string{host, "*." + host}, IsWildcard: true, CertPEM: "LEAF", KeyPEM: "KEY"}
		}},
		{name: "imported", cert: func(host string) *models.Certificate {
			return &models.Certificate{ID: "cert-imp", Host: host, Names: []string{host}, Source: models.CertSourceImported, CertPEM: "LEAF", KeyPEM: "KEY"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			handler := srv.Handler()
			cookie := setupAdmin(t, handler)
			domainID, fqdn := seedDomainTopology(t, srv, cookie)
			if err := database.UpsertCertificate(tc.cert(fqdn)); err != nil {
				t.Fatal(err)
			}
			w := doRequest(t, handler, http.MethodPut, "/api/v1/domains/"+strconv.FormatInt(domainID, 10),
				map[string]any{"subdomain": "renamed"}, cookie)
			if w.Code != http.StatusOK {
				t.Fatalf("rename: %d: %s", w.Code, w.Body.String())
			}
			if _, err := database.GetCertificate(fqdn); err != nil {
				t.Fatalf("%s certificate removed by a rename: %v", tc.name, err)
			}
		})
	}
}

// A change that keeps the name leaves the DNS record, certificate and vhost
// alone.
func TestUpdateDomainWithoutRenameKeepsRecord(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)
	if err := database.UpdateDomainDNSRecord(domainID, "rec-keep", true); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCertificate(&models.Certificate{ID: "cert-keep", Host: fqdn, Names: []string{fqdn}, CertPEM: "LEAF", KeyPEM: "KEY"}); err != nil {
		t.Fatal(err)
	}
	w := doRequest(t, handler, http.MethodPut, "/api/v1/domains/"+strconv.FormatInt(domainID, 10),
		map[string]any{"port": 9091, "subdomain": "health"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d: %s", w.Code, w.Body.String())
	}
	dom, err := database.GetDomain(domainID)
	if err != nil || dom.DNSRecordID != "rec-keep" || !dom.DNSManaged {
		t.Fatalf("record after port change = %+v, err=%v", dom, err)
	}
	if queued, _ := database.ListDomainDNSCleanups(); len(queued) != 0 {
		t.Fatalf("port change queued a cleanup: %+v", queued)
	}
	if _, err := database.GetCertificate(fqdn); err != nil {
		t.Fatalf("certificate removed by a port change: %v", err)
	}
	if deletions, _ := database.ListManagedRouteTombstones("agent-1"); len(deletions) != 0 {
		t.Fatalf("port change tombstoned the vhost: %#v", deletions)
	}
}
