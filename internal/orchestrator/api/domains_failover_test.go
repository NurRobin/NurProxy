package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestDomainBackupsAPI(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	domainID, fqdn := seedDomainTopology(t, srv, cookie)
	seedMoveTargets(t, srv) // srv-1b on agent-1, srv-2 on nginx agent-2
	backupsPath := fmt.Sprintf("/api/v1/domains/%d/backups", domainID)

	refused := []struct {
		name string
		ids  []string
		want string
	}{
		{"primary server", []string{"srv-1"}, "primary server"},
		{"same agent as the primary", []string{"srv-1b"}, "another agent"},
		{"agent outside the zone", []string{"srv-2"}, "does not serve"},
		{"unknown server", []string{"nope"}, "not found"},
		{"too many", []string{"a", "b", "c", "d"}, "at most 3"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			w := doRequest(t, handler, http.MethodPut, backupsPath, map[string]any{"server_ids": tc.ids}, cookie)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("PUT %v = %d %s, want 400 mentioning %q", tc.ids, w.Code, w.Body.String(), tc.want)
			}
		})
	}
	if w := doRequest(t, handler, http.MethodPut, backupsPath, map[string]any{}, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("missing server_ids = %d, want 400", w.Code)
	}

	if err := database.AddAgentZone("agent-2", "zone-1"); err != nil {
		t.Fatal(err)
	}
	w := doRequest(t, handler, http.MethodPut, backupsPath, map[string]any{"server_ids": []string{"srv-2"}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("set backups = %d %s", w.Code, w.Body.String())
	}
	var status models.DomainFailoverStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if len(status.Candidates) != 2 || !status.Candidates[0].Primary || status.Candidates[1].ServerID != "srv-2" || status.ActiveServerID != "srv-1" {
		t.Fatalf("failover status = %+v", status)
	}

	var got models.Domain
	w = doRequest(t, handler, http.MethodGet, fmt.Sprintf("/api/v1/domains/%d", domainID), nil, cookie)
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.BackupServerIDs) != 1 || got.BackupServerIDs[0] != "srv-2" || got.ActiveServerID != "srv-1" {
		t.Fatalf("domain = backups %v active %q", got.BackupServerIDs, got.ActiveServerID)
	}
	var list []models.Domain
	w = doRequest(t, handler, http.MethodGet, "/api/v1/domains", nil, cookie)
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil || len(list) != 1 || len(list[0].BackupServerIDs) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if w := doRequest(t, handler, http.MethodGet, fmt.Sprintf("/api/v1/domains/%d/failover", domainID), nil, cookie); w.Code != http.StatusOK {
		t.Fatalf("GET failover = %d", w.Code)
	}

	// The backup's agent cannot become the primary while it is a backup.
	w = doRequest(t, handler, http.MethodPut, fmt.Sprintf("/api/v1/domains/%d", domainID), map[string]any{"server_id": "srv-2"}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("move primary onto the backup agent = %d %s, want 400", w.Code, w.Body.String())
	}

	// A rename leaves a tombstone for the old standby vhost on the nginx backup.
	w = doRequest(t, handler, http.MethodPut, fmt.Sprintf("/api/v1/domains/%d", domainID), map[string]any{"subdomain": "renamed"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("rename = %d %s", w.Code, w.Body.String())
	}
	tombs, err := database.ListManagedRouteTombstones("agent-2")
	if err != nil {
		t.Fatal(err)
	}
	standbyID := db.StandbyArtifactID(domainID, "agent-2")
	if len(tombs) != 1 || tombs[0].Host != fqdn || !strings.HasPrefix(tombs[0].ResourceID, standbyID+"-was-") {
		t.Fatalf("rename tombstones on the backup = %+v", tombs)
	}

	// The backup server cannot be deleted while it is one; cascade drops it
	// from the list and tombstones the standby route.
	w = doRequest(t, handler, http.MethodDelete, "/api/v1/servers/srv-2", nil, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("delete backup server = %d %s, want 409", w.Code, w.Body.String())
	}
	w = doRequest(t, handler, http.MethodDelete, "/api/v1/servers/srv-2?cascade=true", nil, cookie)
	if w.Code != http.StatusAccepted && w.Code != http.StatusOK {
		t.Fatalf("cascade delete backup server = %d %s", w.Code, w.Body.String())
	}
	if ids, _ := database.DomainsBackedByServer("srv-2"); len(ids) != 0 {
		t.Fatalf("server still a backup for %v", ids)
	}
	tombs, _ = database.ListManagedRouteTombstones("agent-2")
	found := false
	for _, tomb := range tombs {
		found = found || (tomb.ResourceID == standbyID && tomb.Host == "renamed.example.com")
	}
	if !found {
		t.Fatalf("no standby route tombstone after the backup was dropped: %+v", tombs)
	}
}

func TestFailoverSettingsValidation(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	for _, tc := range []struct {
		key, value string
		want       int
	}{
		{"failover_grace", "45", http.StatusOK},
		{"failover_grace", "-1", http.StatusBadRequest},
		{"failover_failback_delay", "soon", http.StatusBadRequest},
		{"failover_failback", "false", http.StatusOK},
		{"failover_failback", "nah", http.StatusBadRequest},
	} {
		w := doRequest(t, handler, http.MethodPut, "/api/v1/settings/"+tc.key, map[string]string{"value": tc.value}, cookie)
		if w.Code != tc.want {
			t.Errorf("%s=%s: %d, want %d", tc.key, tc.value, w.Code, tc.want)
		}
	}
}

func TestDomainIDFromArtifactID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"dom-12", 12},
		{db.StandbyArtifactID(12, "agent-2"), 12},
		{"dom-12-was-0011", 0},
		{"adopt-agent-1-x", 0},
	} {
		got := domainIDFromArtifactID(tc.in)
		if (got == nil) != (tc.want == 0) || (got != nil && *got != tc.want) {
			t.Errorf("domainIDFromArtifactID(%q) = %v, want %d", tc.in, got, tc.want)
		}
	}
}
