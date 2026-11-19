package db

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// seedBackupTopology creates a zone, a primary agent with server srv-p and a
// domain on it, and three more agents (agent-a/b/c) serving the zone with one
// server each (srv-a/b/c).
func seedBackupTopology(t *testing.T, d *DB) *models.Domain {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.CreateProvider(&models.Provider{ID: "prov-1", Type: "mock", Name: "P", Config: "{}"}))
	must(d.CreateZone(&models.Zone{ID: "zone-1", ProviderID: "prov-1", Name: "example.com"}))
	for _, id := range []string{"p", "a", "b", "c"} {
		must(d.CreateAgent(&models.Agent{ID: "agent-" + id, Name: id, FQDN: id + ".edge.example.com", Status: models.AgentStatusAdopted}))
		must(d.CreateServer(&models.Server{ID: "srv-" + id, AgentID: "agent-" + id, Name: "srv-" + id, Address: "10.0.0.1"}))
		if id != "p" {
			must(d.AddAgentZone("agent-"+id, "zone-1"))
		}
	}
	dom := &models.Domain{Subdomain: "app", ZoneID: "zone-1", ServerID: "srv-p", Port: 80, SSLMode: models.SSLModeAuto, Status: models.DomainStatusActive}
	must(d.CreateDomain(dom))
	return dom
}

func TestSetDomainBackups(t *testing.T) {
	d := testDB(t)
	dom := seedBackupTopology(t, d)
	now := time.Now().UTC()

	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-b", "srv-a"}, now); err != nil {
		t.Fatal(err)
	}
	backups, _ := d.ListDomainBackups(dom.ID)
	if len(backups) != 2 || backups[0].ServerID != "srv-b" || backups[1].ServerID != "srv-a" {
		t.Fatalf("order not kept: %+v", backups)
	}
	cands, err := d.DomainCandidates(dom)
	if err != nil || len(cands) != 3 || !cands[0].Primary || cands[1].Server.ID != "srv-b" {
		t.Fatalf("candidates = %+v, %v", cands, err)
	}
	if sb, _ := d.ListStandbyDomains("agent-a"); len(sb) != 1 || sb[0].Server.ID != "srv-a" {
		t.Fatalf("standby domains of agent-a = %+v", sb)
	}

	// agent-b leaves the zone: it can stay a backup, and dropping agent-a
	// still works, but it cannot be added anew.
	if err := d.RemoveAgentZone("agent-b", "zone-1"); err != nil {
		t.Fatal(err)
	}
	removed, err := d.SetDomainBackups(dom.ID, []string{"srv-b"}, now)
	if err != nil || !slices.Equal(removed, []string{"agent-a"}) {
		t.Fatalf("dropping agent-a = %v, %v", removed, err)
	}
	if _, err := d.SetDomainBackups(dom.ID, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-b"}, now); !errors.Is(err, ErrInvalidBackups) {
		t.Fatalf("re-adding a backup outside the zone = %v", err)
	}

	// A primary on a backup agent is refused.
	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-c"}, now); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckPrimaryServer(dom.ID, "srv-c"); !errors.Is(err, ErrInvalidBackups) {
		t.Fatalf("CheckPrimaryServer = %v", err)
	}
	if err := d.CheckPrimaryServer(dom.ID, "srv-a"); err != nil {
		t.Fatalf("CheckPrimaryServer for a free agent = %v", err)
	}

	// A deleting domain can still lose its backups (server cascade).
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatal(err)
	}
	agents, err := d.RemoveServerFromBackups("srv-c", now)
	if err != nil || !slices.Equal(agents, []string{"agent-c"}) {
		t.Fatalf("RemoveServerFromBackups = %v, %v", agents, err)
	}
	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-a"}, now); !errors.Is(err, ErrInvalidBackups) {
		t.Fatalf("adding a backup to a deleting domain = %v", err)
	}
}

func TestDomainFailoverStateRoundTrip(t *testing.T) {
	d := testDB(t)
	dom := seedBackupTopology(t, d)
	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-a"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 11, 18, 10, 0, 0, 123, time.UTC)
	want := models.DomainFailoverState{DomainID: dom.ID, ActiveServerID: "srv-a", PendingServerID: "srv-p", PendingSince: &since, SwitchedAt: &since, Switches: 3}
	if err := d.SaveDomainFailover(want); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDomainFailover(dom.ID)
	if err != nil || got.ActiveServerID != "srv-a" || got.Switches != 3 || got.PendingSince == nil || !got.PendingSince.Equal(since) {
		t.Fatalf("GetDomainFailover = %+v, %v", got, err)
	}
	doms := []models.Domain{*dom}
	if err := d.FillDomainFailover(doms); err != nil || doms[0].ActiveServerID != "srv-a" {
		t.Fatalf("FillDomainFailover = %+v, %v", doms[0], err)
	}

	// The record points at srv-a and the primary has no heartbeat: removing
	// srv-a would leave nothing healthy to move to, so it is refused.
	if _, err := d.SetDomainBackups(dom.ID, []string{}, time.Now()); !errors.Is(err, ErrActiveBackupInUse) {
		t.Fatalf("removing the active backup with nothing healthy left = %v", err)
	}
	if _, err := d.RemoveServerFromBackups("srv-a", time.Now()); !errors.Is(err, ErrActiveBackupInUse) {
		t.Fatalf("server cascade of the active backup = %v", err)
	}
	// With the primary back it may go; the reconciler moves the record.
	if err := d.UpdateAgentHeartbeat("agent-p", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetDomainBackups(dom.ID, []string{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	doms = []models.Domain{*dom}
	if err := d.FillDomainFailover(doms); err != nil || doms[0].ActiveServerID != "srv-p" || len(doms[0].BackupServerIDs) != 0 {
		t.Fatalf("FillDomainFailover after clear = %+v, %v", doms[0], err)
	}

	// A deleted domain takes its state and backups with it.
	if err := d.DeleteDomain(dom.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveDomainFailover(want); err != nil {
		t.Fatalf("saving for a deleted domain = %v, want a silent skip", err)
	}
	if states, _ := d.ListDomainFailoverStates(); len(states) != 0 {
		t.Fatalf("state stored for a deleted domain: %+v", states)
	}
}

// Path routes and failover backups exclude each other: route servers sit on
// the primary agent, so a backup agent's standby copy would dial the primary
// site's addresses.
func TestDomainBackupsAndPathRoutesExcludeEachOther(t *testing.T) {
	d := testDB(t)
	dom := seedBackupTopology(t, d)
	now := time.Now().UTC()

	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-a"}, now); err != nil {
		t.Fatal(err)
	}
	withRoutes := *dom
	withRoutes.ProxyConfig.Routes = []models.PathRoute{{Match: "prefix", Path: "/api", ServerID: "srv-p", Port: 7000}}
	if err := d.CheckDomainRoutes(&withRoutes); !errors.Is(err, ErrRoutesWithBackups) {
		t.Fatalf("routes on a domain with backups: err = %v, want ErrRoutesWithBackups", err)
	}

	if _, err := d.SetDomainBackups(dom.ID, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateDomain(&withRoutes); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-a"}, now); !errors.Is(err, ErrInvalidBackups) {
		t.Fatalf("backups on a domain with path routes: err = %v, want ErrInvalidBackups", err)
	}
}
