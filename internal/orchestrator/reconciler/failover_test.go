package reconciler

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/provider"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// setupFailover extends setupScenario with a second agent in the zone, a
// server on it, and that server as the domain's backup.
func setupFailover(t *testing.T, d *db.DB) (dom *models.Domain, primary, backup *models.Agent) {
	t.Helper()
	_, zone, a1, _, dom := setupScenario(t, d)
	now := time.Now().UTC()
	backup = &models.Agent{
		ID: "agent-2", Name: "Agent Two", FQDN: "agent2.example.com",
		APIURL: "https://agent2.example.com:8443", TokenHash: "token-hash-2",
		DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted, LastSeen: &now,
	}
	if err := d.CreateAgent(backup); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := d.AddAgentZone(backup.ID, zone.ID); err != nil {
		t.Fatalf("AddAgentZone: %v", err)
	}
	if err := d.CreateServer(&models.Server{ID: "srv-2", AgentID: backup.ID, Name: "Backup", Address: "10.0.0.2"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if _, err := d.SetDomainBackups(dom.ID, []string{"srv-2"}, now); err != nil {
		t.Fatalf("SetDomainBackups: %v", err)
	}
	return dom, a1, backup
}

func setLastSeen(t *testing.T, d *db.DB, agentID string, at time.Time) {
	t.Helper()
	a, err := d.GetAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	at = at.UTC()
	a.LastSeen = &at
	if err := d.UpdateAgent(a); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
}

func cnameContent(t *testing.T, d *db.DB, mp *mockDNSProvider, domID int64) string {
	t.Helper()
	dom, err := d.GetDomain(domID)
	if err != nil {
		t.Fatal(err)
	}
	if dom.DNSRecordID == "" {
		t.Fatal("domain has no DNS record")
	}
	rec, ok := mp.getRecord(dom.DNSRecordID)
	if !ok {
		t.Fatalf("record %s is gone at the provider", dom.DNSRecordID)
	}
	return rec.Content
}

func auditCount(t *testing.T, d *db.DB, action string) int {
	t.Helper()
	entries, _, err := d.ListAuditLog(200, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

func TestFailover_switchesCNAMEToBackupAndFailsBack(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	dom, primary, backup := setupFailover(t, d)
	if err := d.SetSetting("failover_failback_delay", "60"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := New(d, newMockAgentClient(), time.Minute)
	r.clock = func() time.Time { return now }
	ctx := context.Background()

	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != primary.FQDN {
		t.Fatalf("initial CNAME -> %s, want the primary %s", got, primary.FQDN)
	}

	// One missed heartbeat (inside offline timeout + grace) moves nothing.
	setLastSeen(t, d, primary.ID, now.Add(-100*time.Second))
	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != primary.FQDN {
		t.Fatalf("CNAME moved on a single missed heartbeat: %s", got)
	}

	// Primary silent past 90 s + 30 s: the record moves to the backup.
	setLastSeen(t, d, primary.ID, now.Add(-10*time.Minute))
	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != backup.FQDN {
		t.Fatalf("after failover CNAME -> %s, want the backup %s", got, backup.FQDN)
	}
	if auditCount(t, d, "failover") != 1 {
		t.Fatal("expected one failover audit entry")
	}
	st, _ := d.GetDomainFailover(dom.ID)
	if st.ActiveServerID != "srv-2" || st.Switches != 1 {
		t.Fatalf("failover state = %+v", st)
	}
	doms := []models.Domain{*dom}
	if err := d.FillDomainFailover(doms); err != nil || doms[0].ActiveServerID != "srv-2" || !slices.Equal(doms[0].BackupServerIDs, []string{"srv-2"}) {
		t.Fatalf("FillDomainFailover = %+v, %v", doms[0], err)
	}

	// The primary comes back: the record waits out the failback delay.
	setLastSeen(t, d, primary.ID, now)
	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != backup.FQDN {
		t.Fatalf("failed back before the delay: %s", got)
	}

	now = now.Add(61 * time.Second)
	setLastSeen(t, d, primary.ID, now)
	setLastSeen(t, d, backup.ID, now)
	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != primary.FQDN {
		t.Fatalf("after the delay CNAME -> %s, want the primary again", got)
	}
	if auditCount(t, d, "failback") != 1 {
		t.Fatal("expected one failback audit entry")
	}
}

func TestFailover_allAgentsOfflineKeepsTheRecord(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	dom, primary, backup := setupFailover(t, d)
	now := time.Now().UTC()
	r := New(d, newMockAgentClient(), time.Minute)
	r.clock = func() time.Time { return now }
	ctx := context.Background()
	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}

	setLastSeen(t, d, primary.ID, now.Add(-time.Hour))
	setLastSeen(t, d, backup.ID, now.Add(-time.Hour))
	for range 3 {
		if err := r.reconcileDNS(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := cnameContent(t, d, mp, dom.ID); got != primary.FQDN {
		t.Fatalf("CNAME -> %s, want it left on %s", got, primary.FQDN)
	}
	recs, _ := mp.ListRecords(ctx, nil, "app.example.com", "")
	if len(recs) != 1 {
		t.Fatalf("want exactly the one record kept, have %d", len(recs))
	}
	if n := auditCount(t, d, "failover_all_down"); n != 1 {
		t.Fatalf("failover_all_down audited %d times, want once", n)
	}

	// The backup reports first: it takes over at once.
	setLastSeen(t, d, backup.ID, now)
	if err := r.reconcileDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != backup.FQDN {
		t.Fatalf("CNAME -> %s, want the backup that came back", got)
	}
}

func TestFailover_backupLeavingTheZoneIsNotSelected(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	dom, primary, backup := setupFailover(t, d)
	if err := d.RemoveAgentZone(backup.ID, dom.ZoneID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := New(d, newMockAgentClient(), time.Minute)
	r.clock = func() time.Time { return now }
	setLastSeen(t, d, primary.ID, now.Add(-time.Hour))
	if err := r.reconcileDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != primary.FQDN {
		t.Fatalf("CNAME -> %s; a backup outside the zone must not be selected", got)
	}
}

func TestFailover_takeoverWritesTheActiveTarget(t *testing.T) {
	d := testDB(t)
	mp := registerMockProvider(t)
	dom, primary, backup := setupFailover(t, d)
	now := time.Now().UTC()
	setLastSeen(t, d, primary.ID, now.Add(-time.Hour))
	mp.seedRecord(provider.Record{Type: "A", Name: "app.example.com", Content: "203.0.113.9"})
	r := New(d, newMockAgentClient(), time.Minute)
	r.clock = func() time.Time { return now }
	if err := r.TakeoverDomainDNS(context.Background(), dom.ID); err != nil {
		t.Fatalf("TakeoverDomainDNS: %v", err)
	}
	if got := cnameContent(t, d, mp, dom.ID); got != backup.FQDN {
		t.Fatalf("takeover CNAME -> %s, want the active backup %s", got, backup.FQDN)
	}
}

func TestFailover_standbyRouteAndCertOnBackupAgent(t *testing.T) {
	d := testDB(t)
	dom, primary, backup := setupFailover(t, d)
	if err := d.UpsertCertificate(&models.Certificate{
		ID: "cert-1", Host: "app.example.com", Names: []string{"app.example.com"},
		CertPEM: "LEAFCHAIN", KeyPEM: "PRIVATEKEY",
	}); err != nil {
		t.Fatal(err)
	}
	hub := newMockHub()
	hub.setConnected(primary.ID, true)
	hub.setConnected(backup.ID, true)
	r := New(d, newMockAgentClient(), time.Minute)
	r.SetHub(hub)

	if err := r.PushAgentRoutes(backup.ID); err != nil {
		t.Fatal(err)
	}
	set, ok := hub.lastSet(backup.ID)
	if !ok || len(set.Intents) != 1 {
		t.Fatalf("backup agent got %+v, want one standby intent", set)
	}
	in := set.Intents[0]
	if in.ArtifactID != db.StandbyArtifactID(dom.ID, backup.ID) || in.Route.Host != "app.example.com" || in.Route.Upstream.Addr != "10.0.0.2" {
		t.Fatalf("standby intent = %+v", in)
	}
	if len(set.Certs) != 1 || set.Certs[0].Host != "app.example.com" {
		t.Fatalf("standby push carries no certificate: %+v", set.Certs)
	}
	if !slices.Contains(set.CertKeep, "app.example.com") {
		t.Fatalf("standby cert not in the keep list: %v", set.CertKeep)
	}

	// The primary keeps its own route, under the primary artifact id.
	if err := r.PushAgentRoutes(primary.ID); err != nil {
		t.Fatal(err)
	}
	pset, _ := hub.lastSet(primary.ID)
	if len(pset.Intents) != 1 || pset.Intents[0].ArtifactID != artifactIDForDomain(dom.ID) || pset.Intents[0].Route.Upstream.Addr != "10.0.0.1" {
		t.Fatalf("primary intents = %+v", pset.Intents)
	}

	// A renewal reaches both agents.
	before := len(hub.sets[backup.ID])
	if err := r.RepushCertForHost(context.Background(), "app.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(hub.sets[backup.ID]) != before+1 {
		t.Fatal("renewal re-push skipped the standby agent")
	}

	// Removing the backup drops the route from the next push.
	if _, err := d.SetDomainBackups(dom.ID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := r.PushAgentRoutes(backup.ID); err != nil {
		t.Fatal(err)
	}
	set, _ = hub.lastSet(backup.ID)
	if len(set.Intents) != 0 || slices.Contains(set.CertKeep, "app.example.com") {
		t.Fatalf("standby route or cert kept after the backup was removed: %+v", set)
	}
}

func TestFailover_deleteTombstonesStandbyOnNginxBackup(t *testing.T) {
	d := testDB(t)
	registerMockProvider(t)
	dom, _, backup := setupFailover(t, d)
	if err := d.UpdateAgentHealth(backup.ID, "", "", "", false, "existing"); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateAgentDetection(backup.ID, &models.ProxyDetection{Installed: true, Kind: "nginx"}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateDomainStatus(dom.ID, models.DomainStatusDeleting, ""); err != nil {
		t.Fatal(err)
	}
	r := New(d, newMockAgentClient(), time.Minute)
	if err := r.reconcileDeletions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetDomain(dom.ID); err == nil {
		t.Fatal("domain row not removed")
	}
	tombs, err := d.ListManagedRouteTombstones(backup.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tombs) != 1 || tombs[0].ResourceID != db.StandbyArtifactID(dom.ID, backup.ID) || tombs[0].Host != "app.example.com" {
		t.Fatalf("standby tombstones = %+v", tombs)
	}
	if ids, _ := d.DomainsBackedByServer("srv-2"); len(ids) != 0 {
		t.Fatalf("backup rows outlived the domain: %v", ids)
	}
}
