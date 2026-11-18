package db

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func TestDiscoverySourceConfigEncryptedAtRest(t *testing.T) {
	d := testDB(t)
	src := &models.DiscoverySource{ID: "src-1", Type: "proxmox", Name: "PVE",
		Config: `{"url":"pve.lan","token_id":"a@pve!b","token_secret":"very-secret-uuid"}`}
	if err := d.CreateDiscoverySource(src); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := d.read.QueryRow(`SELECT config FROM discovery_sources WHERE id = 'src-1'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "very-secret-uuid") || strings.Contains(raw, "pve.lan") {
		t.Fatalf("config stored in clear text: %s", raw)
	}
	got, err := d.GetDiscoverySource("src-1")
	if err != nil || got.Config != src.Config {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	if _, err := d.GetDiscoverySource("nope"); !errors.Is(err, ErrDiscoverySourceNotFound) {
		t.Fatalf("missing source err = %v", err)
	}
}

func TestImportedServerUniquePerMachine(t *testing.T) {
	d := testDB(t)
	if err := d.CreateAgent(&models.Agent{ID: "a1", Name: "A", FQDN: "a.example.com", DNSMode: models.DNSModeStatic}); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateDiscoverySource(&models.DiscoverySource{ID: "src-1", Type: "proxmox", Name: "PVE", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	mk := func(id, ext string) error {
		return d.CreateServer(&models.Server{ID: id, AgentID: "a1", Name: id, Address: "10.0.0.1", DiscoverySourceID: "src-1", ExternalID: ext})
	}
	if err := mk("s1", "pve/n1/qemu/1"); err != nil {
		t.Fatal(err)
	}
	if err := mk("s2", "pve/n1/qemu/1"); !errors.Is(err, ErrServerAlreadyImported) {
		t.Fatalf("duplicate import err = %v, want ErrServerAlreadyImported", err)
	}
	// Manually added servers have no external ID and never collide.
	for _, id := range []string{"m1", "m2"} {
		if err := d.CreateServer(&models.Server{ID: id, AgentID: "a1", Name: id, Address: "10.0.0.2"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := d.RecordDiscoveryRun("src-1", now, `{"candidates":[]}`, []DiscoveryServerUpdate{{ServerID: "s1", ExternalID: "pve/n1/qemu/1", MissingSince: &now}}); err != nil {
		t.Fatal(err)
	}
	s, err := d.GetServer("s1")
	if err != nil || s.DiscoveryMissingSince == nil || !s.DiscoveryMissingSince.Equal(now) {
		t.Fatalf("missing flag = %+v, %v", s, err)
	}
	src, _ := d.GetDiscoverySource("src-1")
	if src.LastRunAt == nil || src.LastError != "" {
		t.Fatalf("source after run = %+v", src)
	}
	if err := d.RecordDiscoveryFailure("src-1", now, "boom"); err != nil {
		t.Fatal(err)
	}
	if res, _ := d.GetDiscoveryResult("src-1"); res != `{"candidates":[]}` {
		t.Fatalf("a failed run must keep the last result, got %q", res)
	}

	if err := d.DeleteDiscoverySource("src-1"); err != nil {
		t.Fatal(err)
	}
	s, err = d.GetServer("s1")
	if err != nil || s.ExternalID != "" || s.DiscoverySourceID != "" || s.DiscoveryMissingSince != nil {
		t.Fatalf("server after source delete = %+v, %v; want kept and unlinked", s, err)
	}
}
