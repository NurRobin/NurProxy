package discoverysvc

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/discovery"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

type countingDiscoverer struct {
	runs atomic.Int32
	fail atomic.Bool
}

func (c *countingDiscoverer) Info() discovery.Info                        { return discovery.Info{ID: "counting"} }
func (c *countingDiscoverer) ValidateConfig(json.RawMessage) error        { return nil }
func (c *countingDiscoverer) Test(context.Context, json.RawMessage) error { return nil }
func (c *countingDiscoverer) Summary(json.RawMessage) string              { return "" }
func (c *countingDiscoverer) Discover(context.Context, json.RawMessage) (*discovery.Result, error) {
	c.runs.Add(1)
	if c.fail.Load() {
		return nil, errors.New("cluster unreachable")
	}
	return &discovery.Result{Candidates: []discovery.Candidate{{ExternalID: "x/1", Name: "one"}}}, nil
}

var counting = &countingDiscoverer{}

func init() { discovery.Register(counting) }

func testDB(t *testing.T) *db.DB {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestSyncDueRunsOnlyDueSources(t *testing.T) {
	d := testDB(t)
	for _, src := range []*models.DiscoverySource{
		{ID: "periodic", Type: "counting", Name: "P", Config: "{}", SyncInterval: 300},
		{ID: "manual", Type: "counting", Name: "M", Config: "{}"},
	} {
		if err := d.CreateDiscoverySource(src); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(d, false)
	start := counting.runs.Load()
	now := time.Now()

	svc.syncDue(context.Background(), now)
	if got := counting.runs.Load() - start; got != 1 {
		t.Fatalf("first sync ran %d sources, want only the periodic one", got)
	}
	svc.syncDue(context.Background(), now.Add(time.Minute))
	if got := counting.runs.Load() - start; got != 1 {
		t.Fatalf("a source inside its interval ran again (%d runs)", got)
	}
	svc.syncDue(context.Background(), now.Add(6*time.Minute))
	if got := counting.runs.Load() - start; got != 2 {
		t.Fatalf("a source past its interval did not run (%d runs)", got)
	}

	// A failed run is recorded and keeps the previous result.
	counting.fail.Store(true)
	defer counting.fail.Store(false)
	if _, err := svc.Run(context.Background(), "periodic", nil); err == nil {
		t.Fatal("Run should report the failure")
	}
	v, err := svc.View("periodic")
	if err != nil {
		t.Fatal(err)
	}
	if v.LastError == "" || !v.HasResult || len(v.Candidates) != 1 {
		t.Fatalf("view after a failed run = %+v", v)
	}
	entries, _, err := d.ListAuditLog(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	periodic := 0
	for _, e := range entries {
		if e.Action == "discovery_run" && e.Source == models.AuditSourceSystem {
			periodic++
		}
	}
	if periodic != 2 {
		t.Fatalf("periodic runs audited as system = %d, want 2", periodic)
	}
}

func TestValidSyncInterval(t *testing.T) {
	for in, want := range map[int]bool{0: true, 299: false, 300: true, 604800: true, 604801: false, -1: false} {
		if ValidSyncInterval(in) != want {
			t.Errorf("ValidSyncInterval(%d) = %v", in, !want)
		}
	}
}
