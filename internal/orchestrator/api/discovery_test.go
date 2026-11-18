package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/NurRobin/NurProxy/internal/discovery"
	_ "github.com/NurRobin/NurProxy/internal/discovery/proxmox" // registers "proxmox"
	"github.com/NurRobin/NurProxy/internal/orchestrator/discoverysvc"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// fakeDiscoverer returns whatever result the test sets. Its IDs follow the
// Proxmox shape so the node-independent identity applies.
type fakeDiscoverer struct {
	mu  sync.Mutex
	res discovery.Result
}

func (f *fakeDiscoverer) Info() discovery.Info {
	return discovery.Info{ID: "fake-discovery", Name: "Fake", SecretFields: []string{"secret"}}
}
func (f *fakeDiscoverer) ValidateConfig(json.RawMessage) error        { return nil }
func (f *fakeDiscoverer) Test(context.Context, json.RawMessage) error { return nil }
func (f *fakeDiscoverer) Summary(json.RawMessage) string              { return "fake endpoint" }
func (f *fakeDiscoverer) IdentityKey(id string) string                { return pveKey(id) }
func (f *fakeDiscoverer) set(res discovery.Result)                    { f.mu.Lock(); f.res = res; f.mu.Unlock() }
func (f *fakeDiscoverer) Discover(context.Context, json.RawMessage) (*discovery.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.res
	r.Candidates = append([]discovery.Candidate(nil), f.res.Candidates...)
	return &r, nil
}

func pveKey(id string) string {
	p := strings.Split(id, "/")
	if len(p) == 4 {
		return p[0] + "/" + p[2] + "/" + p[3]
	}
	return id
}

var fakeDisc = &fakeDiscoverer{}

func init() { discovery.Register(fakeDisc) }

func cand(id, name, addr string) discovery.Candidate {
	c := discovery.Candidate{ExternalID: id, Name: name, Addresses: []discovery.Address{}}
	if addr != "" {
		a, _ := discovery.NewAddress(addr, 24, "eth0")
		c.Addresses = []discovery.Address{a}
		c.SuggestedAddress = addr
	}
	return c
}

func decode[T any](t *testing.T, w interface{ Body() []byte }) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body(), &v); err != nil {
		t.Fatalf("decode: %v: %s", err, w.Body())
	}
	return v
}

type recorder struct {
	code int
	body []byte
}

func (r recorder) Body() []byte { return r.body }

func TestDiscoveryRunImportAndResync(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)
	if err := database.CreateAgent(&models.Agent{ID: "agent-1", Name: "Edge", FQDN: "edge.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateAgent(&models.Agent{ID: "agent-2", Name: "Edge2", FQDN: "edge2.example.com", DNSMode: models.DNSModeStatic, Status: models.AgentStatusAdopted}); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any) recorder {
		w := doRequest(t, handler, method, path, body, cookie)
		return recorder{w.Code, w.Body.Bytes()}
	}

	fakeDisc.set(discovery.Result{Candidates: []discovery.Candidate{
		cand("pve/n1/qemu/101", "web", "192.168.1.21"),
		cand("pve/n1/qemu/102", "db", "192.168.1.22"),
		cand("pve/n2/qemu/103", "noaddr", ""),
	}})

	w := call("POST", "/api/v1/discovery/sources", map[string]any{
		"type": "fake-discovery", "name": "Lab", "config": map[string]string{"secret": "hunter2"},
	})
	if w.code != http.StatusCreated {
		t.Fatalf("create source: %d %s", w.code, w.body)
	}
	if strings.Contains(string(w.body), "hunter2") {
		t.Fatalf("create response leaks the secret: %s", w.body)
	}
	src := decode[struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
	}](t, w)

	// Importing before any run is refused.
	w = call("POST", "/api/v1/agents/agent-1/servers/import", map[string]any{
		"source_id": src.ID, "items": []map[string]string{{"external_id": "pve/n1/qemu/101"}},
	})
	if w.code != http.StatusBadRequest {
		t.Fatalf("import before run: %d %s", w.code, w.body)
	}

	w = call("POST", "/api/v1/discovery/sources/"+src.ID+"/run", nil)
	if w.code != http.StatusOK {
		t.Fatalf("run: %d %s", w.code, w.body)
	}
	view := decode[discoverysvc.View](t, w)
	if len(view.Candidates) != 3 || !view.HasResult {
		t.Fatalf("view = %+v", view)
	}

	// A candidate without a detected address needs one from the operator; the
	// whole request is refused and nothing is created.
	w = call("POST", "/api/v1/agents/agent-1/servers/import", map[string]any{
		"source_id": src.ID, "items": []map[string]string{{"external_id": "pve/n1/qemu/101"}, {"external_id": "pve/n2/qemu/103"}},
	})
	if w.code != http.StatusBadRequest || !strings.Contains(string(w.body), "enter one") {
		t.Fatalf("import without address: %d %s", w.code, w.body)
	}
	if s, _ := database.ListServersByAgent("agent-1"); len(s) != 0 {
		t.Fatalf("a refused import created %d servers", len(s))
	}

	w = call("POST", "/api/v1/agents/agent-1/servers/import", map[string]any{
		"source_id": src.ID, "items": []map[string]string{
			{"external_id": "pve/n1/qemu/101"},
			{"external_id": "pve/n2/qemu/103", "address": "10.9.9.9", "name": "desktop"},
		},
	})
	if w.code != http.StatusCreated {
		t.Fatalf("import: %d %s", w.code, w.body)
	}
	imp := decode[discoverysvc.ImportResult](t, w)
	if len(imp.Created) != 2 || imp.Created[0].Address != "192.168.1.21" || imp.Created[1].Name != "desktop" || imp.Created[1].Address != "10.9.9.9" {
		t.Fatalf("import result = %+v", imp)
	}

	// Importing the same machine again, even under another agent, is skipped.
	w = call("POST", "/api/v1/agents/agent-2/servers/import", map[string]any{
		"source_id": src.ID, "items": []map[string]string{{"external_id": "pve/n1/qemu/101"}},
	})
	imp = decode[discoverysvc.ImportResult](t, w)
	if w.code != http.StatusOK || len(imp.Created) != 0 || len(imp.Skipped) != 1 {
		t.Fatalf("duplicate import: %d %+v", w.code, imp)
	}

	// Imported servers stay editable.
	webID := ""
	for _, s := range mustServers(t, database, "agent-1") {
		if s.ExternalID == "pve/n1/qemu/101" {
			webID = s.ID
		}
	}
	w = call("PUT", "/api/v1/servers/"+webID, map[string]string{"address": "192.168.1.21:8080", "name": "web-renamed"})
	if w.code != http.StatusOK {
		t.Fatalf("edit imported server: %d %s", w.code, w.body)
	}

	// Re-sync: web moved to node n2 (same machine), desktop is gone, a new VM
	// appeared. Node n3 could not be listed, so nothing under it is gone.
	fakeDisc.set(discovery.Result{
		Candidates: []discovery.Candidate{
			cand("pve/n2/qemu/101", "web", "192.168.1.21"),
			cand("pve/n1/qemu/102", "db", "192.168.1.22"),
			cand("pve/n1/qemu/104", "new-vm", "192.168.1.24"),
		},
		Incomplete: []string{"pve/n3/"},
	})
	w = call("POST", "/api/v1/discovery/sources/"+src.ID+"/run", nil)
	if w.code != http.StatusOK {
		t.Fatalf("re-run: %d %s", w.code, w.body)
	}
	view = decode[discoverysvc.View](t, w)
	if len(view.Missing) != 1 || view.Missing[0].Name != "desktop" {
		t.Fatalf("missing = %+v, want the desktop server", view.Missing)
	}
	imported := map[string]string{}
	for _, c := range view.Candidates {
		imported[c.ExternalID] = c.ServerID
	}
	if imported["pve/n2/qemu/101"] != webID || imported["pve/n1/qemu/104"] != "" {
		t.Fatalf("candidates = %+v", view.Candidates)
	}
	web, err := database.GetServer(webID)
	if err != nil {
		t.Fatal(err)
	}
	if web.ExternalID != "pve/n2/qemu/101" || web.DiscoveryMissingSince != nil || web.Name != "web-renamed" || web.Address != "192.168.1.21:8080" {
		t.Fatalf("moved server = %+v; want the new node, not missing, operator edits kept", web)
	}

	// The machine coming back clears the flag.
	fakeDisc.set(discovery.Result{Candidates: []discovery.Candidate{
		cand("pve/n2/qemu/101", "web", "192.168.1.21"),
		cand("pve/n2/qemu/103", "noaddr", ""),
	}})
	w = call("POST", "/api/v1/discovery/sources/"+src.ID+"/run", nil)
	view = decode[discoverysvc.View](t, w)
	if len(view.Missing) != 0 {
		t.Fatalf("missing after the machine returned = %+v", view.Missing)
	}

	// Listing the sources never includes config or the secret.
	w = call("GET", "/api/v1/discovery/sources", nil)
	if w.code != http.StatusOK || strings.Contains(string(w.body), "hunter2") || strings.Contains(string(w.body), "config") {
		t.Fatalf("list sources: %d %s", w.code, w.body)
	}

	// Deleting the source keeps the servers but unlinks them.
	w = call("DELETE", "/api/v1/discovery/sources/"+src.ID, nil)
	if w.code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.code, w.body)
	}
	for _, s := range mustServers(t, database, "agent-1") {
		if s.ExternalID != "" || s.DiscoverySourceID != "" {
			t.Fatalf("server %s still linked after source delete", s.Name)
		}
	}
	if len(mustServers(t, database, "agent-1")) != 2 {
		t.Fatal("deleting a source must not delete its imported servers")
	}

	// Audit entries never carry the secret.
	entries, _, err := database.ListAuditLog(200, 0)
	if err != nil {
		t.Fatal(err)
	}
	sawMissing := false
	for _, e := range entries {
		if strings.Contains(e.Details, "hunter2") {
			t.Fatalf("audit leaks the secret: %+v", e)
		}
		if e.Action == "discovery_missing" {
			sawMissing = true
		}
	}
	if !sawMissing {
		t.Fatal("the gone machine was not audited")
	}
}

func mustServers(t *testing.T, d interface {
	ListServersByAgent(string) ([]models.Server, error)
}, agentID string) []models.Server {
	t.Helper()
	s, err := d.ListServersByAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDiscoverySourceProxmoxValidationAndMasking(t *testing.T) {
	srv, database := testServer(t)
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	// Static validation runs before any connection attempt.
	w := doRequest(t, handler, "POST", "/api/v1/discovery/sources", map[string]any{
		"type": "proxmox", "name": "PVE", "config": map[string]any{"url": "pve.lan", "token_id": "bad", "token_secret": "s"},
	}, cookie)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "token_id") {
		t.Fatalf("invalid config: %d %s", w.Code, w.Body.String())
	}

	// skip_test stores without contacting the cluster (no network in tests).
	w = doRequest(t, handler, "POST", "/api/v1/discovery/sources", map[string]any{
		"type": "proxmox", "name": "PVE", "skip_test": true, "sync_interval": 3600,
		"config": map[string]any{"url": "pve.lan", "token_id": "nurproxy@pve!disc", "token_secret": "very-secret-uuid"},
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "very-secret-uuid") || !strings.Contains(body, "https://pve.lan:8006 as nurproxy@pve!disc") ||
		!strings.Contains(body, `"settings":{"token_id":"nurproxy@pve!disc","url":"pve.lan"}`) {
		t.Fatalf("create response = %s", body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	// Saving the edit form unchanged (every field sent, secret empty) keeps the
	// stored secret.
	w = doRequest(t, handler, "PUT", "/api/v1/discovery/sources/"+created.ID, map[string]any{
		"skip_test": true, "config": map[string]any{
			"url": "pve.lan", "token_id": "nurproxy@pve!disc", "token_secret": "",
			"verify_tls": false, "fingerprint": "", "ca_pem": "",
		},
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("unchanged update: %d %s", w.Code, w.Body.String())
	}

	// A changed endpoint or TLS check without the secret is refused, so the
	// stored secret can't be sent somewhere else.
	for _, cfg := range []map[string]any{
		{"url": "https://attacker.example:8006"},
		{"verify_tls": true, "token_secret": ""},
		{"fingerprint": "AA:BB"},
	} {
		w = doRequest(t, handler, "PUT", "/api/v1/discovery/sources/"+created.ID, map[string]any{"skip_test": true, "config": cfg}, cookie)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "token_secret sent again") {
			t.Errorf("update %v without secret: %d %s", cfg, w.Code, w.Body.String())
		}
		w = doRequest(t, handler, "POST", "/api/v1/discovery/test", map[string]any{"source_id": created.ID, "config": cfg}, cookie)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "token_secret sent again") {
			t.Errorf("test %v without secret: %d %s", cfg, w.Code, w.Body.String())
		}
	}

	// With the secret sent again the change goes through.
	w = doRequest(t, handler, "PUT", "/api/v1/discovery/sources/"+created.ID, map[string]any{
		"skip_test": true, "config": map[string]any{"verify_tls": true, "token_secret": "very-secret-uuid"},
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("update with secret: %d %s", w.Code, w.Body.String())
	}
	src, err := database.GetDiscoverySource(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src.Config, `"token_secret":"very-secret-uuid"`) || !strings.Contains(src.Config, `"verify_tls":true`) {
		t.Fatalf("merged config = %s", src.Config)
	}

	for _, tc := range []struct {
		interval int
		code     int
	}{{60, http.StatusBadRequest}, {0, http.StatusOK}, {900, http.StatusOK}} {
		w = doRequest(t, handler, "PUT", "/api/v1/discovery/sources/"+created.ID, map[string]any{"sync_interval": tc.interval}, cookie)
		if w.Code != tc.code {
			t.Errorf("sync_interval %d: %d %s", tc.interval, w.Code, w.Body.String())
		}
	}
}

func TestDiscoveryDryRunFixture(t *testing.T) {
	srv, database := testServer(t)
	srv.SetDiscovery(discoverysvc.New(database, true))
	handler := srv.Handler()
	cookie := setupAdmin(t, handler)

	w := doRequest(t, handler, "POST", "/api/v1/discovery/sources", map[string]any{
		"type": "proxmox", "name": "PVE dry",
		"config": map[string]any{"url": "pve.sandbox.test", "token_id": "root@pam!dry", "token_secret": "dummy"},
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create in dry-run (connection test simulated): %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	w = doRequest(t, handler, "POST", "/api/v1/discovery/sources/"+created.ID+"/run", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	var view discoverysvc.View
	_ = json.Unmarshal(w.Body.Bytes(), &view)
	if len(view.Candidates) != 4 || len(view.Warnings) != 1 {
		t.Fatalf("dry-run view = %+v", view)
	}
	w = doRequest(t, handler, "GET", "/api/v1/health", nil)
	if !strings.Contains(w.Body.String(), `"discovery_dry_run":true`) {
		t.Fatalf("health = %s", w.Body.String())
	}
}
