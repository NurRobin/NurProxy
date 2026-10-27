package mcp

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// The MCP domain tools take the same tri-state proxied setting as the REST API
// and refuse proxied=true on a zone whose provider has no proxy mode (#126).
func TestDomainToolsProxied(t *testing.T) {
	h, d := testHandler(t)
	enable(t, d)
	zoneID, serverID, _ := seed(t, d) // provider type "mock": no proxy mode

	if !callTool(t, h, "create_domain", map[string]any{
		"subdomain": "orange", "zone_id": zoneID, "server_id": serverID, "port": 8080, "proxied": true,
	}, nil) {
		t.Fatal("create_domain accepted proxied=true on a provider without proxy mode")
	}

	var dom models.Domain
	if callTool(t, h, "create_domain", map[string]any{
		"subdomain": "app", "zone_id": zoneID, "server_id": serverID, "port": 8080,
	}, &dom) {
		t.Fatal("create_domain without proxied failed")
	}
	if dom.Proxied != nil {
		t.Fatalf("proxied = %v, want unset", *dom.Proxied)
	}

	steps := []struct {
		name    string
		args    map[string]any
		wantErr bool
		want    *bool
	}{
		{"set false", map[string]any{"proxied": false}, false, boolp(false)},
		{"absent leaves false", map[string]any{"port": 9090}, false, boolp(false)},
		{"null clears", map[string]any{"proxied": nil}, false, nil},
		{"true refused", map[string]any{"proxied": true}, true, nil},
	}
	for _, st := range steps {
		st.args["id"] = dom.ID
		if isErr := callTool(t, h, "update_domain", st.args, nil); isErr != st.wantErr {
			t.Fatalf("%s: isError = %v, want %v", st.name, isErr, st.wantErr)
		}
		got, err := d.GetDomain(dom.ID)
		if err != nil {
			t.Fatal(err)
		}
		if (got.Proxied == nil) != (st.want == nil) || (got.Proxied != nil && *got.Proxied != *st.want) {
			t.Fatalf("%s: stored proxied = %v, want %v", st.name, got.Proxied, st.want)
		}
	}
}

func boolp(b bool) *bool { return &b }
