package main

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
)

// TestDiscoveryImportAll checks that --all selects only machines that are not
// imported yet and have an address (detected or given with --address).
func TestDiscoveryImportAll(t *testing.T) {
	srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"has_result":true,"candidates":[
				{"external_id":"pve/n1/qemu/101","name":"web","suggested_address":"192.168.1.21"},
				{"external_id":"pve/n1/qemu/102","name":"db","suggested_address":"192.168.1.22","server_id":"s-1"},
				{"external_id":"pve/n1/qemu/103","name":"desk"},
				{"external_id":"pve/n1/lxc/200","name":"ct"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"created":[],"skipped":[]}`)
	})
	cmdDiscovery([]string{"import", "src-1", "--agent", "agent-1", "--all", "--address", "pve/n1/lxc/200=10.0.0.9", "--url", srv.URL, "--key", "k"})
	if len(*reqs) != 2 {
		t.Fatalf("requests = %d, want candidates + import", len(*reqs))
	}
	imp := (*reqs)[1]
	if imp.method != http.MethodPost || imp.path != "/api/v1/agents/agent-1/servers/import" {
		t.Fatalf("import request = %s %s", imp.method, imp.path)
	}
	var body struct {
		SourceID string              `json:"source_id"`
		Items    []map[string]string `json:"items"`
	}
	if err := json.Unmarshal([]byte(imp.body), &body); err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{
		{"external_id": "pve/n1/qemu/101"},
		{"external_id": "pve/n1/lxc/200", "address": "10.0.0.9"},
	}
	if body.SourceID != "src-1" || !reflect.DeepEqual(body.Items, want) {
		t.Fatalf("import body = %+v, want items %v", body, want)
	}
}

// TestDiscoveryUpdateSendsOnlyGivenFields keeps an update from resetting the
// sync interval or the secret it was not asked to change.
func TestDiscoveryUpdateSendsOnlyGivenFields(t *testing.T) {
	srv, reqs := newTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *capturedReq) {
		_, _ = io.WriteString(w, `{}`)
	})
	cmdDiscovery([]string{"update", "src-1", "--config", `{"verify_tls":true}`, "--url", srv.URL, "--key", "k"})
	var body map[string]any
	if err := json.Unmarshal([]byte((*reqs)[0].body), &body); err != nil {
		t.Fatal(err)
	}
	if _, sent := body["sync_interval"]; sent {
		t.Errorf("sync_interval sent without --sync-interval: %v", body)
	}
	cfg, _ := body["config"].(map[string]any)
	if cfg["verify_tls"] != true || len(cfg) != 1 {
		t.Errorf("config = %v, want only verify_tls", cfg)
	}
}
