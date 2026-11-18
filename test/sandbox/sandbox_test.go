//go:build sandbox

// Package sandbox holds an end-to-end test of NurProxy's dry-run / sandbox mode
// (#93): it boots a dry-run orchestrator and a hermetic existing-proxy agent as
// subprocesses, drives the public REST API to stand up a provider, zone, agent
// adoption, server, and central-TLS domain, and asserts the whole control plane
// converges with no external DNS/ACME, bound proxy ports, installed proxy
// package, or privileges.
//
// It is the durable counterpart to scripts/dev-sandbox.sh: same flow, but with
// hard assertions (domain active, certificate issued, DNS records simulated,
// audit entries tagged source=dryrun). Gated behind the `sandbox` build tag so
// it never runs in the normal unit-test pass; invoke with `make test-sandbox`.
package sandbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	agentproxy "github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

const adminPassword = "sandbox-e2e-pass"

func TestSandboxEndToEnd(t *testing.T) {
	repoRoot := repoRoot(t)
	bin := buildBinaries(t, repoRoot)
	dataRoot := t.TempDir()

	stack := startDryOrchestrator(t, bin, dataRoot)
	base, api, zone := stack.base, stack.api, stack.zone

	// --- start the hermetic existing-nginx agent ------------------------------
	agentPort := freePort(t)
	agentDataDir := filepath.Join(dataRoot, "agent1")
	proxyConfigDir := filepath.Join(dataRoot, "nginx", "conf.d")
	if err := os.MkdirAll(proxyConfigDir, 0o755); err != nil {
		t.Fatalf("create sandbox nginx config dir: %v", err)
	}
	operatorPath := filepath.Join(proxyConfigDir, "operator.conf")
	operatorBytes := []byte("# operator-owned sandbox fixture\n")
	if err := os.WriteFile(operatorPath, operatorBytes, 0o644); err != nil {
		t.Fatalf("write operator fixture: %v", err)
	}
	// A certificate the host already serves (#80): the operator's nginx points
	// at it with http-level ssl_certificate directives, as a migrated host
	// would. The agent must discover it so it can be adopted instead of issued.
	legacyCert, legacyKey := sandboxServerCert(t, "legacy.sandbox.test")
	legacyDir := filepath.Join(dataRoot, "legacy-tls")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("create legacy cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "fullchain.pem"), []byte(legacyCert), 0o644); err != nil {
		t.Fatalf("write legacy cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "privkey.pem"), []byte(legacyKey), 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}
	legacyConf := fmt.Sprintf("# operator TLS defaults\nssl_certificate %s;\nssl_certificate_key %s;\n",
		filepath.Join(legacyDir, "fullchain.pem"), filepath.Join(legacyDir, "privkey.pem"))
	if err := os.WriteFile(filepath.Join(proxyConfigDir, "tls-defaults.conf"), []byte(legacyConf), 0o644); err != nil {
		t.Fatalf("write legacy tls config: %v", err)
	}
	agent := startProcess(t, bin.agent, []string{
		"-orchestrator", base,
		"-fqdn", "edge1.sandbox.test",
		"-api-port", fmt.Sprintf("%d", agentPort),
		"-data-dir", agentDataDir,
		"-proxy-mode", "existing",
		"-proxy-type", "nginx",
		"-proxy-config-dir", proxyConfigDir,
		"-proxy-binary", bin.proxy,
	}, "NURPROXY_NO_SUDO=1", "PATH="+filepath.Dir(bin.proxy)+string(os.PathListSeparator)+os.Getenv("PATH"))
	defer agent.stop()

	// A dry built-in agent next to it: its Caddy is simulated in memory, but the
	// routes and TLS strategy it records are what a real Caddy would be given,
	// so they can be checked against a real caddy binary below.
	caddyAgentPort := freePort(t)
	caddyAgentDataDir := filepath.Join(dataRoot, "agent2")
	caddyAgent := startProcess(t, bin.agent, []string{
		"-dry-run",
		"-orchestrator", base,
		"-fqdn", "edge2.sandbox.test",
		"-api-port", fmt.Sprintf("%d", caddyAgentPort),
		"-data-dir", caddyAgentDataDir,
	})
	defer caddyAgent.stop()

	// --- adopt the agents once they register ---------------------------------
	agentID := stack.adoptAgent(t, "edge1.sandbox.test", "edge1")
	caddyAgentID := stack.adoptAgent(t, "edge2.sandbox.test", "edge2")

	// --- server + central-TLS domain (triggers simulated issuance) -----------
	var server struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/agents/"+agentID+"/servers", map[string]string{
		"name": "app", "address": "10.0.0.5:8080",
	}, &server)
	assertDiscoveryImport(t, api, agentID)

	var domain struct {
		ID int `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "app", "zone_id": zone.ID, "server_id": server.ID,
		"port": 8080, "ssl_mode": "central",
	}, &domain)

	// Apex (@) domain alongside it (apex support, #92): the "@" sentinel must
	// converge through the same dry pipeline — DNS record created at the zone apex
	// (FQDN == bare zone), cert issued for the bare zone, route rendered. Created
	// now so it converges in the same reconciler cycle as "app" (no extra wait).
	// It is also the Cloudflare-proxied domain (#126): its CNAME must be created
	// with the orange cloud on.
	var apex struct {
		ID int `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "@", "zone_id": zone.ID, "server_id": server.ID,
		"port": 8080, "ssl_mode": "central", "proxied": true,
	}, &apex)

	// A domain for the host whose certificate the agent found on disk (#80).
	// Its first issuance waits for the operator to adopt that certificate.
	var legacy struct {
		ID int `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "legacy", "zone_id": zone.ID, "server_id": server.ID,
		"port": 8080, "ssl_mode": "central",
	}, &legacy)

	// Two domains opted into the zone wildcard certificate (#69). Created now so
	// they converge in the same cycle; both must end up on ONE shared
	// "*.sandbox.test" cert, issued once.
	wildcardIDs := make([]int, 0, 2)
	for _, sub := range []string{"w1", "w2"} {
		var wd struct {
			ID int `json:"id"`
		}
		api.post("/api/v1/domains", map[string]any{
			"subdomain": sub, "zone_id": zone.ID, "server_id": server.ID,
			"port": 8080, "ssl_mode": "central", "tls_wildcard": true,
		}, &wd)
		wildcardIDs = append(wildcardIDs, wd.ID)
	}
	// A domain on the Caddy agent that turns on most structured proxy options,
	// so the real-caddy check below covers more of caddygen than a bare proxy.
	var caddyServer struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/agents/"+caddyAgentID+"/servers", map[string]string{
		"name": "api", "address": "10.0.0.6",
	}, &caddyServer)
	var caddyDomain struct {
		ID int `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "api", "zone_id": zone.ID, "server_id": caddyServer.ID,
		"port": 9000, "ssl_mode": "central",
		"proxy_config": map[string]any{
			"force_https":             true,
			"websocket":               true,
			"custom_request_headers":  map[string]string{"X-Sandbox": "1"},
			"custom_response_headers": map[string]string{"X-Frame-Options": "DENY"},
			"path_strip":              "/v1",
			"timeout_read":            30,
			"timeout_idle":            60,
			"ip_allowlist":            []string{"10.0.0.0/8", "127.0.0.1"},
		},
	}, &caddyDomain)

	// --- assert convergence ---------------------------------------------------
	// The CNAME (which flips the domain to active) is written on a reconciler
	// cycle; the default interval is 60s, so allow one full cycle plus margin.
	var final string
	waitFor(t, 75*time.Second, func() bool {
		var d struct {
			Status      string `json:"status"`
			DNSManaged  bool   `json:"dns_managed"`
			DNSRecordID string `json:"dns_record_id"`
		}
		api.get(fmt.Sprintf("/api/v1/domains/%d", domain.ID), &d)
		final = d.Status
		return d.Status == "active" && d.DNSManaged && d.DNSRecordID != ""
	})
	if final != "active" {
		t.Fatalf("domain never became active (last status %q)", final)
	}

	// The apex (@) domain must converge the same way — proves the "@" sentinel
	// flows correctly through DNS create / issuance / render (apex support, #92).
	var apexFinal string
	waitFor(t, 75*time.Second, func() bool {
		var d struct {
			Status      string `json:"status"`
			DNSManaged  bool   `json:"dns_managed"`
			DNSRecordID string `json:"dns_record_id"`
		}
		api.get(fmt.Sprintf("/api/v1/domains/%d", apex.ID), &d)
		apexFinal = d.Status
		return d.Status == "active" && d.DNSManaged && d.DNSRecordID != ""
	})
	if apexFinal != "active" {
		t.Fatalf("apex (@) domain never became active (last status %q)", apexFinal)
	}

	// Both wildcard domains converge to active on the same self-signed
	// "*.sandbox.test" cert, installed on the agent once per FQDN.
	for _, id := range wildcardIDs {
		var status string
		waitFor(t, 75*time.Second, func() bool {
			var d struct {
				Status string `json:"status"`
			}
			api.get(fmt.Sprintf("/api/v1/domains/%d", id), &d)
			status = d.Status
			return d.Status == "active"
		})
		if status != "active" {
			t.Fatalf("wildcard domain %d never became active (last status %q)", id, status)
		}
	}
	var w1Cert, w2Cert string
	waitFor(t, 30*time.Second, func() bool {
		w1Cert = readFileNamed(agentDataDir, "w1.sandbox.test.crt")
		w2Cert = readFileNamed(agentDataDir, "w2.sandbox.test.crt")
		return w1Cert != "" && w1Cert == w2Cert
	})
	if w1Cert == "" || w1Cert != w2Cert {
		t.Fatal("wildcard domains did not receive the same certificate on the agent")
	}
	block, _ := pem.Decode([]byte(w1Cert))
	if block == nil {
		t.Fatal("wildcard certificate on the agent is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse wildcard certificate: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.sandbox.test" || leaf.Issuer.String() != leaf.Subject.String() {
		t.Fatalf("wildcard certificate names=%v issuer=%q subject=%q, want one self-signed *.sandbox.test", leaf.DNSNames, leaf.Issuer, leaf.Subject)
	}
	var wildAudit struct {
		Entries []struct {
			EntityID string `json:"entity_id"`
			Action   string `json:"action"`
		} `json:"entries"`
	}
	api.get("/api/v1/audit-log?limit=200", &wildAudit)
	issued := 0
	for _, e := range wildAudit.Entries {
		if e.Action == "renewed" && e.EntityID == "*.sandbox.test" {
			issued++
		}
		if e.Action == "renewed" && (e.EntityID == "w1.sandbox.test" || e.EntityID == "w2.sandbox.test") {
			t.Fatalf("wildcard domain got a per-host certificate: %+v", e)
		}
	}
	if issued != 1 {
		t.Fatalf("*.sandbox.test issued %d times, want exactly once", issued)
	}
	// The Caddy agent's domain converges in the same cycle; then its recorded
	// config goes through a real caddy when one is available (#96).
	stack.waitDomainActive(t, caddyDomain.ID)
	validateDryCaddyAgent(t, caddyAgentPort, caddyAgentDataDir, 1)

	// The DNS record must be a simulated one (dryrun-* ID from the in-memory store).
	var dom struct {
		DNSRecordID string `json:"dns_record_id"`
	}
	api.get(fmt.Sprintf("/api/v1/domains/%d", domain.ID), &dom)
	if got := dom.DNSRecordID; len(got) < 7 || got[:7] != "dryrun-" {
		t.Fatalf("expected a simulated dryrun-* DNS record ID, got %q", got)
	}

	// The audit trail must tag the simulated DNS/cert work as source=dryrun.
	var audit struct {
		Entries []struct {
			Action string `json:"action"`
			Source string `json:"source"`
		} `json:"entries"`
	}
	api.get("/api/v1/audit-log?limit=50", &audit)
	var sawDryRunDNS, sawIssuance bool
	for _, e := range audit.Entries {
		if e.Source == "dryrun" && (e.Action == "dns_created" || e.Action == "a_record_created") {
			sawDryRunDNS = true
		}
		if e.Source == "dryrun" && (e.Action == "renewed" || e.Action == "issue_failed") {
			sawIssuance = true
		}
	}
	if !sawDryRunDNS {
		t.Error("no audit entry with source=dryrun for DNS record creation")
	}
	if !sawIssuance {
		t.Error("no audit entry with source=dryrun for certificate issuance")
	}

	// Operator-imported certificate (#80): it replaces the dry-issued one, is
	// stored as imported, and reaches the agent's cert store over the same push.
	importedCert, importedKey := sandboxServerCert(t, "app.sandbox.test")
	var imported struct {
		Host   string `json:"host"`
		Source string `json:"source"`
	}
	api.put(fmt.Sprintf("/api/v1/domains/%d/certificate", domain.ID), map[string]string{
		"cert_pem": importedCert, "key_pem": importedKey,
	}, &imported)
	if imported.Host != "app.sandbox.test" || imported.Source != "imported" {
		t.Fatalf("certificate import response = %+v", imported)
	}
	agentCertPath := ""
	waitFor(t, 20*time.Second, func() bool {
		agentCertPath = findFileWithContent(agentDataDir, "app.sandbox.test.crt", importedCert)
		return agentCertPath != ""
	})
	t.Logf("imported certificate installed on the agent at %s", agentCertPath)

	// Adopting an on-disk certificate (#80). By now a reconciler cycle has run
	// for the legacy domain too, and its issuance must have been held back.
	var cands struct {
		Candidates []struct {
			Fingerprint string `json:"fingerprint"`
			Source      string `json:"source"`
			CertPath    string `json:"cert_path"`
			Serving     bool   `json:"serving"`
			Adoptable   bool   `json:"adoptable"`
			Reason      string `json:"reason"`
		} `json:"candidates"`
		OnFile   bool       `json:"certificate_on_file"`
		Deferred *time.Time `json:"issuance_deferred_until"`
	}
	api.get(fmt.Sprintf("/api/v1/domains/%d/certificate/candidates", legacy.ID), &cands)
	if len(cands.Candidates) == 0 || !cands.Candidates[0].Adoptable || !cands.Candidates[0].Serving ||
		cands.Candidates[0].CertPath != filepath.Join(legacyDir, "fullchain.pem") {
		t.Fatalf("legacy certificate not offered for adoption: %+v", cands)
	}
	if cands.OnFile || cands.Deferred == nil {
		t.Fatalf("legacy domain issuance was not held for adoption: on_file=%v deferred=%v", cands.OnFile, cands.Deferred)
	}
	var adopted struct {
		Host       string `json:"host"`
		Source     string `json:"source"`
		SourcePath string `json:"source_path"`
	}
	api.post(fmt.Sprintf("/api/v1/domains/%d/certificate/adopt", legacy.ID), map[string]string{
		"fingerprint": cands.Candidates[0].Fingerprint,
	}, &adopted)
	if adopted.Host != "legacy.sandbox.test" || adopted.Source != "imported" || adopted.SourcePath != filepath.Join(legacyDir, "fullchain.pem") {
		t.Fatalf("adoption response = %+v", adopted)
	}
	waitFor(t, 20*time.Second, func() bool {
		return findFileWithContent(agentDataDir, "legacy.sandbox.test.crt", legacyCert) != ""
	})
	api.get("/api/v1/audit-log?limit=100", &audit)
	var sawAdoption bool
	for _, e := range audit.Entries {
		if e.Action == "cert_adopted" {
			sawAdoption = true
		}
	}
	if !sawAdoption {
		t.Error("no cert_adopted audit entry")
	}

	// Per-domain logging (#150): the nginx agent advertises access log control,
	// and turning the access log off for one domain re-renders only that
	// domain's vhost. The error log level is not exercised: the agent offers it
	// only when the host's nginx error log is /var/log/nginx/error.log, which
	// depends on the machine, not on the hermetic fixture.
	waitFor(t, 30*time.Second, func() bool {
		var agents []struct {
			ID   string `json:"id"`
			Caps struct {
				AccessLog bool `json:"access_log"`
			} `json:"proxy_capabilities"`
		}
		api.get("/api/v1/agents", &agents)
		for _, a := range agents {
			if a.ID == agentID {
				return a.Caps.AccessLog
			}
		}
		return false
	})
	apexVhostPath := filepath.Join(proxyConfigDir, "nurproxy-sandbox.test.conf")
	apexVhostBefore, err := os.ReadFile(apexVhostPath)
	if err != nil {
		t.Fatalf("read apex vhost: %v", err)
	}
	api.put(fmt.Sprintf("/api/v1/domains/%d", domain.ID), map[string]any{"access_log": "off"}, nil)
	appPath := filepath.Join(proxyConfigDir, "nurproxy-app.sandbox.test.conf")
	waitFor(t, 75*time.Second, func() bool {
		content, err := os.ReadFile(appPath)
		return err == nil && bytes.Contains(content, []byte("    access_log off;\n"))
	})
	if got, err := os.ReadFile(apexVhostPath); err != nil || !bytes.Equal(got, apexVhostBefore) {
		t.Fatalf("logging change on one domain rewrote another domain's vhost: err=%v", err)
	}

	// The agent's nginx is a fixture that accepts anything; a real nginx must
	// accept the rendered vhosts too, with their real cert paths (#96).
	validateNginxVhosts(t, proxyConfigDir, agentDataDir)

	stalePath := filepath.Join(proxyConfigDir, "nurproxy-stale.sandbox.test.conf.nurproxy-tmp")
	if err := os.WriteFile(stalePath, []byte(agentproxy.ManagedArtifactMarker+"\n# stale sandbox temp\n"), 0o644); err != nil {
		t.Fatalf("inject managed stale temp: %v", err)
	}
	api.post(fmt.Sprintf("/api/v1/domains/%d/config/reset", domain.ID), map[string]any{}, nil)

	// Only the stale-temp repair is under test here; other automatic repairs
	// (e.g. re-materializing the adopted legacy bundle) may be listed too.
	var repairs []recoverymodel.OperationReport
	waitFor(t, 15*time.Second, func() bool {
		if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
			return false
		}
		var all []recoverymodel.OperationReport
		api.get("/api/v1/agents/"+agentID+"/repairs", &all)
		repairs = repairs[:0]
		for _, r := range all {
			if r.Action == recoverymodel.ActionRemoveManagedTemp {
				repairs = append(repairs, r)
			}
		}
		return len(repairs) == 1 && repairs[0].Action == recoverymodel.ActionRemoveManagedTemp &&
			repairs[0].Source == recoverymodel.RequestSourceAutomatic && repairs[0].State == recoverymodel.OperationStateSucceeded
	})
	if repairs[0].SnapshotReference == "" || repairs[0].ValidationOutcome != "valid" {
		t.Fatalf("stale-temp repair omitted snapshot/validation evidence: %#v", repairs[0])
	}
	wantStates := []recoverymodel.OperationState{
		recoverymodel.OperationStateDetected, recoverymodel.OperationStatePlanned,
		recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying,
		recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded,
	}
	if len(repairs[0].Steps) != len(wantStates) {
		t.Fatalf("stale-temp repair steps = %#v, want %v", repairs[0].Steps, wantStates)
	}
	for i, want := range wantStates {
		if repairs[0].Steps[i].State != want {
			t.Fatalf("stale-temp repair step %d = %q, want %q", i, repairs[0].Steps[i].State, want)
		}
	}
	var resolvedDiagnostics []recoverymodel.Diagnostic
	var staleDiagnosticID string
	waitFor(t, 10*time.Second, func() bool {
		api.get("/api/v1/agents/"+agentID+"/diagnostics?include_resolved=true", &resolvedDiagnostics)
		for _, diagnostic := range resolvedDiagnostics {
			if diagnostic.Code == recoverymodel.CodeManagedStaleTemp && diagnostic.ProposedAction == recoverymodel.ActionRemoveManagedTemp {
				staleDiagnosticID = diagnostic.ID
				return true
			}
		}
		return false
	})
	var activeAfterRepair []recoverymodel.Diagnostic
	waitFor(t, 10*time.Second, func() bool {
		api.get("/api/v1/agents/"+agentID+"/diagnostics", &activeAfterRepair)
		for _, diagnostic := range activeAfterRepair {
			if diagnostic.ID == staleDiagnosticID {
				return false
			}
		}
		return true
	})
	resolvedDiagnostics = nil
	api.get("/api/v1/agents/"+agentID+"/diagnostics?include_resolved=true", &resolvedDiagnostics)
	historyRetained := false
	for _, diagnostic := range resolvedDiagnostics {
		if diagnostic.ID == staleDiagnosticID {
			historyRetained = true
			break
		}
	}
	if !historyRetained {
		t.Fatalf("resolved stale-temp diagnostic %q disappeared from history", staleDiagnosticID)
	}

	// Path routes (#89): a domain with an exact and a prefix route to a second
	// server of the same agent converges to active, and its vhost carries the
	// locations in the shape the helper's nginx policy admits. It runs after
	// the stale-temp check, which expects exactly one repair: installing the
	// new domain's certificate brings automatic repairs of its own.
	var apiServer struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/agents/"+agentID+"/servers", map[string]string{
		"name": "api", "address": "10.0.0.6",
	}, &apiServer)
	var routed struct {
		ID int `json:"id"`
	}
	api.post("/api/v1/domains", map[string]any{
		"subdomain": "paths", "zone_id": zone.ID, "server_id": server.ID,
		"port": 2412, "ssl_mode": "central",
		"proxy_config": map[string]any{"routes": []map[string]any{
			{"match": "exact", "path": "/api/world", "server_id": apiServer.ID, "port": 80},
			{"match": "prefix", "path": "/media", "server_id": apiServer.ID, "port": 9000, "strip_prefix": true},
		}},
	}, &routed)
	routedPath := filepath.Join(proxyConfigDir, "nurproxy-paths.sandbox.test.conf")
	var routedStatus, routedError string
	waitFor(t, 90*time.Second, func() bool {
		var d struct {
			Status   string `json:"status"`
			ErrorMsg string `json:"error_msg"`
		}
		api.get(fmt.Sprintf("/api/v1/domains/%d", routed.ID), &d)
		routedStatus, routedError = d.Status, d.ErrorMsg
		content, err := os.ReadFile(routedPath)
		return d.Status == "active" && err == nil &&
			bytes.Contains(content, []byte("    location = /api/world {\n        proxy_pass http://10.0.0.6:80;\n")) &&
			bytes.Contains(content, []byte("    location /media/ {\n        rewrite ^/media/?(.*)$ /$1 break;\n        proxy_pass http://10.0.0.6:9000;\n")) &&
			bytes.Contains(content, []byte("    location / {\n        proxy_pass http://10.0.0.5:2412;\n"))
	})
	if routedStatus != "active" {
		t.Fatalf("domain with path routes never became active (status %q, error %q)", routedStatus, routedError)
	}
	// The route server cannot be deleted while the route uses it.
	if code := api.status(http.MethodDelete, "/api/v1/servers/"+apiServer.ID); code != http.StatusConflict {
		t.Fatalf("deleting a server used by a path route: status %d, want 409", code)
	}

	// Rename the apex domain to www (#151): the new name gets its own record
	// and certificate, the old record (NurProxy-created) is deleted once the new
	// one exists, and the old vhost file leaves the agent.
	var apexBefore struct {
		DNSRecordID string `json:"dns_record_id"`
	}
	api.get(fmt.Sprintf("/api/v1/domains/%d", apex.ID), &apexBefore)
	oldVhost := filepath.Join(proxyConfigDir, "nurproxy-sandbox.test.conf")
	if _, err := os.Stat(oldVhost); err != nil {
		t.Fatalf("apex vhost missing before rename: %v", err)
	}
	api.put(fmt.Sprintf("/api/v1/domains/%d", apex.ID), map[string]any{"subdomain": "www"}, nil)
	newVhost := filepath.Join(proxyConfigDir, "nurproxy-www.sandbox.test.conf")
	var renamedRecord string
	waitFor(t, 30*time.Second, func() bool {
		var d struct {
			Status      string `json:"status"`
			DNSManaged  bool   `json:"dns_managed"`
			DNSRecordID string `json:"dns_record_id"`
		}
		api.get(fmt.Sprintf("/api/v1/domains/%d", apex.ID), &d)
		renamedRecord = d.DNSRecordID
		if d.Status != "active" || !d.DNSManaged || d.DNSRecordID == "" || d.DNSRecordID == apexBefore.DNSRecordID {
			return false
		}
		var h struct {
			Checks map[string]string `json:"checks"`
		}
		mustGetJSON(t, &http.Client{}, base+"/api/v1/health", &h)
		if _, queued := h.Checks["domain_dns_cleanup"]; queued {
			return false
		}
		_, oldErr := os.Stat(oldVhost)
		_, newErr := os.Stat(newVhost)
		return os.IsNotExist(oldErr) && newErr == nil
	})
	var renameAudit struct {
		Entries []struct {
			EntityType string `json:"entity_type"`
			EntityID   string `json:"entity_id"`
			Action     string `json:"action"`
			Source     string `json:"source"`
		} `json:"entries"`
	}
	var sawOldDeleted, sawRenamedIssued, sawOldCertDropped bool
	waitFor(t, 30*time.Second, func() bool {
		renameAudit.Entries = nil
		api.get("/api/v1/audit-log?limit=200", &renameAudit)
		for _, e := range renameAudit.Entries {
			switch {
			case e.Source == "dryrun" && e.Action == "dns_deleted" && e.EntityType == "domain" && e.EntityID == fmt.Sprint(apex.ID):
				sawOldDeleted = true
			case e.Source == "dryrun" && e.Action == "renewed" && e.EntityID == "www.sandbox.test":
				sawRenamedIssued = true
			case e.Action == "deleted" && e.EntityType == "certificate" && e.EntityID == "sandbox.test":
				sawOldCertDropped = true
			}
		}
		return sawOldDeleted && sawRenamedIssued && sawOldCertDropped
	})
	t.Logf("renamed apex to www: record %s -> %s", apexBefore.DNSRecordID, renamedRecord)

	managedPath := filepath.Join(proxyConfigDir, "nurproxy-app.sandbox.test.conf")
	managedBefore, err := os.ReadFile(managedPath)
	if err != nil {
		t.Fatalf("read managed fixture before unknown failure: %v", err)
	}
	failValidation := filepath.Join(filepath.Dir(bin.proxy), "fail-validation")
	if err := os.WriteFile(failValidation, []byte("enabled\n"), 0o600); err != nil {
		t.Fatalf("enable sandbox validation failure: %v", err)
	}
	api.put(fmt.Sprintf("/api/v1/domains/%d/config", domain.ID), map[string]any{
		"config": "server { listen 8081; server_name app.sandbox.test; }\n",
	}, nil)

	var activeDiagnostics []recoverymodel.Diagnostic
	waitFor(t, 15*time.Second, func() bool {
		api.get("/api/v1/agents/"+agentID+"/diagnostics", &activeDiagnostics)
		for _, diagnostic := range activeDiagnostics {
			if diagnostic.Code == recoverymodel.CodeUnknownProxyError {
				return true
			}
		}
		return false
	})
	var unknown *recoverymodel.Diagnostic
	for i := range activeDiagnostics {
		if activeDiagnostics[i].Code == recoverymodel.CodeUnknownProxyError {
			unknown = &activeDiagnostics[i]
			break
		}
	}
	if unknown == nil || unknown.Ownership != recoverymodel.OwnershipUnknown || unknown.ProposedAction != "" || unknown.AutoRepairEligible || unknown.HardChange {
		t.Fatalf("unknown validation error was not diagnosis-only: %#v", unknown)
	}
	// The rename above runs automatic repairs of its own (orphan vhost prune,
	// cert bundle rematerialize), possibly still landing now; only a repair for
	// the unknown failure's diagnostic is wrong.
	api.get("/api/v1/agents/"+agentID+"/repairs", &repairs)
	for _, repair := range repairs {
		if repair.DiagnosticID == unknown.ID {
			t.Fatalf("unknown validation error created a repair operation: %#v", repair)
		}
	}
	if got, err := os.ReadFile(operatorPath); err != nil || !bytes.Equal(got, operatorBytes) {
		t.Fatalf("unknown validation failure changed operator config: got=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(managedPath); err != nil || !bytes.Equal(got, managedBefore) {
		t.Fatalf("unknown validation failure did not roll back managed config: err=%v", err)
	}

	// --- Cloudflare proxy state (#126) -----------------------------------------
	// The apex was created with proxied=true, so its simulated CNAME must have
	// been created proxied. Turning the setting off and running the synchronous
	// DNS takeover must flip the existing record to DNS only, audited as such.
	auditFor := func(entityID int, action string) []string {
		var log struct {
			Entries []struct {
				EntityType string `json:"entity_type"`
				EntityID   string `json:"entity_id"`
				Action     string `json:"action"`
				Details    string `json:"details"`
			} `json:"entries"`
		}
		api.get("/api/v1/audit-log?limit=500", &log)
		var out []string
		for _, e := range log.Entries {
			if e.EntityType == "domain" && e.EntityID == fmt.Sprint(entityID) && e.Action == action {
				out = append(out, e.Details)
			}
		}
		return out
	}
	// Two creations: the apex itself and, after the rename above, www.
	created := auditFor(apex.ID, "dns_created")
	if len(created) != 2 {
		t.Fatalf("apex domain dns_created audit = %q, want the apex and the renamed www record", created)
	}
	for _, c := range created {
		if !strings.Contains(c, "(proxied)") {
			t.Fatalf("apex domain CNAME was not created proxied; dns_created audit = %q", created)
		}
	}
	api.put(fmt.Sprintf("/api/v1/domains/%d", apex.ID), map[string]any{"proxied": false}, nil)
	api.post(fmt.Sprintf("/api/v1/domains/%d/dns/takeover", apex.ID), map[string]any{}, nil)
	// A background reconcile may enforce the setting before the takeover does,
	// so only require that the flip happened, not who did it.
	flipped := auditFor(apex.ID, "dns_proxied_updated")
	if len(flipped) == 0 {
		t.Fatal("explicit proxied=false was not enforced on the existing record: no dns_proxied_updated audit entry")
	}
	for _, f := range flipped {
		if !strings.Contains(f, "from proxied to DNS only") {
			t.Fatalf("unexpected proxy change: %q", f)
		}
	}
	// A second takeover reports the record's live state in its audit text.
	api.post(fmt.Sprintf("/api/v1/domains/%d/dns/takeover", apex.ID), map[string]any{}, nil)
	sawDNSOnly := false
	for _, d := range auditFor(apex.ID, "dns_takeover") {
		if strings.Contains(d, "(DNS only)") {
			sawDNSOnly = true
		}
	}
	if !sawDNSOnly {
		t.Fatalf("apex record is still proxied after the flip; dns_takeover audit = %q", auditFor(apex.ID, "dns_takeover"))
	}
	var apexAfter struct {
		Proxied *bool `json:"proxied"`
	}
	api.get(fmt.Sprintf("/api/v1/domains/%d", apex.ID), &apexAfter)
	if apexAfter.Proxied == nil || *apexAfter.Proxied {
		t.Fatalf("apex proxied setting = %v, want false", apexAfter.Proxied)
	}

	// --- DNS takeover preview (#128) -------------------------------------------
	// The dry run reports the plan and changes nothing: the apex's record is
	// already the desired CNAME, so it would only be taken over, with no deletes.
	takeoversBefore := len(auditFor(apex.ID, "dns_takeover"))
	var preview struct {
		DryRun bool `json:"dry_run"`
		Plan   struct {
			Action string            `json:"action"`
			Delete []json.RawMessage `json:"delete"`
		} `json:"plan"`
	}
	api.post(fmt.Sprintf("/api/v1/domains/%d/dns/takeover?dry_run=true", apex.ID), map[string]any{}, &preview)
	if !preview.DryRun || preview.Plan.Action != "adopt" || len(preview.Plan.Delete) != 0 {
		t.Fatalf("takeover preview = %+v, want a dry-run adopt without deletes", preview)
	}
	if n := len(auditFor(apex.ID, "dns_takeover")); n != takeoversBefore {
		t.Fatalf("takeover preview wrote %d dns_takeover audit entries", n-takeoversBefore)
	}
	var apexDNS struct {
		DNSManaged bool   `json:"dns_managed"`
		DNSError   string `json:"dns_error"`
	}
	api.get(fmt.Sprintf("/api/v1/domains/%d", apex.ID), &apexDNS)
	if !apexDNS.DNSManaged || apexDNS.DNSError != "" {
		t.Fatalf("apex after takeover: dns_managed=%v dns_error=%q, want managed without error", apexDNS.DNSManaged, apexDNS.DNSError)
	}

	// --- opt-in cascade delete of the agent (#104) ------------------------------
	// The foreign keys are ON DELETE RESTRICT, so the agent, its servers and its
	// domains only disappear once the reconciler has torn the domains down and
	// finalized the deferred parent delete, children before parents. The agent
	// must be able to apply the route removals, so the injected validation
	// failure from above is switched off first.
	if err := os.Remove(failValidation); err != nil {
		t.Fatalf("disable sandbox validation failure: %v", err)
	}
	// Teardown and finalize can take two reconciler cycles; shorten the
	// interval so they fit the wait (it applies once the running timer fires).
	api.put("/api/v1/settings/reconciler_interval", map[string]string{"value": "5"}, nil)
	api.do(http.MethodDelete, "/api/v1/agents/"+agentID+"?cascade=true", nil, nil)
	waitFor(t, 90*time.Second, func() bool {
		var doms []struct {
			ID int `json:"id"`
		}
		api.get("/api/v1/domains", &doms)
		// Only the Caddy agent's domain may remain: it belongs to edge2.
		for _, d := range doms {
			if d.ID != caddyDomain.ID {
				return false
			}
		}
		var agents []struct {
			ID string `json:"id"`
		}
		api.get("/api/v1/agents", &agents)
		for _, a := range agents {
			if a.ID == agentID {
				return false
			}
		}
		return true
	})
	var cascadeAudit struct {
		Entries []struct {
			EntityType string `json:"entity_type"`
			EntityID   string `json:"entity_id"`
			Action     string `json:"action"`
			Details    string `json:"details"`
		} `json:"entries"`
	}
	api.get("/api/v1/audit-log?limit=1000", &cascadeAudit)
	sawFinalized := false
	var agentEntries []string
	for _, e := range cascadeAudit.Entries {
		if e.EntityType == "agent" && e.EntityID == agentID {
			agentEntries = append(agentEntries, e.Action+": "+e.Details)
		}
		if e.EntityType == "agent" && e.EntityID == agentID && e.Action == "delete" && strings.Contains(e.Details, "cascade finalized") {
			sawFinalized = true
		}
	}
	if !sawFinalized {
		t.Fatalf("agent cascade delete was not finalized by the reconciler; agent audit: %q", agentEntries)
	}

	t.Logf("sandbox converged: domain active, DNS record %s, audit tagged dryrun; stale managed temp auto-healed and an unclassified validation failure remained diagnosis-only (validator/reload are hermetic fixtures, not native nginx proof)", dom.DNSRecordID)
}

// assertDiscoveryImport drives server discovery (#25) through the dry stack:
// a Proxmox source with dummy credentials (the connection test is simulated),
// a run that returns the dry-run fixture, an import of two machines (one with
// a detected address, one with an operator-supplied address), and a re-run
// plus re-import that must not duplicate anything.
func assertDiscoveryImport(t *testing.T, api *apiClient, agentID string) {
	t.Helper()
	var src struct {
		ID string `json:"id"`
	}
	api.post("/api/v1/discovery/sources", map[string]any{
		"type": "proxmox", "name": "pve-dry",
		"config": map[string]any{"url": "https://pve.sandbox.test:8006", "token_id": "nurproxy@pve!dry", "token_secret": "dummy-dry-secret"},
	}, &src)
	type candidate struct {
		ExternalID       string `json:"external_id"`
		SuggestedAddress string `json:"suggested_address"`
		ServerID         string `json:"server_id"`
	}
	type view struct {
		Candidates []candidate `json:"candidates"`
		Warnings   []string    `json:"warnings"`
		Missing    []any       `json:"missing"`
	}
	var v view
	api.post("/api/v1/discovery/sources/"+src.ID+"/run", nil, &v)
	if len(v.Candidates) != 4 || len(v.Warnings) != 1 {
		t.Fatalf("dry discovery run = %+v, want the 4-machine fixture with one offline-node warning", v)
	}
	var imp struct {
		Created []struct {
			Address    string `json:"address"`
			ExternalID string `json:"external_id"`
		} `json:"created"`
		Skipped []any `json:"skipped"`
	}
	items := []map[string]string{
		{"external_id": "pve/pve1/qemu/101"},
		{"external_id": "pve/pve1/qemu/103", "address": "192.168.10.23"},
	}
	api.post("/api/v1/agents/"+agentID+"/servers/import", map[string]any{"source_id": src.ID, "items": items}, &imp)
	if len(imp.Created) != 2 || imp.Created[0].Address != "192.168.10.21" || imp.Created[1].Address != "192.168.10.23" {
		t.Fatalf("discovery import = %+v", imp)
	}
	api.post("/api/v1/discovery/sources/"+src.ID+"/run", nil, &v)
	imported := 0
	for _, c := range v.Candidates {
		if c.ServerID != "" {
			imported++
		}
	}
	if imported != 2 || len(v.Missing) != 0 {
		t.Fatalf("re-run after import = %+v, want 2 imported and none missing", v)
	}
	imp.Created, imp.Skipped = nil, nil
	api.post("/api/v1/agents/"+agentID+"/servers/import", map[string]any{"source_id": src.ID, "items": items}, &imp)
	if len(imp.Created) != 0 || len(imp.Skipped) != 2 {
		t.Fatalf("re-import = %+v, want both skipped", imp)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type binaries struct{ orch, agent, proxy, upstream string }

// sandboxStack is a running dry-run orchestrator with an API key and a seeded
// provider (dummy token) and zone (sandbox.test).
type sandboxStack struct {
	base string
	api  *apiClient
	zone struct {
		ID string `json:"id"`
	}
}

// startDryOrchestrator boots a dry-run orchestrator, bootstraps auth and an API
// key, and seeds a provider and the sandbox.test zone. The process is stopped
// via t.Cleanup.
func startDryOrchestrator(t *testing.T, bin binaries, dataRoot string) *sandboxStack {
	t.Helper()
	orchPort := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", orchPort)
	orch := startProcess(t, bin.orch, []string{
		"-port", fmt.Sprintf("%d", orchPort),
		"-data-dir", filepath.Join(dataRoot, "orch"),
	}, "NP_DRY_RUN=true")
	t.Cleanup(orch.stop)

	// A fresh-DB cold boot must run every migration and a single WAL fsync
	// before the API serves /health; on slow/loaded CI disks that can take tens
	// of seconds, so allow a generous readiness window (the convergence wait
	// uses 75s for a full reconciler cycle).
	waitFor(t, 60*time.Second, func() bool { return httpOK(base + "/api/v1/health") })

	// Health must advertise the sandbox so the dashboard banner lights up.
	var health map[string]any
	mustGetJSON(t, &http.Client{}, base+"/api/v1/health", &health)
	if health["dry_run"] != true || health["dns_dry_run"] != true || health["acme_dry_run"] != true || health["discovery_dry_run"] != true {
		t.Fatalf("health did not report dry-run: %v", health)
	}

	// --- bootstrap auth + API key (cookie session) ---------------------------
	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar}
	postJSON(t, cli, base+"/api/v1/auth/setup", map[string]string{"password": adminPassword}, nil)
	var keyResp struct {
		APIKey string `json:"api_key"`
	}
	postJSON(t, cli, base+"/api/v1/api-key", map[string]string{}, &keyResp)
	if keyResp.APIKey == "" {
		t.Fatal("no API key returned")
	}
	s := &sandboxStack{base: base, api: &apiClient{base: base, key: keyResp.APIKey, t: t}}

	// --- provider (dummy creds) + zone ---------------------------------------
	var prov struct {
		ID string `json:"id"`
	}
	s.api.post("/api/v1/providers", map[string]any{
		"type": "cloudflare", "name": "CF-dry",
		"config": map[string]string{"api_token": "dummy-dry-token"},
	}, &prov)
	if prov.ID == "" {
		t.Fatal("provider not created (dry-run validation should accept a dummy token)")
	}
	s.api.post("/api/v1/zones", map[string]string{"provider_id": prov.ID, "name": "sandbox.test"}, &s.zone)
	return s
}

// adoptAgent waits for the agent with fqdn to register and adopts it onto the
// stack's zone, returning its ID.
func (s *sandboxStack) adoptAgent(t *testing.T, fqdn, name string) string {
	t.Helper()
	var agentID string
	waitFor(t, 15*time.Second, func() bool {
		var agents []struct {
			ID   string `json:"id"`
			FQDN string `json:"fqdn"`
		}
		s.api.get("/api/v1/agents", &agents)
		for _, a := range agents {
			if a.FQDN == fqdn {
				agentID = a.ID
				return true
			}
		}
		return false
	})
	s.api.put("/api/v1/agents/"+agentID+"/adopt", map[string]any{
		"name": name, "zone_ids": []string{s.zone.ID},
	}, nil)
	return agentID
}

// waitDomainActive waits one reconciler cycle plus margin for the domain to be
// active with a managed DNS record.
func (s *sandboxStack) waitDomainActive(t *testing.T, id int) {
	t.Helper()
	var last string
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) {
		var d struct {
			Status      string `json:"status"`
			ErrorMsg    string `json:"error_msg"`
			DNSManaged  bool   `json:"dns_managed"`
			DNSRecordID string `json:"dns_record_id"`
		}
		s.api.get(fmt.Sprintf("/api/v1/domains/%d", id), &d)
		if d.Status == "active" && d.DNSManaged && d.DNSRecordID != "" {
			return
		}
		last = d.Status + " " + d.ErrorMsg
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("domain %d never became active (last: %s)", id, last)
}

func repoRoot(t *testing.T) string {
	// test/sandbox -> repo root is two levels up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// buildBinaries compiles the headless orchestrator and the agent into a temp
// dir, so the test is self-contained (no reliance on pre-built artifacts) and
// runs with no embedded dashboard / npm dependency.
func buildBinaries(t *testing.T, root string) binaries {
	t.Helper()
	out := t.TempDir()
	b := binaries{
		orch:     filepath.Join(out, "nurproxy-orch"),
		agent:    filepath.Join(out, "nurproxy-agent"),
		proxy:    filepath.Join(out, "nginx"),
		upstream: filepath.Join(out, "fakeupstream"),
	}
	build := func(bin, tags, pkg string) {
		args := []string{"build"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		args = append(args, "-o", bin, pkg)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", pkg, err, out)
		}
	}
	build(b.orch, "headless", "./cmd/nurproxy")
	build(b.agent, "", "./cmd/nurproxy-agent")
	build(b.proxy, "sandbox", "./test/sandbox/proxyfixture")
	build(b.upstream, "sandbox", "./test/sandbox/fakeupstream")
	return b
}

type process struct {
	cmd     *exec.Cmd
	t       *testing.T
	logPath string
	stopped bool
}

func startProcess(t *testing.T, bin string, args []string, env ...string) *process {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ()
	for _, value := range env {
		if value != "" {
			cmd.Env = append(cmd.Env, value)
		}
	}
	p := &process{cmd: cmd, t: t}
	logf, err := os.Create(filepath.Join(t.TempDir(), filepath.Base(bin)+".log"))
	if err == nil {
		cmd.Stdout, cmd.Stderr = logf, logf
		p.logPath = logf.Name()
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", bin, err)
	}
	return p
}

func (p *process) stop() {
	if p.stopped {
		return
	}
	p.stopped = true
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
}

// terminate asks the process to shut down with SIGTERM, so it can stop its own
// children (the agent stops its Caddy), and kills it after a grace period.
func (p *process) terminate(grace time.Duration) {
	if p.stopped || p.cmd.Process == nil {
		return
	}
	p.stopped = true
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = p.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		_ = p.cmd.Process.Kill()
		<-done
	}
}

// logTail returns the last n bytes of the process log, for failure messages.
func (p *process) logTail(n int) string {
	if p.logPath == "" {
		return ""
	}
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		return ""
	}
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func httpOK(url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func mustGetJSON(t *testing.T, cli *http.Client, url string, out any) {
	t.Helper()
	resp, err := cli.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

func postJSON(t *testing.T, cli *http.Client, url string, body, out any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", url, err)
	}
	resp, err := cli.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("POST %s: status %d", url, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
}

// apiClient is a tiny Bearer-authenticated REST helper for the seeding calls.
type apiClient struct {
	base string
	key  string
	t    *testing.T
}

func (c *apiClient) do(method, path string, body, out any) {
	c.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal %s %s body: %v", method, path, err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		c.t.Fatalf("%s %s: status %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			c.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
}

func (c *apiClient) get(path string, out any)     { c.do(http.MethodGet, path, nil, out) }
func (c *apiClient) post(path string, b, out any) { c.do(http.MethodPost, path, b, out) }
func (c *apiClient) put(path string, b, out any)  { c.do(http.MethodPut, path, b, out) }
func (c *apiClient) del(path string)              { c.do(http.MethodDelete, path, nil, nil) }

// status sends a bodyless request and returns the response status, for
// calls that are expected to fail.
func (c *apiClient) status(method, path string) int {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, nil)
	if err != nil {
		c.t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// sandboxServerCert mints a self-signed server certificate for host, standing
// in for an operator's existing bundle.
func sandboxServerCert(t *testing.T, host string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// readFileNamed returns the content of the first file named name below root,
// or "" when there is none (yet).
func readFileNamed(root, name string) string {
	found := ""
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != name {
			return nil
		}
		if got, rErr := os.ReadFile(path); rErr == nil {
			found = string(got)
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// findFileWithContent returns the path of a file named name below root whose
// content equals want, or "" when there is none (yet).
func findFileWithContent(root, name, want string) string {
	found := ""
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != name {
			return nil
		}
		if got, rErr := os.ReadFile(path); rErr == nil && string(got) == want {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
