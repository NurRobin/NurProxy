package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/discovery"
)

const (
	testTokenID     = "nurproxy@pve!discovery"
	testTokenSecret = "5f0c3a52-6c1e-4b8b-9d6e-000000000001"
)

// fakePVE serves the subset of the Proxmox VE API2 JSON that discovery reads.
// Response shapes follow the PVE API viewer: every answer is wrapped in
// {"data": ...}, the guest-agent answer nests the agent's reply one level
// deeper ({"data":{"result":[...]}}), the LXC list sends vmid as a string, and
// errors carry PVE's message in the HTTP reason phrase.
type fakePVE struct {
	mu     sync.Mutex
	routes map[string]string // path -> JSON body (already wrapped)
	errs   map[string]fakeErr
	auths  []string
}

type fakeErr struct {
	status int
	reason string
}

func (f *fakePVE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	body, ok := f.routes[r.URL.Path]
	e, isErr := f.errs[r.URL.Path]
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "PVEAPIToken="+testTokenID+"="+testTokenSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"data":null}`))
		return
	}
	if isErr {
		// PVE puts its message in the HTTP reason phrase ("500 QEMU guest
		// agent is not running"), which net/http's ResponseWriter cannot set,
		// so the raw response is written on the hijacked connection.
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		body := `{"data":null}`
		fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", e.status, e.reason, len(body), body)
		_ = buf.Flush()
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

const p = "/api2/json/"

func clusterFixture() *fakePVE {
	return &fakePVE{
		routes: map[string]string{
			p + "version": `{"data":{"version":"8.2.4","release":"8.2","repoid":"faa83925c9641325"}}`,
			// The PVEAuditor role on /, as a privilege-separated token sees it.
			p + "access/permissions": `{"data":{"/":{"Sys.Audit":1,"VM.Audit":1,"Datastore.Audit":1},"/vms":{"VM.Audit":1}}}`,
			p + "nodes": `{"data":[
				{"node":"pve1","status":"online","type":"node","id":"node/pve1","maxcpu":8},
				{"node":"pve2","status":"offline","type":"node","id":"node/pve2"}]}`,
			p + "nodes/pve1/qemu": `{"data":[
				{"vmid":101,"name":"web-01","status":"running","maxmem":4294967296},
				{"vmid":102,"name":"db-01","status":"running"},
				{"vmid":103,"name":"win-desktop","status":"stopped"},
				{"vmid":9000,"name":"ubuntu-template","status":"stopped","template":1}]}`,
			p + "nodes/pve1/lxc": `{"data":[
				{"vmid":"200","name":"jellyfin","status":"running","type":"lxc"},
				{"vmid":"201","name":"pihole","status":"stopped","type":"lxc"}]}`,
			// 101: guest agent with docker0 + loopback + link-local next to the LAN address.
			p + "nodes/pve1/qemu/101/agent/network-get-interfaces": `{"data":{"result":[
				{"name":"lo","hardware-address":"00:00:00:00:00:00","ip-addresses":[
					{"ip-address-type":"ipv4","ip-address":"127.0.0.1","prefix":8},
					{"ip-address-type":"ipv6","ip-address":"::1","prefix":128}]},
				{"name":"ens18","hardware-address":"bc:24:11:aa:bb:01","ip-addresses":[
					{"ip-address-type":"ipv6","ip-address":"fe80::be24:11ff:feaa:bb01","prefix":64},
					{"ip-address-type":"ipv4","ip-address":"192.168.10.21","prefix":24}],
				 "statistics":{"rx-bytes":1,"tx-bytes":2}},
				{"name":"docker0","hardware-address":"02:42:00:00:00:01","ip-addresses":[
					{"ip-address-type":"ipv4","ip-address":"172.17.0.1","prefix":16}]}]}}`,
			p + "nodes/pve1/qemu/102/config": `{"data":{"name":"db-01","ipconfig0":"ip=192.168.10.22/24,gw=192.168.10.1","ipconfig1":"ip=dhcp,ip6=fd00:10::22/64","net0":"virtio=BC:24:11:AA:BB:02,bridge=vmbr0","digest":"x"}}`,
			p + "nodes/pve1/qemu/103/config": `{"data":{"name":"win-desktop","ostype":"win11","net0":"virtio=BC:24:11:AA:BB:03,bridge=vmbr0"}}`,
			p + "nodes/pve1/lxc/200/interfaces": `{"data":[
				{"name":"lo","hwaddr":"00:00:00:00:00:00","inet":"127.0.0.1/8","inet6":"::1/128"},
				{"name":"eth0","hwaddr":"bc:24:11:cc:00:01","inet":"192.168.10.30/24","inet6":"fe80::be24:11ff:fecc:1/64"}]}`,
			p + "nodes/pve1/lxc/201/config": `{"data":{"hostname":"pihole","net0":"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:CC:00:02,ip=192.168.10.31/24,gw=192.168.10.1,type=veth"}}`,
		},
		errs: map[string]fakeErr{
			p + "nodes/pve1/qemu/102/agent/network-get-interfaces": {500, "QEMU guest agent is not running"},
		},
	}
}

func configFor(t *testing.T, srv *httptest.Server, extra map[string]any) json.RawMessage {
	t.Helper()
	cfg := map[string]any{
		"url":          srv.URL,
		"token_id":     testTokenID,
		"token_secret": testTokenSecret,
		"verify_tls":   false,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDiscoverCluster(t *testing.T) {
	fake := clusterFixture()
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()

	res, err := (&Discoverer{}).Discover(context.Background(), configFor(t, srv, nil))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	byID := map[string]discovery.Candidate{}
	for _, c := range res.Candidates {
		byID[c.ExternalID] = c
	}
	if len(byID) != 5 {
		t.Fatalf("got %d candidates, want 5 (template skipped, offline node skipped): %+v", len(byID), res.Candidates)
	}
	tests := []struct {
		id, name, suggested, source, kind string
	}{
		{"pve/pve1/qemu/101", "web-01", "192.168.10.21", SourceGuestAgent, "qemu"},
		{"pve/pve1/qemu/102", "db-01", "192.168.10.22", SourceCloudInit, "qemu"},
		{"pve/pve1/qemu/103", "win-desktop", "", "", "qemu"},
		{"pve/pve1/lxc/200", "jellyfin", "192.168.10.30", SourceLXCInterfaces, "lxc"},
		{"pve/pve1/lxc/201", "pihole", "192.168.10.31", SourceLXCConfig, "lxc"},
	}
	for _, tt := range tests {
		c, ok := byID[tt.id]
		if !ok {
			t.Errorf("%s missing", tt.id)
			continue
		}
		if c.Name != tt.name || c.SuggestedAddress != tt.suggested || c.AddressSource != tt.source || c.Kind != tt.kind || c.Location != "pve1" {
			t.Errorf("%s = %+v, want name %q suggested %q source %q kind %q", tt.id, c, tt.name, tt.suggested, tt.source, tt.kind)
		}
	}

	// Every address stays visible, best first; non-backend ones are marked.
	web := byID["pve/pve1/qemu/101"]
	kinds := map[string]string{}
	for _, a := range web.Addresses {
		kinds[a.IP] = a.Kind
	}
	want := map[string]string{
		"192.168.10.21":             discovery.KindPrivate,
		"172.17.0.1":                discovery.KindContainerBridge,
		"127.0.0.1":                 discovery.KindLoopback,
		"::1":                       discovery.KindLoopback,
		"fe80::be24:11ff:feaa:bb01": discovery.KindLinkLocal,
	}
	for ip, k := range want {
		if kinds[ip] != k {
			t.Errorf("web-01 address %s kind = %q, want %q (all: %+v)", ip, kinds[ip], k, web.Addresses)
		}
	}
	if web.Addresses[0].IP != "192.168.10.21" {
		t.Errorf("web-01 first address = %s, want the LAN address first", web.Addresses[0].IP)
	}
	// db-01's second ipconfig adds an IPv6 ULA; dhcp is skipped.
	if len(byID["pve/pve1/qemu/102"].Addresses) != 2 {
		t.Errorf("db-01 addresses = %+v, want the ipconfig0 IPv4 and the ipconfig1 ULA", byID["pve/pve1/qemu/102"].Addresses)
	}

	// The offline node is a warning and marks its prefix incomplete; the
	// "no guest agent" reply for db-01 is expected and is not a warning.
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "pve2") {
		t.Errorf("warnings = %q, want only the offline-node warning", res.Warnings)
	}
	if res.Covers("pve/pve2/qemu/300") || !res.Covers("pve/pve1/qemu/300") {
		t.Errorf("incomplete = %q, want pve2 excluded and pve1 covered", res.Incomplete)
	}
}

func TestDiscoverNodeListingFailureIsPartial(t *testing.T) {
	fake := clusterFixture()
	delete(fake.routes, p+"nodes/pve1/lxc")
	fake.errs[p+"nodes/pve1/lxc"] = fakeErr{595, "No route to host"}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()

	res, err := (&Discoverer{}).Discover(context.Background(), configFor(t, srv, nil))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Covers("pve/pve1/lxc/200") {
		t.Error("lxc on pve1 should be incomplete after its listing failed")
	}
	if !res.Covers("pve/pve1/qemu/101") {
		t.Error("qemu on pve1 was listed and should be covered")
	}
	for _, c := range res.Candidates {
		if c.Kind == "lxc" {
			t.Errorf("unexpected lxc candidate %s", c.ExternalID)
		}
	}
}

func TestAuthHeaderAndSecretNotInErrors(t *testing.T) {
	fake := clusterFixture()
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()

	bad := configFor(t, srv, map[string]any{"token_secret": "wrong-secret-value"})
	err := (&Discoverer{}).Test(context.Background(), bad)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("Test with a wrong secret = %v, want a 401 error", err)
	}
	if strings.Contains(err.Error(), "wrong-secret-value") {
		t.Fatalf("error leaks the secret: %v", err)
	}
	if err := (&Discoverer{}).Test(context.Background(), configFor(t, srv, nil)); err != nil {
		t.Fatalf("Test with the right token: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.auths[len(fake.auths)-1] != "PVEAPIToken="+testTokenID+"="+testTokenSecret {
		t.Fatalf("Authorization header = %q", fake.auths[len(fake.auths)-1])
	}
}

func TestTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(clusterFixture())
	defer srv.Close()
	leaf := srv.Certificate()
	sum := sha256.Sum256(leaf.Raw)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	tests := []struct {
		name    string
		extra   map[string]any
		wantErr string
	}{
		{"verify against system roots fails for self-signed", map[string]any{"verify_tls": true}, "certificate"},
		{"verify with the CA supplied", map[string]any{"verify_tls": true, "ca_pem": caPEM}, ""},
		{"pinned fingerprint matches", map[string]any{"verify_tls": true, "fingerprint": formatFingerprint(sum[:])}, ""},
		{"pinned fingerprint mismatch", map[string]any{"fingerprint": strings.Repeat("AB:", 31) + "AB"}, "does not match"},
		{"verification off", map[string]any{"verify_tls": false}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&Discoverer{}).Test(context.Background(), configFor(t, srv, tt.extra))
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr bool
	}{
		{"valid", `{"url":"pve.lan","token_id":"root@pam!np","token_secret":"abc"}`, false},
		{"missing url", `{"token_id":"root@pam!np","token_secret":"abc"}`, true},
		{"token id without realm", `{"url":"pve.lan","token_id":"root!np","token_secret":"abc"}`, true},
		{"token id without name", `{"url":"pve.lan","token_id":"root@pam","token_secret":"abc"}`, true},
		{"missing secret", `{"url":"pve.lan","token_id":"root@pam!np"}`, true},
		{"bad scheme", `{"url":"ftp://pve.lan","token_id":"root@pam!np","token_secret":"abc"}`, true},
		{"plain http sends the token in clear text", `{"url":"http://pve.lan:8006","token_id":"root@pam!np","token_secret":"abc"}`, true},
		{"user info in url", `{"url":"https://root:pw@pve.lan:8006","token_id":"root@pam!np","token_secret":"abc"}`, true},
		{"bad fingerprint", `{"url":"pve.lan","token_id":"root@pam!np","token_secret":"abc","fingerprint":"zz"}`, true},
		{"bad ca", `{"url":"pve.lan","token_id":"root@pam!np","token_secret":"abc","ca_pem":"nope"}`, true},
		{"secret with newline", `{"url":"pve.lan","token_id":"root@pam!np","token_secret":"a\nb"}`, true},
		{"key in other case", `{"url":"pve.lan","token_id":"root@pam!np","token_secret":"abc","Fingerprint":"AA"}`, true},
		{"duplicate url in other case", `{"url":"pve.lan","URL":"evil.example","token_id":"root@pam!np","token_secret":"abc"}`, true},
		{"unknown key", `{"url":"pve.lan","token_id":"root@pam!np","token_secret":"abc","proxy":"x"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&Discoverer{}).ValidateConfig(json.RawMessage(tt.cfg))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBaseURLAndSummary(t *testing.T) {
	tests := []struct{ in, want string }{
		{"pve.lan", "https://pve.lan:8006"},
		{"https://pve.lan:8006/", "https://pve.lan:8006"},
		{"https://pve.lan/api2/json", "https://pve.lan:8006"},
		{"https://10.0.0.2:443", "https://10.0.0.2:443"},
		{"[fd00::2]", "https://[fd00::2]:8006"},
	}
	for _, tt := range tests {
		u, err := (&Config{URL: tt.in}).baseURL()
		if err != nil || u.String() != tt.want {
			t.Errorf("baseURL(%q) = %v, %v; want %q", tt.in, u, err, tt.want)
		}
	}
	s := (&Discoverer{}).Summary(json.RawMessage(`{"url":"pve.lan","token_id":"root@pam!np","token_secret":"topsecret"}`))
	if strings.Contains(s, "topsecret") || s != "https://pve.lan:8006 as root@pam!np" {
		t.Errorf("Summary = %q", s)
	}
}

func TestIdentityKey(t *testing.T) {
	d := &Discoverer{}
	if !discovery.SameMachine(d, "pve/pve1/qemu/101", "pve/pve2/qemu/101") {
		t.Error("a VM migrated between nodes should be the same machine")
	}
	if discovery.SameMachine(d, "pve/pve1/qemu/101", "pve/pve1/lxc/101") {
		t.Error("qemu and lxc with the same vmid number are different machines")
	}
}

func TestVMAuditScope(t *testing.T) {
	tests := []struct {
		name        string
		perms       string
		testErr     string
		discoverErr string
		incomplete  bool
	}{
		{"auditor on /", `{"data":{"/":{"Sys.Audit":1,"VM.Audit":1}}}`, "", "", false},
		{"VM.Audit on /vms", `{"data":{"/":{"Sys.Audit":1},"/vms":{"VM.Audit":1}}}`, "", "", false},
		{"only Sys.Audit", `{"data":{"/":{"Sys.Audit":1}}}`, "VM.Audit", "VM.Audit", false},
		{"pool only", `{"data":{"/":{"Sys.Audit":1},"/pool/web":{"VM.Audit":1}}}`, "", "", true},
		{"single guest only", `{"data":{"/":{"Sys.Audit":1},"/vms/101":{"VM.Audit":1}}}`, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := clusterFixture()
			fake.routes[p+"access/permissions"] = tt.perms
			srv := httptest.NewTLSServer(fake)
			defer srv.Close()
			cfg := configFor(t, srv, nil)

			err := (&Discoverer{}).Test(context.Background(), cfg)
			if (tt.testErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.testErr)) {
				t.Fatalf("Test = %v, want error containing %q", err, tt.testErr)
			}
			res, err := (&Discoverer{}).Discover(context.Background(), cfg)
			if tt.discoverErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.discoverErr) {
					t.Fatalf("Discover = %v, want error containing %q", err, tt.discoverErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if got := !res.Covers("pve/pve1/qemu/101"); got != tt.incomplete {
				t.Fatalf("incomplete = %v (%q, warnings %q), want %v", got, res.Incomplete, res.Warnings, tt.incomplete)
			}
		})
	}
}

func TestPermissionsUnreadableMakesRunIncomplete(t *testing.T) {
	fake := clusterFixture()
	delete(fake.routes, p+"access/permissions")
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	res, err := (&Discoverer{}).Discover(context.Background(), configFor(t, srv, nil))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Covers("pve/pve1/qemu/101") || len(res.Candidates) != 5 {
		t.Fatalf("result = %d candidates, incomplete %q; want all guests and nothing covered", len(res.Candidates), res.Incomplete)
	}
}

// TestRedirectNotFollowed keeps the Authorization header from being carried
// to the target of a redirect.
func TestRedirectNotFollowed(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirector.Close()

	err := (&Discoverer{}).Test(context.Background(), configFor(t, redirector, nil))
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("Test against a redirect = %v, want an HTTP 302 error", err)
	}
	if leaked.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

// TestRunsLeaveNoConnections checks that repeated runs do not pile up
// connection goroutines.
func TestRunsLeaveNoConnections(t *testing.T) {
	srv := httptest.NewTLSServer(clusterFixture())
	defer srv.Close()
	cfg := configFor(t, srv, nil)
	d := &Discoverer{}
	if _, err := d.Discover(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	settle := func() int {
		n := runtime.NumGoroutine()
		for i := 0; i < 50; i++ {
			time.Sleep(10 * time.Millisecond)
			if m := runtime.NumGoroutine(); m >= n {
				break
			} else {
				n = m
			}
		}
		return n
	}
	before := settle()
	for i := 0; i < 20; i++ {
		if _, err := d.Discover(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if err := d.Test(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	if after := settle(); after > before+5 {
		t.Fatalf("goroutines grew from %d to %d over 20 runs", before, after)
	}
}
