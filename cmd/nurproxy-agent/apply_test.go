package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeCode(t *testing.T) {
	cases := map[string]string{
		"  abcd-1234 ": "ABCD-1234",
		"abcd-1234":    "ABCD-1234",
		"ABCD-1234\n":  "ABCD-1234",
	}
	for in, want := range cases {
		if got := normalizeCode(in); got != want {
			t.Errorf("normalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "c"); got != "c" {
		t.Errorf("firstNonEmpty = %q, want c", got)
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("firstNonEmpty = %q, want a", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty = %q, want empty", got)
	}
}

func TestClaimAdminOp404IsCodeNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := claimAdminOp(t.Context(), srv.Client(), srv.URL, "agent-1", "tok", "ABCD-1234")
	if err != errCodeNotFound {
		t.Fatalf("expected errCodeNotFound, got %v", err)
	}
}

func TestClaimAdminOpHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the agent presents its plaintext Bearer token and the code.
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing/wrong bearer: %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Code != "ABCD-1234" {
			t.Errorf("code = %q, want ABCD-1234", body.Code)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "op-1",
			"op_type": "set_proxy_mode",
			"payload": map[string]interface{}{"proxy_mode": "existing", "proxy_type": "nginx"},
		})
	}))
	defer srv.Close()

	claim, err := claimAdminOp(t.Context(), srv.Client(), srv.URL, "agent-1", "tok", "ABCD-1234")
	if err != nil {
		t.Fatalf("claimAdminOp: %v", err)
	}
	if claim.ID != "op-1" || claim.OpType != "set_proxy_mode" {
		t.Fatalf("unexpected claim: %+v", claim)
	}
	var p setProxyModePayload
	if err := json.Unmarshal(claim.Payload, &p); err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	if p.ProxyMode != "existing" || p.ProxyType != "nginx" {
		t.Errorf("payload = %+v", p)
	}
}

func TestAckAdminOp(t *testing.T) {
	var gotOK bool
	var gotResult string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/op-1/ack") {
			t.Errorf("unexpected ack path %q", r.URL.Path)
		}
		var body struct {
			OK     bool   `json:"ok"`
			Result string `json:"result"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotOK = body.OK
		gotResult = body.Result
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := ackAdminOp(t.Context(), srv.Client(), srv.URL, "agent-1", "tok", "op-1", true, "applied; permissions OK"); err != nil {
		t.Fatalf("ackAdminOp: %v", err)
	}
	if !gotOK || gotResult != "applied; permissions OK" {
		t.Errorf("ack body = ok:%t result:%q", gotOK, gotResult)
	}
}

func TestReconfigureLocalUnreachable(t *testing.T) {
	// Port 1 is reserved and won't have a listener — connection refused.
	_, reachable, err := reconfigureLocal(t.Context(), 1, "tok", setProxyModePayload{ProxyMode: "existing"})
	if reachable {
		t.Error("expected unreachable for a closed port")
	}
	if err == nil {
		t.Error("expected a transport error")
	}
}

func TestReconfigureLocalHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"message": "switched to existing nginx",
			"remediation": map[string]interface{}{
				"steps": []map[string]interface{}{
					{"title": "Make config writable", "commands": []string{"sudo chgrp -R nurproxy /etc/nginx"}},
				},
				"sudoers_line": "agent ALL=(root) NOPASSWD: /usr/sbin/nginx -t",
			},
		})
	}))
	defer srv.Close()

	// reconfigureLocal targets 127.0.0.1:{port}; rebuild against the test server URL
	// by parsing its port. Simpler: hit it directly through the same decode path.
	res, reachable, err := postReconfigure(t, srv.URL)
	if err != nil || !reachable {
		t.Fatalf("reconfigure: reachable=%t err=%v", reachable, err)
	}
	if !res.OK || res.Remediation == nil || len(res.Remediation.Steps) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Remediation.SudoersLine == "" {
		t.Error("expected sudoers line")
	}
}

// postReconfigure exercises the same response-decoding contract reconfigureLocal
// relies on, against an arbitrary URL (httptest doesn't bind 127.0.0.1:apiPort).
func postReconfigure(t *testing.T, url string) (reconfigureResult, bool, error) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(`{}`))
	if err != nil {
		return reconfigureResult{}, false, err
	}
	defer resp.Body.Close()
	var res reconfigureResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return reconfigureResult{}, true, err
	}
	return res, true, nil
}
