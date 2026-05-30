package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/permcheck"
)

// fakeReconfigurer records the request it received and returns a canned result,
// so the handler test exercises request decoding + response shaping without a real
// Holder or host proxy.
type fakeReconfigurer struct {
	gotReq proxy.ReconfigureRequest
	result proxy.ReconfigureResult
}

func (f *fakeReconfigurer) Reconfigure(_ context.Context, req proxy.ReconfigureRequest, _ proxy.ReconfigureDeps) proxy.ReconfigureResult {
	f.gotReq = req
	return f.result
}

func reconfigureBody() []byte {
	b, _ := json.Marshal(map[string]any{
		"proxy_mode":       "existing",
		"proxy_type":       "nginx",
		"proxy_config_dir": "/etc/nginx",
		"proxy_binary":     "/usr/sbin/nginx",
		"proxy_reload_cmd": "/usr/sbin/nginx -s reload",
		"proxy_test_cmd":   "/usr/sbin/nginx -t",
		"proxy_service":    "nginx",
		"proxy_log_paths":  []string{"/var/log/nginx/error.log"},
	})
	return b
}

func TestHandleReconfigureRequiresAuth(t *testing.T) {
	s := newTestServer()
	s.SetReconfigurer(&fakeReconfigurer{}, proxy.ReconfigureDeps{})

	// No Authorization header — must be rejected by authMiddleware before the
	// handler runs.
	req := httptest.NewRequest(http.MethodPost, "/admin/reconfigure", bytes.NewReader(reconfigureBody()))
	w := httptest.NewRecorder()
	s.authMiddleware(s.handleReconfigure)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated reconfigure status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleReconfigureHappyPath(t *testing.T) {
	s := newTestServer()
	fr := &fakeReconfigurer{
		result: proxy.ReconfigureResult{
			OK:      false,
			Message: "switched to existing nginx but config is not writable",
			Remediation: &permcheck.Remediation{
				Steps: []permcheck.RemediationStep{{
					Title:    "Make the config directory writable",
					Commands: []string{"sudo groupadd -f nurproxy"},
				}},
				SudoersLine: "agent ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -s reload",
			},
		},
	}
	s.SetReconfigurer(fr, proxy.ReconfigureDeps{})

	req := httptest.NewRequest(http.MethodPost, "/admin/reconfigure", bytes.NewReader(reconfigureBody()))
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.authMiddleware(s.handleReconfigure)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// The snake_case body must have been decoded into the typed request.
	if fr.gotReq.Mode != "existing" || fr.gotReq.Type != "nginx" {
		t.Errorf("decoded request = %+v, want mode=existing type=nginx", fr.gotReq)
	}
	if fr.gotReq.ConfigDir != "/etc/nginx" || len(fr.gotReq.LogPaths) != 1 {
		t.Errorf("decoded request lost fields: %+v", fr.gotReq)
	}

	var resp struct {
		OK          bool   `json:"ok"`
		Message     string `json:"message"`
		Remediation *struct {
			Steps []struct {
				Title    string   `json:"title"`
				Commands []string `json:"commands"`
			} `json:"steps"`
			SudoersLine string `json:"sudoers_line"`
		} `json:"remediation"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.OK {
		t.Error("expected ok=false in the applied-with-warnings response")
	}
	if resp.Message == "" {
		t.Error("expected a non-empty message")
	}
	if resp.Remediation == nil {
		t.Fatal("expected remediation in the response")
	}
	if len(resp.Remediation.Steps) != 1 || resp.Remediation.Steps[0].Title == "" {
		t.Errorf("remediation steps malformed: %+v", resp.Remediation.Steps)
	}
	if resp.Remediation.SudoersLine == "" {
		t.Error("expected a sudoers_line in the remediation")
	}
}

func TestHandleReconfigureOmitsRemediationWhenNil(t *testing.T) {
	s := newTestServer()
	s.SetReconfigurer(&fakeReconfigurer{
		result: proxy.ReconfigureResult{OK: true, Message: "switched to existing nginx"},
	}, proxy.ReconfigureDeps{})

	req := httptest.NewRequest(http.MethodPost, "/admin/reconfigure", bytes.NewReader(reconfigureBody()))
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.authMiddleware(s.handleReconfigure)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if _, present := raw["remediation"]; present {
		t.Error("remediation key should be omitted when nil")
	}
}

func TestHandleReconfigureUnavailableWhenUnset(t *testing.T) {
	s := newTestServer() // no SetReconfigurer

	req := httptest.NewRequest(http.MethodPost, "/admin/reconfigure", bytes.NewReader(reconfigureBody()))
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.authMiddleware(s.handleReconfigure)(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (no holder wired)", w.Code, http.StatusServiceUnavailable)
	}
}
