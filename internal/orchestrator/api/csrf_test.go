package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieAuthenticatedMutationRejectsCrossSiteBrowserRequest(t *testing.T) {
	_, _, handler, cookie := recoveryFixture(t)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/agents/agent-1/safe-auto-repair", bytes.NewBufferString(`{"mode":"enabled"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-site mutation = %d, want 403: %s", response.Code, response.Body.String())
	}
}

func TestCookieAuthenticatedMutationAcceptsSameOriginBrowserRequest(t *testing.T) {
	_, _, handler, cookie := recoveryFixture(t)
	request := httptest.NewRequest(http.MethodPut, "https://nurproxy.example/api/v1/agents/agent-1/safe-auto-repair", bytes.NewBufferString(`{"mode":"enabled"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://nurproxy.example")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("same-origin mutation = %d: %s", response.Code, response.Body.String())
	}
}
