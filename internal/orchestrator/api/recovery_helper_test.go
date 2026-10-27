package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func signedHelperHello(t *testing.T, instanceID string) helperprotocol.Signed[helperprotocol.HelperHello] {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := helperprotocol.HelperHello{
		RequestID: "enrollment-request-1", HelperInstanceID: instanceID,
		HelperBuildID: "v0.4.0-dev-0619e04", AttestationKeyID: "attestation-" + instanceID,
		AttestationPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}
	signed, err := helperprotocol.Sign(hello.AttestationKeyID, privateKey, helperprotocol.NewEnvelope(helperprotocol.MessageHelperHello, hello))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestRecoveryHelperEnrollmentRequiresAdminAndVerifiesAttestation(t *testing.T) {
	_, database, handler, cookie := recoveryFixture(t)
	signed := signedHelperHello(t, "helper-1")
	path := "/api/v1/agents/agent-1/recovery/helper"
	statusPath := "/api/v1/agents/agent-1/recovery/helper-status"
	if w := doRequestWithAuth(t, handler, http.MethodGet, statusPath, nil, recoveryAgentToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("agent accessed admin helper status = %d, want 401", w.Code)
	}
	if w := doRequest(t, handler, http.MethodGet, statusPath, nil, cookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"enrolled":false`) {
		t.Fatalf("unenrolled helper status = %d: %s", w.Code, w.Body.String())
	}
	w := doRequestWithAuth(t, handler, http.MethodPut, path, signed, recoveryAgentToken)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("agent enrollment = %d, want 401", w.Code)
	}
	forged := signed
	forged.Envelope.Payload.HelperBuildID = "attacker-build"
	w = doRequest(t, handler, http.MethodPut, path, forged, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("forged enrollment = %d, want 400: %s", w.Code, w.Body.String())
	}
	w = doRequest(t, handler, http.MethodPut, path, signed, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid enrollment = %d: %s", w.Code, w.Body.String())
	}
	if w := doRequest(t, handler, http.MethodGet, statusPath, nil, cookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"helper_instance_id":"helper-1"`) {
		t.Fatalf("enrolled helper status = %d: %s", w.Code, w.Body.String())
	}
	stored, err := database.GetRecoveryHelper("agent-1")
	if err != nil || stored.HelperInstanceID != "helper-1" || stored.AttestationPublicKey != signed.Envelope.Payload.AttestationPublicKey {
		t.Fatalf("stored helper = %#v, err=%v", stored, err)
	}
	entries, _, err := database.ListAuditLog(20, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.EntityType == "recovery_helper" && entry.EntityID == "helper-1" && entry.Action == "enrolled" && !strings.Contains(entry.Details, signed.Envelope.Payload.AttestationPublicKey) {
			found = true
		}
	}
	if !found {
		t.Fatal("bounded helper enrollment audit was not recorded")
	}
	w = doRequestWithAuth(t, handler, http.MethodGet, path, nil, recoveryAgentToken)
	if w.Code != http.StatusOK {
		t.Fatalf("agent helper pin lookup = %d: %s", w.Code, w.Body.String())
	}
	w = doRequestWithAuth(t, handler, http.MethodGet, "/api/v1/agents/other/recovery/helper", nil, recoveryAgentToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-agent helper pin lookup = %d, want 403", w.Code)
	}
}

func TestRecoveryHelperEnrollmentRefusesSilentRotation(t *testing.T) {
	_, _, handler, cookie := recoveryFixture(t)
	path := "/api/v1/agents/agent-1/recovery/helper"
	if w := doRequest(t, handler, http.MethodPut, path, signedHelperHello(t, "helper-1"), cookie); w.Code != http.StatusCreated {
		t.Fatalf("initial enrollment = %d", w.Code)
	}
	if w := doRequest(t, handler, http.MethodPut, path, signedHelperHello(t, "helper-2"), cookie); w.Code != http.StatusConflict {
		t.Fatalf("silent rotation = %d, want 409: %s", w.Code, w.Body.String())
	}
}
