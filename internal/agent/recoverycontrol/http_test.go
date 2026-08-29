package recoverycontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func TestHTTPOrchestratorUsesAgentScopedAuthenticatedRecoveryRoutes(t *testing.T) {
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		key := r.Method + " " + r.URL.Path
		requests[key]++
		switch key {
		case "GET /api/v1/agents/agent-1/recovery/helper":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "agent-1", "helper_instance_id": "helper-1", "helper_build_id": "dev-1",
				"attestation_key_id": "attestation-1", "attestation_public_key": strings.Repeat("A", 43),
				"hello_digest": strings.Repeat("a", 64), "enrolled_at": time.Now().UTC(),
			})
		case "GET /api/v1/agents/agent-1/recovery/plans":
			_ = json.NewEncoder(w).Encode([]ExecutionRecord{{HelperPlanID: "plan-1", DiagnosticID: "diagnostic-1", ExpiresAt: time.Now().UTC().Add(time.Minute)}})
		case "POST /api/v1/agents/agent-1/recovery/plans":
			w.WriteHeader(http.StatusCreated)
		case "POST /api/v1/agents/agent-1/recovery/plans/plan-1/receipt":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	remote, err := NewHTTP(server.URL, "agent-1", "agent-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	pin, err := remote.HelperPin(context.Background())
	if err != nil || pin.HelperInstanceID != "helper-1" || pin.AttestationKeyID != "attestation-1" {
		t.Fatalf("pin = %#v, err=%v", pin, err)
	}
	plans, err := remote.ListPlans(context.Background())
	if err != nil || len(plans) != 1 || plans[0].HelperPlanID != "plan-1" {
		t.Fatalf("plans = %#v, err=%v", plans, err)
	}
	plan := helperprotocol.Signed[helperprotocol.HelperPlan]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageHelperPlan, helperprotocol.HelperPlan{})}
	if err := remote.SubmitPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	receipt := helperprotocol.Signed[helperprotocol.HelperReceipt]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, helperprotocol.HelperReceipt{})}
	if err := remote.SubmitReceipt(context.Background(), "plan-1", receipt); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"GET /api/v1/agents/agent-1/recovery/helper", "GET /api/v1/agents/agent-1/recovery/plans",
		"POST /api/v1/agents/agent-1/recovery/plans", "POST /api/v1/agents/agent-1/recovery/plans/plan-1/receipt",
	} {
		if requests[key] != 1 {
			t.Fatalf("requests[%q] = %d", key, requests[key])
		}
	}
}

func TestHTTPOrchestratorBoundsResponsesAndRejectsNonSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
			return
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	remote, err := NewHTTP(server.URL, "agent-1", "agent-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.ListPlans(context.Background()); err == nil {
		t.Fatal("oversized response was accepted")
	}
	if err := remote.SubmitPlan(context.Background(), helperprotocol.Signed[helperprotocol.HelperPlan]{}); err == nil {
		t.Fatal("non-success plan response was accepted")
	}
}
