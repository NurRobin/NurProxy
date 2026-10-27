package api

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/recoveryauth"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

func seedLiveDomain(t *testing.T, database *db.DB, subdomain string) {
	t.Helper()
	if err := database.CreateProvider(&models.Provider{ID: "prov-live", Type: "cloudflare", Name: "CF", Config: `{"api_token":"test"}`}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateZone(&models.Zone{ID: "zone-live", ProviderID: "prov-live", ExternalID: "ext-live", Name: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateServer(&models.Server{ID: "srv-live", AgentID: "agent-1", Name: "Live", Address: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateDomain(&models.Domain{Subdomain: subdomain, ZoneID: "zone-live", ServerID: "srv-live", Port: 8080, Status: models.DomainStatusActive}); err != nil {
		t.Fatal(err)
	}
}

// The helper latches its permanent breaker after rollback_failed and after a
// journal recovery that ends outcome_indeterminate (#148). helper-status must
// report it in both cases and stay quiet otherwise.
func TestHelperStatusReportsManagedApplyBreaker(t *testing.T) {
	cases := []struct {
		name          string
		state         helperprotocol.JournalState
		note          string // appended to the receipt message
		liveDomain    string // subdomain of example.com kept live on agent-1
		wantOpen      bool
		wantLeftovers string
	}{
		{name: "succeeded", state: helperprotocol.JournalSucceeded},
		{name: "rolled back", state: helperprotocol.JournalRolledBack},
		{name: "rollback failed", state: helperprotocol.JournalRollbackFailed, wantOpen: true},
		{name: "outcome indeterminate", state: helperprotocol.JournalOutcomeIndeterminate, wantOpen: true},
		{name: "succeeded with leftover vhosts", state: helperprotocol.JournalSucceeded,
			note:          "; " + helperprotocol.ManagedLeftoverVhostsNote + "nurproxy-a.example.com.conf, nurproxy-b.example.com.conf; later note",
			wantLeftovers: "nurproxy-a.example.com.conf, nurproxy-b.example.com.conf"},
		{name: "files of live domains are not leftovers", state: helperprotocol.JournalSucceeded, liveDomain: "a",
			note:          "; " + helperprotocol.ManagedLeftoverVhostsNote + "nurproxy-a.example.com.conf, nurproxy-b.example.com.conf and 3 more",
			wantLeftovers: "nurproxy-b.example.com.conf and 3 more"},
		{name: "only live domain files leaves nothing to report", state: helperprotocol.JournalSucceeded, liveDomain: "a",
			note: "; " + helperprotocol.ManagedLeftoverVhostsNote + "nurproxy-a.example.com.conf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, database, handler, cookie := recoveryFixture(t)
			authority, err := recoveryauth.New(make([]byte, ed25519.SeedSize))
			if err != nil {
				t.Fatal(err)
			}
			srv.SetRecoveryAuthority(authority)
			if tc.liveDomain != "" {
				seedLiveDomain(t, database, tc.liveDomain)
			}
			_, signedPlan, helperPrivate := managedApplyAPIFixture(t, database, authority)
			basePath := "/api/v1/agents/agent-1/recovery/applies/apply-operation-1"
			w := doRequestWithAuth(t, handler, http.MethodPost, basePath+"/plan", signedPlan, recoveryAgentToken)
			if w.Code != http.StatusCreated {
				t.Fatalf("managed plan = %d: %s", w.Code, w.Body.String())
			}
			var execution db.ManagedApplyExecution
			if err := json.Unmarshal(w.Body.Bytes(), &execution); err != nil || execution.SignedGrant == nil {
				t.Fatalf("managed plan response: %v", err)
			}
			grant := execution.SignedGrant.Envelope.Payload
			requestDigest, err := helperprotocol.Digest(helperprotocol.NewEnvelope(helperprotocol.MessageExecuteManagedApplyRequest, helperprotocol.ExecuteManagedApplyRequest{
				OperationID: grant.OperationID, HelperPlanID: grant.HelperPlanID, Grant: *execution.SignedGrant,
			}))
			if err != nil {
				t.Fatal(err)
			}
			receipt := helperprotocol.HelperReceipt{
				OperationID: grant.OperationID, CanonicalRequestDigest: requestDigest, HelperInstanceID: grant.HelperInstanceID,
				Action: helperprotocol.ActionApplyManagedProxyState, State: tc.state,
				RollbackCoverage: helperprotocol.RollbackCoveragePartial, SnapshotDigest: strings.Repeat("c", 64),
				SanitizedResult: "managed apply ended as " + string(tc.state) + tc.note, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}
			signedReceipt, err := helperprotocol.Sign("attestation-1", helperPrivate, helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, receipt))
			if err != nil {
				t.Fatal(err)
			}
			if w := doRequestWithAuth(t, handler, http.MethodPost, basePath+"/receipt", signedReceipt, recoveryAgentToken); w.Code != http.StatusNoContent {
				t.Fatalf("managed receipt = %d: %s", w.Code, w.Body.String())
			}

			w = doRequest(t, handler, http.MethodGet, "/api/v1/agents/agent-1/recovery/helper-status", nil, cookie)
			if w.Code != http.StatusOK {
				t.Fatalf("helper status = %d: %s", w.Code, w.Body.String())
			}
			var status struct {
				Breaker   *managedApplyBreakerView   `json:"managed_apply_breaker"`
				Leftovers *managedApplyLeftoversView `json:"managed_apply_leftovers"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if open := status.Breaker != nil && status.Breaker.Open; open != tc.wantOpen {
				t.Fatalf("breaker open = %v, want %v (%s)", open, tc.wantOpen, w.Body.String())
			}
			gotLeftovers := ""
			if status.Leftovers != nil {
				gotLeftovers = status.Leftovers.Files
			}
			if gotLeftovers != tc.wantLeftovers {
				t.Fatalf("leftovers = %q, want %q", gotLeftovers, tc.wantLeftovers)
			}
			if tc.wantOpen && (status.Breaker.OperationID != "apply-operation-1" || status.Breaker.Reason != receipt.SanitizedResult) {
				t.Fatalf("breaker view = %#v", status.Breaker)
			}
		})
	}
}
