package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/reconciler"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// captureHub records the intent sets the reconciler publishes, standing in for
// a connected agent stream so the test can observe exactly what the next push
// would deliver to the agent.
type captureHub struct {
	mu   sync.Mutex
	sets []proxymodel.IntentSet
}

func (h *captureHub) Connected(string) bool                                { return true }
func (h *captureHub) PublishIntents(string, []proxymodel.RouteIntent) bool { return true }

func (h *captureHub) PublishIntentSet(_ string, set proxymodel.IntentSet) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sets = append(h.sets, set)
	return true
}

func (h *captureHub) last() (proxymodel.IntentSet, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sets) == 0 {
		return proxymodel.IntentSet{}, false
	}
	return h.sets[len(h.sets)-1], true
}

// TestDomainConfig_ResetAndUpdate_resetManualArtifact covers the drift-accept
// trap: once the domain's "dom-<id>" artifact is Source=manual, the reconciler
// pushes its stored bytes verbatim and ignores the domain row, and the agent's
// apply-ACK of those identical bytes hits AppendConfigArtifactVersion's
// semantic-equality gate before the source-updating UPDATE — so the artifact
// stays manual forever. A config reset (or a new manual config) on the domain
// row alone therefore never reaches the agent. Reset/update must also drop the
// manual artifact, after which the next push renders from the domain model.
func TestDomainConfig_ResetAndUpdate_resetManualArtifact(t *testing.T) {
	const staleManual = `{"handle":[{"handler":"static_response","body":"drift-accepted"}]}`
	const newManual = `{"handle":[{"handler":"static_response","body":"new-manual"}]}`

	cases := []struct {
		name         string
		acceptDrift  bool // promote the artifact to Source=manual first
		method       string
		pathSuffix   string // appended to /api/v1/domains/{id}
		body         interface{}
		wantArtifact bool   // artifact row still present after the call
		wantRaw      string // "" = next push must render from the domain model
	}{
		{
			name:        "reset after drift-accept renders from the domain model",
			acceptDrift: true,
			method:      "POST",
			pathSuffix:  "/config/reset",
		},
		{
			name:        "manual update after drift-accept deploys the new bytes",
			acceptDrift: true,
			method:      "PUT",
			pathSuffix:  "/config",
			body:        map[string]json.RawMessage{"config": json.RawMessage(newManual)},
			wantRaw:     newManual,
		},
		{
			name:         "reset with a generated artifact keeps its history",
			method:       "POST",
			pathSuffix:   "/config/reset",
			wantArtifact: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, database := testServer(t)
			h := srv.Handler()
			cookie := setupAdmin(t, h)
			dom := makePreviewDomain(t, srv, "", "")

			artifactID := fmt.Sprintf("dom-%d", dom.ID)
			seedArtifact(t, srv, "a1", artifactID, `{"handle":[]}`)
			if tc.acceptDrift {
				w := doRequest(t, h, "POST", "/api/v1/artifacts/"+artifactID+"/accept",
					map[string]string{"content": staleManual}, cookie)
				if w.Code != http.StatusOK {
					t.Fatalf("accept: %d %s", w.Code, w.Body.String())
				}
				art, err := database.GetConfigArtifact(artifactID)
				if err != nil || art.Source != models.ArtifactSourceManual {
					t.Fatalf("accept did not promote artifact to manual: %+v (%v)", art, err)
				}
			}

			path := fmt.Sprintf("/api/v1/domains/%d%s", dom.ID, tc.pathSuffix)
			w := doRequest(t, h, tc.method, path, tc.body, cookie)
			if w.Code != http.StatusOK {
				t.Fatalf("%s %s: %d %s", tc.method, path, w.Code, w.Body.String())
			}

			_, artErr := database.GetConfigArtifact(artifactID)
			if tc.wantArtifact && artErr != nil {
				t.Fatalf("generated artifact should survive a reset: %v", artErr)
			}
			if !tc.wantArtifact {
				if artErr == nil {
					t.Fatal("manual artifact should be deleted so the next push renders from the domain model")
				}
				assertAuditEntry(t, database, "config_artifact", artifactID, "reset")
			}

			// "Next push": exactly what the reconciler would deliver to the agent now.
			hub := &captureHub{}
			rec := reconciler.New(database, nil, time.Minute)
			rec.SetHub(hub)
			if err := rec.PushAgentRoutes("a1"); err != nil {
				t.Fatalf("PushAgentRoutes: %v", err)
			}
			set, ok := hub.last()
			if !ok || len(set.Intents) != 1 {
				t.Fatalf("expected 1 pushed intent, got %+v", set)
			}
			route := set.Intents[0].Route
			if route.Host != "app.example.com" {
				t.Errorf("pushed host = %q, want app.example.com", route.Host)
			}
			if route.Raw.Content == staleManual {
				t.Fatal("push still carries the stale drift-accepted bytes")
			}
			if tc.wantRaw == "" {
				if route.IsRaw() {
					t.Errorf("push should render from the domain model, got raw content %q", route.Raw.Content)
				}
				if route.Upstream.Port != dom.Port {
					t.Errorf("model-rendered upstream port = %d, want %d", route.Upstream.Port, dom.Port)
				}
			} else if route.Raw.Content != tc.wantRaw {
				t.Errorf("pushed raw content = %q, want the new manual config %q", route.Raw.Content, tc.wantRaw)
			}
		})
	}
}

// assertAuditEntry fails the test unless an audit entry with the given identity
// and action exists.
func assertAuditEntry(t *testing.T, database interface {
	ListAuditLog(limit, offset int) ([]models.AuditLogEntry, int, error)
}, entityType, entityID, action string) {
	t.Helper()
	entries, _, err := database.ListAuditLog(50, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.EntityType == entityType && e.EntityID == entityID && e.Action == action {
			return
		}
	}
	t.Errorf("no audit entry %s/%s action=%s", entityType, entityID, action)
}
