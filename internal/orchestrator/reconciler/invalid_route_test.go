package reconciler

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// TestBuildDesiredRoutes_holdsBackInvalidStoredRoute checks that a domain
// whose stored proxy settings fail validation is not pushed (the agent's
// helper would refuse the whole batch), keeps its current file and
// certificate on the agent, and shows the reason on the domain.
func TestBuildDesiredRoutes_holdsBackInvalidStoredRoute(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, dom := setupScenario(t, d)

	artifactID := artifactIDForDomain(dom.ID)
	art := &models.ConfigArtifact{
		ID: artifactID, AgentID: agent.ID, Backend: "caddy",
		Target:  models.Target{Kind: models.TargetKindCaddyRoute, Path: "caddy:route:" + artifactID},
		Source:  models.ArtifactSourceGenerated,
		Content: `{"handle":[]}`,
	}
	if err := d.CreateConfigArtifact(art, "tester", "seed"); err != nil {
		t.Fatalf("CreateConfigArtifact: %v", err)
	}
	dom.ProxyConfig.CustomResponseHeaders = map[string]string{"X-A": "a\nb"}
	if err := d.UpdateDomain(dom); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}

	r := New(d, newMockAgentClient(), time.Minute)
	desired, keep, err := r.buildDesiredRoutes(agent)
	if err != nil {
		t.Fatalf("buildDesiredRoutes: %v", err)
	}
	if len(desired) != 0 {
		t.Fatalf("invalid route was pushed: %+v", desired)
	}
	if !slices.Contains(keep, art.Target.Path) {
		t.Fatalf("current file of the held-back route is not retained: %v", keep)
	}
	if set := r.intentSetFor(agent, desired, keep); !slices.Contains(set.CertKeep, "app.example.com") {
		t.Fatalf("certificate of the held-back route is not retained: %+v", set.CertKeep)
	}
	stored, err := d.GetDomain(dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != models.DomainStatusError || !strings.Contains(stored.ErrorMsg, "proxy settings are invalid") {
		t.Fatalf("domain status = %q, error = %q", stored.Status, stored.ErrorMsg)
	}
}
