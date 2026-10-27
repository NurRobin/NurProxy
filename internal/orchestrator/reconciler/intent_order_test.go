package reconciler

import (
	"fmt"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// The managed apply revision is a digest of the intent set, so an unchanged
// desired state must always produce the same set regardless of map order.
func TestIntentSetForIsDeterministic(t *testing.T) {
	d := testDB(t)
	_, _, agent, _, _ := setupScenario(t, d)
	r := New(d, newMockAgentClient(), time.Minute)

	desired := make(map[string]desiredRoute)
	for index := range 16 {
		host := fmt.Sprintf("app-%02d.example.com", index)
		desired[host] = desiredRoute{
			fqdn: host, artifactID: fmt.Sprintf("domain-%02d", index),
			intent: proxymodel.Route{Host: host, Upstream: proxymodel.Upstream{Addr: "10.0.0.2", Port: 8080}},
		}
	}

	var want string
	for attempt := range 20 {
		set := helperprotocol.NormalizeManagedIntentSet(r.intentSetFor(agent, desired, nil))
		for index := 1; index < len(set.Intents); index++ {
			if set.Intents[index-1].ArtifactID >= set.Intents[index].ArtifactID {
				t.Fatalf("intents not sorted: %s before %s", set.Intents[index-1].ArtifactID, set.Intents[index].ArtifactID)
			}
		}
		revision, err := helperprotocol.Digest(set)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			want = revision
		} else if revision != want {
			t.Fatalf("attempt %d produced revision %s, want %s", attempt, revision, want)
		}
	}
}
