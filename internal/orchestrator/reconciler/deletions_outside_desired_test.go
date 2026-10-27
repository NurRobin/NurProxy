package reconciler

import (
	"reflect"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestDeletionsOutsideDesired(t *testing.T) {
	moved := helperprotocol.ManagedDeletion{ResourceID: "dom-1", Host: "a.example.com", Backend: "nginx"}
	deleted := helperprotocol.ManagedDeletion{ResourceID: "dom-2", Host: "b.example.com", Backend: "nginx"}
	cases := []struct {
		name      string
		deletions []helperprotocol.ManagedDeletion
		desired   []string
		want      []helperprotocol.ManagedDeletion
	}{
		{name: "no tombstones", deletions: []helperprotocol.ManagedDeletion{}, desired: []string{"dom-1"}, want: []helperprotocol.ManagedDeletion{}},
		{name: "tombstones for absent routes stay", deletions: []helperprotocol.ManagedDeletion{moved, deleted}, desired: []string{"dom-3"}, want: []helperprotocol.ManagedDeletion{moved, deleted}},
		{name: "tombstone for a rendered route is dropped", deletions: []helperprotocol.ManagedDeletion{moved, deleted}, desired: []string{"dom-1"}, want: []helperprotocol.ManagedDeletion{deleted}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intents := make([]proxymodel.RouteIntent, 0, len(tc.desired))
			for _, id := range tc.desired {
				intents = append(intents, proxymodel.RouteIntent{ArtifactID: id})
			}
			got := deletionsOutsideDesired(tc.deletions, intents)
			if got == nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("deletionsOutsideDesired = %#v, want %#v", got, tc.want)
			}
		})
	}
}
