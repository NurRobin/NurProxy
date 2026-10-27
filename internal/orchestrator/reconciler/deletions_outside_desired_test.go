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
	upperCased := helperprotocol.ManagedDeletion{ResourceID: "dom-5", Host: "App.example.com", Backend: "nginx"}
	wildcard := helperprotocol.ManagedDeletion{ResourceID: "dom-6", Host: "*.example.com", Backend: "nginx"}
	sameHostAgain := helperprotocol.ManagedDeletion{ResourceID: "dom-4", Host: "b.example.com", Backend: "nginx"}
	type route struct{ id, host string }
	cases := []struct {
		name      string
		deletions []helperprotocol.ManagedDeletion
		desired   []route
		want      []helperprotocol.ManagedDeletion
	}{
		{name: "no tombstones", deletions: []helperprotocol.ManagedDeletion{}, desired: []route{{"dom-1", "a.example.com"}}, want: []helperprotocol.ManagedDeletion{}},
		{name: "tombstones for absent routes stay", deletions: []helperprotocol.ManagedDeletion{moved, deleted}, desired: []route{{"dom-3", "c.example.com"}}, want: []helperprotocol.ManagedDeletion{moved, deleted}},
		{name: "tombstone for a rendered resource is dropped", deletions: []helperprotocol.ManagedDeletion{moved, deleted}, desired: []route{{"dom-1", "a.example.com"}}, want: []helperprotocol.ManagedDeletion{deleted}},
		{name: "tombstone for a host a new domain renders is dropped", deletions: []helperprotocol.ManagedDeletion{moved, deleted}, desired: []route{{"dom-70", "a.example.com"}}, want: []helperprotocol.ManagedDeletion{deleted}},
		{name: "tombstone for a differently cased host is a different file and stays", deletions: []helperprotocol.ManagedDeletion{upperCased}, desired: []route{{"dom-70", "app.example.com"}}, want: []helperprotocol.ManagedDeletion{upperCased}},
		{name: "wildcard tombstone collides with its sanitized file name", deletions: []helperprotocol.ManagedDeletion{wildcard}, desired: []route{{"dom-71", "_wildcard.example.com"}}, want: []helperprotocol.ManagedDeletion{}},
		{name: "second tombstone for the same host is dropped", deletions: []helperprotocol.ManagedDeletion{deleted, sameHostAgain}, desired: []route{}, want: []helperprotocol.ManagedDeletion{deleted}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intents := make([]proxymodel.RouteIntent, 0, len(tc.desired))
			for _, r := range tc.desired {
				intents = append(intents, proxymodel.RouteIntent{ArtifactID: r.id, Route: proxymodel.Route{Host: r.host}})
			}
			got := deletionsOutsideDesired(tc.deletions, intents)
			if got == nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("deletionsOutsideDesired = %#v, want %#v", got, tc.want)
			}
		})
	}
}
