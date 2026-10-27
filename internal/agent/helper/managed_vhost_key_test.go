package helper

import (
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy/apache"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/nginx"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// The orchestrator decides which route tombstones collide by
// helperprotocol.ManagedVhostKey; it must name exactly the file the agent's
// backends write, including case.
func TestManagedVhostKeyMatchesBackendFileNames(t *testing.T) {
	for _, host := range []string{"app.example.com", "App.example.com", "*.example.com", " spaced.example.com ", "a/b..c\\d.example.com"} {
		key := helperprotocol.ManagedVhostKey(host)
		if got, want := nginx.ManagedFileName(host), "nurproxy-"+key+".conf"; got != want {
			t.Errorf("nginx file for %q = %q, key gives %q", host, got, want)
		}
		if got, want := apache.ManagedFileName(host), "nurproxy-"+key+".conf"; got != want {
			t.Errorf("apache file for %q = %q, key gives %q", host, got, want)
		}
	}
}
