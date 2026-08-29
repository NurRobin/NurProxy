package proxy

import (
	"strings"
	"testing"
)

func TestManagedArtifactMarkerStampAndHasAreExactBoundedAndIdempotent(t *testing.T) {
	body := "server { listen 80; }\n"
	stamped := StampManagedArtifact(body)
	if !HasManagedArtifactMarker(stamped) {
		t.Fatalf("stamped artifact was not recognized: %q", stamped)
	}
	if got := StampManagedArtifact(stamped); got != stamped {
		t.Fatalf("StampManagedArtifact is not idempotent:\n%q\n%q", stamped, got)
	}
	if strings.Count(stamped, ManagedArtifactMarker) != 1 {
		t.Fatalf("marker count = %d", strings.Count(stamped, ManagedArtifactMarker))
	}
	if got := StampManagedArtifact(ManagedArtifactMarker + "\n" + ManagedArtifactMarker + "\n" + body); strings.Count(got, ManagedArtifactMarker) != 1 || !HasManagedArtifactMarker(got) {
		t.Fatalf("leading duplicate markers were not normalized: %q", got)
	}
	if got := StampManagedArtifact(body + ManagedArtifactMarker + "\n"); strings.Count(got, ManagedArtifactMarker) != 1 || !HasManagedArtifactMarker(got) {
		t.Fatalf("embedded exact marker line was not normalized: %q", got)
	}

	for _, content := range []string{
		body,
		" # nurproxy-managed:v1\n" + body,
		"# nurproxy-managed:v2\n" + body,
		ManagedArtifactMarker + " trailing\n" + body,
		ManagedArtifactMarker + "\n" + ManagedArtifactMarker + "\n" + body,
		ManagedArtifactMarker + "\n# comment\n" + ManagedArtifactMarker + "\n" + body,
		ManagedArtifactMarker + "\r\n" + body,
		strings.Repeat("x", MaxManagedArtifactMarkerProbeBytes+1),
	} {
		if HasManagedArtifactMarker(content) {
			t.Errorf("malformed/unmanaged content was accepted: %q", content)
		}
	}
}
