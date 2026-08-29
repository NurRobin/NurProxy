package proxy

import (
	"errors"
	"os"
	"path/filepath"
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

func TestManagedArtifactFileSnapshotRequiresRegularFileAndRechecksIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nurproxy-app.conf")
	content := StampManagedArtifact("server {}\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, managed, identity, err := ReadManagedArtifactFile(path)
	if err != nil || string(got) != content || !managed {
		t.Fatalf("read snapshot: managed=%v content=%q err=%v", managed, got, err)
	}
	if err := identity.Recheck(); err != nil {
		t.Fatalf("fresh identity failed recheck: %v", err)
	}
	old := path + ".old"
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := identity.Recheck(); err == nil {
		t.Fatal("replacement retained the prior identity")
	}

	symlink := filepath.Join(dir, "nurproxy-link.conf")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ReadManagedArtifactFile(symlink); !errors.Is(err, ErrManagedArtifactNotRegular) {
		t.Fatalf("symlink read error = %v", err)
	}
	if _, _, err := ProbeManagedArtifactFile(symlink); !errors.Is(err, ErrManagedArtifactNotRegular) {
		t.Fatalf("symlink probe error = %v", err)
	}
}
