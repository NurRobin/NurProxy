package proxy

import "strings"

const (
	ManagedArtifactMarker              = "# nurproxy-managed:v1"
	MaxManagedArtifactMarkerProbeBytes = 256

	managedArtifactMarkerPrefix = "# nurproxy-managed:"
)

// StampManagedArtifact places the exact current marker on the first line and
// normalizes any leading NurProxy marker lines left by an earlier render pass.
func StampManagedArtifact(content string) string {
	lines := strings.Split(content, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, managedArtifactMarkerPrefix) {
			kept = append(kept, line)
		}
	}
	return ManagedArtifactMarker + "\n" + strings.Join(kept, "\n")
}

// HasManagedArtifactMarker recognizes only one exact current marker on the
// first line and inspects at most MaxManagedArtifactMarkerProbeBytes bytes.
func HasManagedArtifactMarker(content string) bool {
	if len(content) > MaxManagedArtifactMarkerProbeBytes {
		content = content[:MaxManagedArtifactMarkerProbeBytes]
	}
	prefix := ManagedArtifactMarker + "\n"
	if !strings.HasPrefix(content, prefix) {
		return false
	}
	remainder := content[len(prefix):]
	if strings.HasPrefix(remainder, managedArtifactMarkerPrefix) {
		return false
	}
	return !strings.Contains(remainder, "\n"+managedArtifactMarkerPrefix)
}
