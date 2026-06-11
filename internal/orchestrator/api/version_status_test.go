package api

import "testing"

func TestCompareAgentVersion(t *testing.T) {
	tests := []struct {
		agent, orch, want string
	}{
		{"v0.2.1", "v0.2.1", versionCurrent},
		{"0.2.1", "v0.2.1", versionCurrent}, // normalize leading v
		{"v0.2.0", "v0.2.1", versionOutdated},
		{"v0.1.9", "v0.2.0", versionOutdated},
		{"v1.0.0", "v0.9.9", versionAhead},
		{"v0.3.0", "v0.2.9", versionAhead},
		{"v0.2.1-rc.1", "v0.2.1", versionCurrent}, // prerelease ignored in coarse compare
		{"dev", "v0.2.1", versionUnknown},         // non-semver agent
		{"v0.2.1", "dev", versionUnknown},         // non-semver orchestrator
		{"", "v0.2.1", versionUnknown},            // missing
		{"v0.2", "v0.2.1", versionUnknown},        // not three components
		{"abc", "v0.2.1", versionUnknown},         // garbage
	}
	for _, tt := range tests {
		if got := compareAgentVersion(tt.agent, tt.orch); got != tt.want {
			t.Errorf("compareAgentVersion(%q, %q) = %q, want %q", tt.agent, tt.orch, got, tt.want)
		}
	}
}
