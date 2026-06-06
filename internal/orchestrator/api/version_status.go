package api

import (
	"strconv"
	"strings"
)

// Version-skew status values reported on agents (models.Agent.VersionStatus).
const (
	versionCurrent  = "current"
	versionOutdated = "outdated"
	versionAhead    = "ahead"
	versionUnknown  = "unknown"
)

// agentVersionStatus compares an agent's reported version against the
// orchestrator's own (s.version) and classifies the skew for the dashboard.
// Anything it can't confidently parse as semver (empty, "dev", git hashes) is
// "unknown" rather than a misleading verdict.
func (s *Server) agentVersionStatus(agentVersion string) string {
	return compareAgentVersion(agentVersion, s.version)
}

// compareAgentVersion is the pure comparison behind agentVersionStatus, split
// out so it can be tested without a Server.
func compareAgentVersion(agentVersion, orchestratorVersion string) string {
	if strings.TrimSpace(agentVersion) == "" || strings.TrimSpace(orchestratorVersion) == "" {
		return versionUnknown
	}
	if agentVersion == orchestratorVersion {
		return versionCurrent
	}
	av, aok := parseSemver(agentVersion)
	ov, ook := parseSemver(orchestratorVersion)
	if !aok || !ook {
		return versionUnknown
	}
	switch cmp := av.compare(ov); {
	case cmp < 0:
		return versionOutdated
	case cmp > 0:
		return versionAhead
	default:
		return versionCurrent
	}
}

type semver struct{ major, minor, patch int }

// parseSemver parses "vX.Y.Z" / "X.Y.Z" (a trailing -prerelease/+build is
// ignored for this coarse comparison). It returns ok=false for anything that
// isn't three numeric components, so non-release builds fall back to "unknown".
func parseSemver(v string) (semver, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Drop pre-release / build metadata; we only rank the release triple.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{nums[0], nums[1], nums[2]}, true
}

// compare returns -1/0/+1 for a<b / a==b / a>b.
func (a semver) compare(b semver) int {
	for _, d := range []int{a.major - b.major, a.minor - b.minor, a.patch - b.patch} {
		if d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}
