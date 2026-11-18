package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AgentUpgradeState is the lifecycle of one operator-requested agent upgrade.
// States only ever move forward (see CanTransitionUpgrade); done, failed and
// rolled_back are terminal.
type AgentUpgradeState string

const (
	// UpgradeRequested: the orchestrator recorded the request and pushed it.
	UpgradeRequested AgentUpgradeState = "requested"
	// UpgradeDownloading: the agent accepted it and is fetching the release.
	UpgradeDownloading AgentUpgradeState = "downloading"
	// UpgradeInstalled: the release passed signature and checksum verification
	// and was handed to the privileged applier, which swaps the binary.
	UpgradeInstalled AgentUpgradeState = "installed"
	// UpgradeRestarting: the applier is restarting the service and waiting for
	// the new agent to report healthy.
	UpgradeRestarting AgentUpgradeState = "restarting"
	// UpgradeDone: the agent came back reporting the target version.
	UpgradeDone AgentUpgradeState = "done"
	// UpgradeFailed: the upgrade stopped before the binary was swapped, or the
	// orchestrator gave up waiting. The previous binary is still in place.
	UpgradeFailed AgentUpgradeState = "failed"
	// UpgradeRolledBack: the new binary did not come up healthy and the applier
	// restored the previous one.
	UpgradeRolledBack AgentUpgradeState = "rolled_back"
)

// upgradeRank orders the non-terminal states; every terminal state ranks last.
var upgradeRank = map[AgentUpgradeState]int{
	UpgradeRequested:   0,
	UpgradeDownloading: 1,
	UpgradeInstalled:   2,
	UpgradeRestarting:  3,
	UpgradeDone:        4,
	UpgradeFailed:      4,
	UpgradeRolledBack:  4,
}

// Valid reports whether s is a known state.
func (s AgentUpgradeState) Valid() bool {
	_, ok := upgradeRank[s]
	return ok
}

// Terminal reports whether s ends the upgrade.
func (s AgentUpgradeState) Terminal() bool {
	return s == UpgradeDone || s == UpgradeFailed || s == UpgradeRolledBack
}

// CanTransitionUpgrade reports whether an upgrade in state from may move to
// state to. Moves are forward-only, may skip intermediate states (a lost report
// must not wedge the machine), and never leave a terminal state, with one
// exception: done may still become rolled_back, because done can be inferred
// from a heartbeat before the applier's own verdict arrives. Repeating the
// current non-terminal state is allowed so a retried report is idempotent.
func CanTransitionUpgrade(from, to AgentUpgradeState) bool {
	if from == UpgradeDone && to == UpgradeRolledBack {
		return true
	}
	if !from.Valid() || !to.Valid() || from.Terminal() {
		return false
	}
	return upgradeRank[to] >= upgradeRank[from]
}

// UpgradeTrigger names who started an upgrade.
const (
	UpgradeTriggerManual  = "manual"
	UpgradeTriggerRollout = "rollout"
	UpgradeTriggerAuto    = "auto"
)

// AgentUpgrade is one upgrade attempt as tracked by the orchestrator.
type AgentUpgrade struct {
	ID            string            `json:"id"`
	AgentID       string            `json:"agent_id"`
	FromVersion   string            `json:"from_version"`
	TargetVersion string            `json:"target_version"`
	State         AgentUpgradeState `json:"state"`
	Error         string            `json:"error,omitempty"`
	Trigger       string            `json:"trigger"`
	RolloutID     string            `json:"rollout_id,omitempty"`
	RequestedBy   string            `json:"requested_by,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// SelfUpdateStatus is the agent's own verdict on whether it can replace its
// binary on this host, reported on every heartbeat so the dashboard can explain
// a disabled upgrade button before anything is attempted.
type SelfUpdateStatus struct {
	Supported bool `json:"supported"`
	// Reason explains why Supported is false, phrased as an operator action.
	Reason string `json:"reason,omitempty"`
	// InstallKind is how the binary was installed: "standalone", "deb", "rpm",
	// "pacman", "homebrew", "container" or "unknown".
	InstallKind string `json:"install_kind,omitempty"`
	// ServiceManager is the init system that restarts the agent, if any.
	ServiceManager string `json:"service_manager,omitempty"`
	// DryRun marks a sandbox agent that only simulates the upgrade.
	DryRun bool `json:"dry_run,omitempty"`
}

// UpgradeCommand is pushed to an agent over its stream to start an upgrade.
type UpgradeCommand struct {
	UpgradeID string `json:"upgrade_id"`
	Version   string `json:"version"`
}

// Validate rejects a command the agent must not act on.
func (c UpgradeCommand) Validate() error {
	if !ValidUpgradeID(c.UpgradeID) {
		return fmt.Errorf("invalid upgrade id")
	}
	if _, ok := NormalizeReleaseVersion(c.Version); !ok {
		return fmt.Errorf("invalid release version %q", c.Version)
	}
	return nil
}

// UpgradeReport is the agent's progress report for one upgrade.
type UpgradeReport struct {
	UpgradeID string            `json:"upgrade_id"`
	State     AgentUpgradeState `json:"state"`
	// Version is the version the reporting agent binary runs.
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ValidUpgradeID accepts the identifiers the orchestrator mints: short,
// filename-safe tokens. Agents also use them in file names under their state
// directory, so anything else is refused.
func ValidUpgradeID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

// NormalizeReleaseVersion strips a leading "v" and reports whether the rest is
// a release version as GoReleaser stamps it (MAJOR.MINOR.PATCH with an optional
// -prerelease). The normalized form is what release asset names and the
// signing certificate's tag use.
func NormalizeReleaseVersion(v string) (string, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if !ValidReleaseVersion(v) {
		return "", false
	}
	return v, true
}

// ValidReleaseVersion reports whether v (without a leading "v") is
// MAJOR.MINOR.PATCH[-PRERELEASE] with dot-separated alphanumeric prerelease
// identifiers. Build metadata is not accepted: release tags never carry it, and
// the version ends up in download URLs and file names.
func ValidReleaseVersion(v string) bool {
	_, ok := parseReleaseVersion(v)
	return ok
}

type releaseVersion struct {
	core [3]int
	pre  []string
}

func parseReleaseVersion(v string) (releaseVersion, bool) {
	var rv releaseVersion
	if len(v) == 0 || len(v) > 64 {
		return rv, false
	}
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return rv, false
	}
	for i, p := range parts {
		if !numericIdentifier(p) {
			return rv, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return rv, false
		}
		rv.core[i] = n
	}
	if hasPre {
		ids := strings.Split(pre, ".")
		for _, id := range ids {
			if id == "" {
				return rv, false
			}
			for _, r := range id {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
					continue
				}
				return rv, false
			}
			if isDigits(id) && !numericIdentifier(id) {
				return rv, false
			}
		}
		rv.pre = ids
	}
	return rv, true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// numericIdentifier is a non-empty digit string without a leading zero.
func numericIdentifier(s string) bool {
	return isDigits(s) && (s == "0" || s[0] != '0') && len(s) <= 9
}

// IsPrereleaseVersion reports whether v is a release version with a
// -prerelease suffix (an -rc, -beta and so on).
func IsPrereleaseVersion(v string) bool {
	rv, ok := parseReleaseVersion(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	return ok && len(rv.pre) > 0
}

// CompareReleaseVersions orders two release versions by semver precedence
// (a prerelease ranks below its release). ok is false when either side is not a
// release version, e.g. a "dev" build.
func CompareReleaseVersions(a, b string) (cmp int, ok bool) {
	av, aok := parseReleaseVersion(strings.TrimPrefix(a, "v"))
	bv, bok := parseReleaseVersion(strings.TrimPrefix(b, "v"))
	if !aok || !bok {
		return 0, false
	}
	for i := range av.core {
		if av.core[i] != bv.core[i] {
			if av.core[i] < bv.core[i] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(av.pre) == 0 && len(bv.pre) == 0:
		return 0, true
	case len(av.pre) == 0:
		return 1, true
	case len(bv.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(av.pre) && i < len(bv.pre); i++ {
		x, y := av.pre[i], bv.pre[i]
		if x == y {
			continue
		}
		xn, yn := isDigits(x), isDigits(y)
		switch {
		case xn && yn:
			xi, _ := strconv.Atoi(x)
			yi, _ := strconv.Atoi(y)
			if xi < yi {
				return -1, true
			}
			return 1, true
		case xn:
			return -1, true
		case yn:
			return 1, true
		case x < y:
			return -1, true
		default:
			return 1, true
		}
	}
	switch {
	case len(av.pre) < len(bv.pre):
		return -1, true
	case len(av.pre) > len(bv.pre):
		return 1, true
	}
	return 0, true
}
