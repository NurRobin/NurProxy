// Package failover decides which agent a domain's CNAME points at when the
// domain has backup servers on other agents (#74). The decision is a pure
// function of the candidates' heartbeat health, the stored decision state and
// the policy, so the reconciler (which acts on it) and the API (which shows
// it) cannot disagree, and the hysteresis can be tested without a clock.
package failover

import (
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

const (
	// DefaultOfflineTimeout and offlineFloor mirror the agent_offline_timeout
	// setting: how long an agent may go without a heartbeat before it is
	// marked offline.
	DefaultOfflineTimeout = 90 * time.Second
	offlineFloor          = 15 * time.Second
	// DefaultGrace is added on top of the offline timeout before a domain
	// fails over, so a slow heartbeat or a short orchestrator hiccup does not
	// move DNS.
	DefaultGrace = 30 * time.Second
	// DefaultFailbackDelay is how long a more preferred candidate must stay
	// healthy before the record moves back to it.
	DefaultFailbackDelay = 5 * time.Minute
	// MaxBackups bounds the backup list of one domain.
	MaxBackups = 3
)

// SettingsReader is the part of the database the policy is read from.
type SettingsReader interface {
	GetSetting(key string) (string, error)
}

// Policy holds the failover timing.
type Policy struct {
	// DownAfter is how long an agent may go without a heartbeat before it
	// counts as down for failover.
	DownAfter time.Duration
	// Failback moves the record back to a more preferred candidate once it
	// has been healthy for FailbackAfter. Without it the record stays where
	// it is until that agent fails.
	Failback      bool
	FailbackAfter time.Duration
}

// OfflineTimeout reads agent_offline_timeout (seconds), clamped to a floor so
// a misconfiguration cannot make agents flap.
func OfflineTimeout(s SettingsReader) time.Duration {
	if v, err := s.GetSetting("agent_offline_timeout"); err == nil && v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			d := time.Duration(secs) * time.Second
			if d < offlineFloor {
				return offlineFloor
			}
			return d
		}
	}
	return DefaultOfflineTimeout
}

// LoadPolicy reads the failover settings. Unset or unparsable values fall
// back to the defaults; negative durations count as zero.
func LoadPolicy(s SettingsReader) Policy {
	return Policy{
		DownAfter:     OfflineTimeout(s) + seconds(s, "failover_grace", DefaultGrace),
		Failback:      boolSetting(s, "failover_failback", true),
		FailbackAfter: seconds(s, "failover_failback_delay", DefaultFailbackDelay),
	}
}

func seconds(s SettingsReader, key string, def time.Duration) time.Duration {
	v, err := s.GetSetting(key)
	if err != nil || v == "" {
		return def
	}
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	if secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

func boolSetting(s SettingsReader, key string, def bool) bool {
	v, err := s.GetSetting(key)
	if err != nil || v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// Candidate is one server that may serve the domain, in priority order: the
// primary first, then the backups.
type Candidate struct {
	ServerID string
	// Eligible is false for an agent that may never be selected: not adopted,
	// no FQDN to point at, or a backup agent that no longer serves the zone.
	Eligible bool
	LastSeen *time.Time
}

// Healthy reports whether c's agent counts as up at now.
func (p Policy) Healthy(c Candidate, now time.Time) bool {
	if !c.Eligible || c.LastSeen == nil {
		return false
	}
	return now.Sub(*c.LastSeen) <= p.DownAfter
}

// Event names what a decision changed, for the audit log.
type Event string

const (
	// EventFailover: the active agent is down; the record moves to the first
	// healthy candidate.
	EventFailover Event = "failover"
	// EventFailback: a more preferred candidate stayed healthy for the
	// failback delay; the record moves back to it.
	EventFailback Event = "failback"
	// EventAllDown: no candidate is healthy; the record stays where it is.
	EventAllDown Event = "failover_all_down"
	// EventRecovered: after all were down, the active agent is healthy again.
	EventRecovered Event = "failover_recovered"
)

// Decision is the outcome of one evaluation.
type Decision struct {
	// Active indexes the candidate the record should point at; -1 when there
	// are no candidates.
	Active int
	// State is the decision state to store. Its DomainID is copied from the
	// input.
	State models.DomainFailoverState
	// Events lists what changed, in order.
	Events []Event
	// Changed reports whether State differs from the input state.
	Changed bool
}

// Decide picks the candidate the domain's record should point at.
//
//   - While the active candidate is healthy it stays, except that a more
//     preferred healthy candidate takes over once it has been healthy for
//     FailbackAfter (when Failback is on).
//   - When the active candidate is down, the first healthy candidate in
//     priority order takes over at once; DownAfter already is the grace.
//   - When none is healthy, the record stays on the active candidate: the
//     last record is never removed.
//
// An active server that is no longer a candidate (backup removed, primary
// changed) is replaced by the primary before the rules above apply.
func Decide(cands []Candidate, st models.DomainFailoverState, p Policy, now time.Time) Decision {
	if len(cands) == 0 {
		return Decision{Active: -1, State: st}
	}
	active := 0
	for i := range cands {
		if cands[i].ServerID == st.ActiveServerID {
			active = i
			break
		}
	}
	next := st
	next.ActiveServerID = cands[active].ServerID
	var events []Event
	switchTo := func(i int, ev Event) {
		active = i
		next.ActiveServerID = cands[i].ServerID
		next.PendingServerID, next.PendingSince = "", nil
		at := now
		next.SwitchedAt = &at
		next.Switches++
		events = append(events, ev)
	}
	healthy := func(i int) bool { return p.Healthy(cands[i], now) }

	if !healthy(active) {
		next.PendingServerID, next.PendingSince = "", nil
		replacement := -1
		for i := range cands {
			if healthy(i) {
				replacement = i
				break
			}
		}
		if replacement >= 0 {
			next.AllDown = false
			switchTo(replacement, EventFailover)
		} else if !st.AllDown {
			next.AllDown = true
			events = append(events, EventAllDown)
		}
	} else {
		if st.AllDown {
			next.AllDown = false
			events = append(events, EventRecovered)
		}
		preferred := -1
		if p.Failback {
			for i := 0; i < active; i++ {
				if healthy(i) {
					preferred = i
					break
				}
			}
		}
		if preferred < 0 {
			next.PendingServerID, next.PendingSince = "", nil
		} else {
			if next.PendingServerID != cands[preferred].ServerID || next.PendingSince == nil {
				at := now
				next.PendingServerID, next.PendingSince = cands[preferred].ServerID, &at
			}
			if now.Sub(*next.PendingSince) >= p.FailbackAfter {
				switchTo(preferred, EventFailback)
			}
		}
	}
	return Decision{Active: active, State: next, Events: events, Changed: !sameState(st, next)}
}

func sameState(a, b models.DomainFailoverState) bool {
	return a.ActiveServerID == b.ActiveServerID && a.PendingServerID == b.PendingServerID &&
		sameTime(a.PendingSince, b.PendingSince) && a.AllDown == b.AllDown &&
		sameTime(a.SwitchedAt, b.SwitchedAt) && a.Switches == b.Switches
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
