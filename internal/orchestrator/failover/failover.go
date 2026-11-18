// Package failover decides which agent a domain's CNAME points at when the
// domain has backup servers on other agents (#74). The decision is a pure
// function of the candidates' heartbeat health, the stored decision state and
// the policy, so the reconciler (which acts on it), the takeover preview and
// the API (which only show it) cannot disagree, and the hysteresis can be
// tested without a clock.
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
	// DefaultSettle is how long the current target is held after the
	// orchestrator starts, after a pass that came late, and after every agent
	// was down. Agents reconnect with up to 30 s of backoff and heartbeat
	// every 30 s; until all had a chance to report, a missing heartbeat says
	// nothing about the agent.
	DefaultSettle = 90 * time.Second
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
	// Settle is how long the current target is held, even when it looks
	// down, after StartedAt, after a stale pass and after all-down ends.
	Settle time.Duration
	// StartedAt is when the deciding orchestrator started; zero for none.
	StartedAt time.Time
	// StaleAfter: a pass that comes more than this after the previous one
	// (the orchestrator was stopped, stuck or cut off) starts a settle
	// period. Zero disables the check.
	StaleAfter time.Duration
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
// back to the defaults; negative durations count as zero. StartedAt and
// StaleAfter are the caller's to fill in.
func LoadPolicy(s SettingsReader) Policy {
	return Policy{
		DownAfter:     OfflineTimeout(s) + seconds(s, "failover_grace", DefaultGrace),
		Failback:      boolSetting(s, "failover_failback", true),
		FailbackAfter: seconds(s, "failover_failback_delay", DefaultFailbackDelay),
		Settle:        seconds(s, "failover_settle", DefaultSettle),
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
	// no FQDN to point the CNAME at, or a backup agent that no longer serves
	// the zone or has not applied the standby route and certificate.
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
	// EventTargetRemoved: the server the record pointed at is no longer a
	// candidate (its backup entry, server or agent was removed); the record
	// moves to the first healthy candidate, or to the primary if none is.
	EventTargetRemoved Event = "failover_target_removed"
)

// Decision is the outcome of one evaluation.
type Decision struct {
	// Active indexes the candidate the record should point at; -1 when there
	// are no candidates.
	Active int
	// Previous indexes the candidate the record pointed at before this pass,
	// -1 when that server is no longer a candidate.
	Previous int
	// State is the decision state to store. Its DomainID is copied from the
	// input.
	State models.DomainFailoverState
	// Events lists what changed, in order.
	Events []Event
	// Settling reports that a down target is being held for the settle
	// period.
	Settling bool
}

// Decide picks the candidate the domain's record should point at.
//
//   - While the active candidate is healthy it stays, except that a more
//     preferred healthy candidate takes over once it has been healthy for
//     FailbackAfter (when Failback is on).
//   - When the active candidate is down, the first healthy candidate in
//     priority order takes over; DownAfter already is the grace. During a
//     settle period (after StartedAt, after a stale pass, after all-down
//     ended) a down target is held instead, because agents are still
//     reconnecting and whoever reports first would win.
//   - When none is healthy, the record stays on the active candidate: the
//     last record is never removed.
//   - A stored target that is no longer a candidate is replaced by the first
//     healthy candidate, or the primary.
//
// The returned state always carries EvaluatedAt=now, so the caller stores it
// on every pass that acts.
func Decide(cands []Candidate, st models.DomainFailoverState, p Policy, now time.Time) Decision {
	if len(cands) == 0 {
		return Decision{Active: -1, Previous: -1, State: st}
	}
	next := st
	stamp := now
	next.EvaluatedAt = &stamp
	var events []Event
	healthy := func(i int) bool { return p.Healthy(cands[i], now) }
	firstHealthy := func() int {
		for i := range cands {
			if healthy(i) {
				return i
			}
		}
		return -1
	}
	clearPending := func() { next.PendingServerID, next.PendingSince = "", nil }
	switchTo := func(i int, ev Event) {
		next.ActiveServerID = cands[i].ServerID
		clearPending()
		at := now
		next.SwitchedAt = &at
		next.Switches++
		events = append(events, ev)
	}

	if st.EvaluatedAt != nil && p.StaleAfter > 0 && now.Sub(*st.EvaluatedAt) > p.StaleAfter {
		next.SettleSince = &stamp
	}

	active := -1
	for i := range cands {
		if cands[i].ServerID == st.ActiveServerID {
			active = i
			break
		}
	}
	if active < 0 {
		if st.ActiveServerID == "" {
			// First evaluation: the record points at the primary already.
			active = 0
			next.ActiveServerID = cands[0].ServerID
		} else {
			target := firstHealthy()
			if target < 0 {
				target = 0
			}
			next.AllDown = false
			switchTo(target, EventTargetRemoved)
			return Decision{Active: target, Previous: -1, State: next, Events: events}
		}
	}
	prev := active

	if !healthy(active) && st.AllDown && firstHealthy() >= 0 {
		// All-down ends with someone other than the target reporting first;
		// give the rest the settle period to report too.
		next.AllDown = false
		next.SettleSince = &stamp
	}
	settleFrom := p.StartedAt
	if next.SettleSince != nil && next.SettleSince.After(settleFrom) {
		settleFrom = *next.SettleSince
	}
	settling := p.Settle > 0 && !settleFrom.IsZero() && now.Before(settleFrom.Add(p.Settle))

	if !healthy(active) {
		clearPending()
		if settling {
			return Decision{Active: active, Previous: prev, State: next, Events: events, Settling: true}
		}
		if i := firstHealthy(); i >= 0 {
			next.AllDown = false
			switchTo(i, EventFailover)
			active = i
		} else if !next.AllDown {
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
			clearPending()
		} else {
			if next.PendingServerID != cands[preferred].ServerID || next.PendingSince == nil {
				at := now
				next.PendingServerID, next.PendingSince = cands[preferred].ServerID, &at
			}
			if now.Sub(*next.PendingSince) >= p.FailbackAfter {
				switchTo(preferred, EventFailback)
				active = preferred
			}
		}
	}
	return Decision{Active: active, Previous: prev, State: next, Events: events}
}
