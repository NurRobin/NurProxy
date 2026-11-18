package failover

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func seen(ago time.Duration) *time.Time {
	t := t0.Add(-ago)
	return &t
}

func at(d time.Duration) *time.Time {
	t := t0.Add(d)
	return &t
}

var policy = Policy{DownAfter: 120 * time.Second, Failback: true, FailbackAfter: 5 * time.Minute}

func cands(primary, backup, second *time.Time) []Candidate {
	out := []Candidate{
		{ServerID: "p", Eligible: true, LastSeen: primary},
		{ServerID: "b", Eligible: true, LastSeen: backup},
	}
	if second != nil {
		out = append(out, Candidate{ServerID: "c", Eligible: true, LastSeen: second})
	}
	return out
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name       string
		cands      []Candidate
		state      models.DomainFailoverState
		policy     Policy
		wantActive string
		wantEvents []Event
		wantState  func(t *testing.T, st models.DomainFailoverState)
	}{
		{
			name:       "no state, primary healthy: stays on primary",
			cands:      cands(seen(10*time.Second), seen(10*time.Second), nil),
			wantActive: "p",
		},
		{
			name:       "one missed heartbeat is not down",
			cands:      cands(seen(100*time.Second), seen(5*time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "p"},
			wantActive: "p",
		},
		{
			name:       "primary down past DownAfter: fails over to the backup",
			cands:      cands(seen(121*time.Second), seen(5*time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "p"},
			wantActive: "b",
			wantEvents: []Event{EventFailover},
			wantState: func(t *testing.T, st models.DomainFailoverState) {
				if st.Switches != 1 || st.SwitchedAt == nil || !st.SwitchedAt.Equal(t0) {
					t.Fatalf("switch not recorded: %+v", st)
				}
			},
		},
		{
			name:       "never-seen primary counts as down",
			cands:      cands(nil, seen(5*time.Second), nil),
			wantActive: "b",
			wantEvents: []Event{EventFailover},
		},
		{
			name:       "priority order: skips a down first backup",
			cands:      cands(seen(time.Hour), seen(time.Hour), seen(time.Second)),
			state:      models.DomainFailoverState{ActiveServerID: "p"},
			wantActive: "c",
			wantEvents: []Event{EventFailover},
		},
		{
			name: "ineligible backup is never selected",
			cands: []Candidate{
				{ServerID: "p", Eligible: true, LastSeen: seen(time.Hour)},
				{ServerID: "b", Eligible: false, LastSeen: seen(time.Second)},
			},
			state:      models.DomainFailoverState{ActiveServerID: "p"},
			wantActive: "p",
			wantEvents: []Event{EventAllDown},
		},
		{
			name:       "all down: record stays on the last active agent",
			cands:      cands(seen(time.Hour), seen(time.Hour), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", Switches: 1},
			wantActive: "b",
			wantEvents: []Event{EventAllDown},
			wantState: func(t *testing.T, st models.DomainFailoverState) {
				if !st.AllDown || st.Switches != 1 {
					t.Fatalf("all-down not recorded or switch counted: %+v", st)
				}
			},
		},
		{
			name:       "all down again: no repeated event",
			cands:      cands(seen(time.Hour), seen(time.Hour), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", AllDown: true},
			wantActive: "b",
		},
		{
			name:       "all down, then the primary returns: failover to it at once",
			cands:      cands(seen(time.Second), seen(time.Hour), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", AllDown: true},
			wantActive: "p",
			wantEvents: []Event{EventFailover},
			wantState: func(t *testing.T, st models.DomainFailoverState) {
				if st.AllDown {
					t.Fatal("all-down flag kept after a candidate came back")
				}
			},
		},
		{
			name:       "all down, then the active backup returns: recovered",
			cands:      cands(seen(time.Hour), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", AllDown: true},
			wantActive: "b",
			wantEvents: []Event{EventRecovered},
		},
		{
			name:       "primary back: failback waits for the delay",
			cands:      cands(seen(time.Second), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b"},
			wantActive: "b",
			wantState: func(t *testing.T, st models.DomainFailoverState) {
				if st.PendingServerID != "p" || st.PendingSince == nil || !st.PendingSince.Equal(t0) {
					t.Fatalf("failback not pending: %+v", st)
				}
			},
		},
		{
			name:       "primary healthy for the whole delay: fails back",
			cands:      cands(seen(time.Second), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", PendingServerID: "p", PendingSince: at(-5 * time.Minute), Switches: 1},
			wantActive: "p",
			wantEvents: []Event{EventFailback},
			wantState: func(t *testing.T, st models.DomainFailoverState) {
				if st.PendingServerID != "" || st.PendingSince != nil || st.Switches != 2 {
					t.Fatalf("failback state wrong: %+v", st)
				}
			},
		},
		{
			name:       "primary drops out while pending: pending is cleared",
			cands:      cands(seen(time.Hour), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", PendingServerID: "p", PendingSince: at(-4 * time.Minute)},
			wantActive: "b",
			wantState: func(t *testing.T, st models.DomainFailoverState) {
				if st.PendingServerID != "" || st.PendingSince != nil {
					t.Fatalf("pending kept for a down candidate: %+v", st)
				}
			},
		},
		{
			name:       "failback off: stays on the backup",
			cands:      cands(seen(time.Second), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b", PendingServerID: "p", PendingSince: at(-time.Hour)},
			policy:     Policy{DownAfter: policy.DownAfter, Failback: false, FailbackAfter: policy.FailbackAfter},
			wantActive: "b",
		},
		{
			name:       "zero failback delay: fails back in the same pass",
			cands:      cands(seen(time.Second), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "b"},
			policy:     Policy{DownAfter: policy.DownAfter, Failback: true},
			wantActive: "p",
			wantEvents: []Event{EventFailback},
		},
		{
			name:       "active server no longer a candidate: back to the primary",
			cands:      cands(seen(time.Second), seen(time.Second), nil),
			state:      models.DomainFailoverState{ActiveServerID: "gone"},
			wantActive: "p",
		},
		{
			name:       "on the second backup, the first comes back: fails back to the first",
			cands:      cands(seen(time.Hour), seen(time.Second), seen(time.Second)),
			state:      models.DomainFailoverState{ActiveServerID: "c", PendingServerID: "b", PendingSince: at(-6 * time.Minute)},
			wantActive: "b",
			wantEvents: []Event{EventFailback},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.policy
			if p == (Policy{}) {
				p = policy
			}
			dec := Decide(tt.cands, tt.state, p, t0)
			if got := tt.cands[dec.Active].ServerID; got != tt.wantActive {
				t.Fatalf("active = %s, want %s (state %+v)", got, tt.wantActive, dec.State)
			}
			if dec.State.ActiveServerID != tt.wantActive {
				t.Fatalf("stored active = %s, want %s", dec.State.ActiveServerID, tt.wantActive)
			}
			if !slices.Equal(dec.Events, tt.wantEvents) {
				t.Fatalf("events = %v, want %v", dec.Events, tt.wantEvents)
			}
			if tt.wantState != nil {
				tt.wantState(t, dec.State)
			}
		})
	}
}

func TestDecide_changedOnlyWhenStateMoves(t *testing.T) {
	st := models.DomainFailoverState{DomainID: 7, ActiveServerID: "p"}
	dec := Decide(cands(seen(time.Second), seen(time.Second), nil), st, policy, t0)
	if dec.Changed {
		t.Fatalf("steady state reported as changed: %+v", dec.State)
	}
	if dec.State.DomainID != 7 {
		t.Fatalf("domain id lost: %+v", dec.State)
	}
	if dec := Decide(nil, st, policy, t0); dec.Active != -1 || dec.Changed {
		t.Fatalf("no candidates: %+v", dec)
	}
}

// A flapping primary (healthy, down, healthy) never fails back before it has
// been healthy for the full delay in one stretch.
func TestDecide_flappingPrimaryDoesNotFailBack(t *testing.T) {
	st := models.DomainFailoverState{ActiveServerID: "b"}
	step := func(primarySeen *time.Time, now time.Time) {
		dec := Decide([]Candidate{
			{ServerID: "p", Eligible: true, LastSeen: primarySeen},
			{ServerID: "b", Eligible: true, LastSeen: &now},
		}, st, policy, now)
		st = dec.State
	}
	now := t0
	step(&now, now) // primary back: pending
	now = t0.Add(4 * time.Minute)
	stale := now.Add(-3 * time.Minute)
	step(&stale, now) // primary gone again: pending cleared
	now = t0.Add(5 * time.Minute)
	step(&now, now) // back again: the delay starts over
	if st.ActiveServerID != "b" || st.PendingSince == nil || !st.PendingSince.Equal(now) {
		t.Fatalf("delay did not restart: %+v", st)
	}
	now = now.Add(5 * time.Minute)
	step(&now, now)
	if st.ActiveServerID != "p" {
		t.Fatalf("no failback after a full stable delay: %+v", st)
	}
}

type settings map[string]string

func (s settings) GetSetting(key string) (string, error) {
	v, ok := s[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name string
		in   settings
		want Policy
	}{
		{"defaults", settings{}, Policy{DownAfter: DefaultOfflineTimeout + DefaultGrace, Failback: true, FailbackAfter: DefaultFailbackDelay}},
		{"configured", settings{"agent_offline_timeout": "60", "failover_grace": "0", "failover_failback": "false", "failover_failback_delay": "30"},
			Policy{DownAfter: 60 * time.Second, Failback: false, FailbackAfter: 30 * time.Second}},
		{"offline floor and negative grace", settings{"agent_offline_timeout": "1", "failover_grace": "-5"},
			Policy{DownAfter: 15 * time.Second, Failback: true, FailbackAfter: DefaultFailbackDelay}},
		{"garbage falls back to defaults", settings{"failover_grace": "soon", "failover_failback": "maybe"},
			Policy{DownAfter: DefaultOfflineTimeout + DefaultGrace, Failback: true, FailbackAfter: DefaultFailbackDelay}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LoadPolicy(tt.in); got != tt.want {
				t.Fatalf("LoadPolicy = %+v, want %+v", got, tt.want)
			}
		})
	}
}
