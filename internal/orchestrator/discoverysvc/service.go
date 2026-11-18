// Package discoverysvc runs server discovery sources for the orchestrator: on
// demand from the API and periodically for sources with a sync interval. It
// keeps the last result of each source, marks imported servers whose machine
// disappeared, and imports selected candidates as servers.
package discoverysvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/NurRobin/NurProxy/internal/discovery"
	"github.com/NurRobin/NurProxy/internal/discovery/dryrun"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// RunTimeout bounds one discovery run.
const RunTimeout = 2 * time.Minute

// Sync interval limits in seconds. 0 disables periodic sync.
const (
	MinSyncInterval = 300
	MaxSyncInterval = 7 * 24 * 3600
)

// ErrNoResult is returned when a source has not completed a run yet.
var ErrNoResult = errors.New("this source has not been run yet: run discovery first")

// Auditor records an audit entry for an action of the service.
type Auditor func(entityType, entityID, action, details string)

// Service runs discovery sources.
type Service struct {
	db     *db.DB
	dryRun bool

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// New returns a service. With dryRun, every source is replaced by the
// sandbox fixture and nothing is contacted.
func New(database *db.DB, dryRun bool) *Service {
	return &Service{db: database, dryRun: dryRun, locks: map[string]*sync.Mutex{}}
}

// DryRun reports whether discovery is simulated.
func (s *Service) DryRun() bool { return s.dryRun }

// Discoverer returns the implementation for a source type, wrapped for
// dry-run when the service simulates discovery.
func (s *Service) Discoverer(typ string) (discovery.Discoverer, error) {
	d, err := discovery.Get(typ)
	if err != nil {
		return nil, err
	}
	if s.dryRun {
		return dryrun.Wrap(d), nil
	}
	return d, nil
}

func (s *Service) lock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.locks[id]
	if !ok {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}

// CandidateView is a candidate annotated with the server imported from it.
type CandidateView struct {
	discovery.Candidate
	ServerID   string `json:"server_id,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
}

// View is a source's last result as the dashboard shows it.
type View struct {
	SourceID   string          `json:"source_id"`
	LastRunAt  *time.Time      `json:"last_run_at,omitempty"`
	LastError  string          `json:"last_error,omitempty"`
	HasResult  bool            `json:"has_result"`
	Candidates []CandidateView `json:"candidates"`
	Warnings   []string        `json:"warnings,omitempty"`
	// Missing are imported servers whose machine the source no longer
	// reports.
	Missing []models.Server `json:"missing"`
}

// Run discovers a source now, stores the result and updates the imported
// servers' links. audit may be nil.
func (s *Service) Run(ctx context.Context, sourceID string, audit Auditor) (*View, error) {
	l := s.lock(sourceID)
	l.Lock()
	defer l.Unlock()

	src, err := s.db.GetDiscoverySource(sourceID)
	if err != nil {
		return nil, err
	}
	d, err := s.Discoverer(src.Type)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	now := time.Now().UTC()
	res, err := d.Discover(ctx, json.RawMessage(src.Config))
	if err != nil {
		msg := err.Error()
		if rerr := s.db.RecordDiscoveryFailure(src.ID, now, msg); rerr != nil {
			log.Printf("discovery: recording failure of %s: %v", src.ID, rerr)
		}
		if audit != nil {
			audit("discovery_source", src.ID, "discovery_failed", msg)
		}
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	servers, err := s.db.ListServersByDiscoverySource(src.ID)
	if err != nil {
		return nil, err
	}
	updates := make([]db.DiscoveryServerUpdate, 0, len(servers))
	type transition struct{ server, action, details string }
	var transitions []transition
	for _, srv := range servers {
		u := db.DiscoveryServerUpdate{ServerID: srv.ID, ExternalID: srv.ExternalID, MissingSince: srv.DiscoveryMissingSince}
		if c := findCandidate(d, res.Candidates, srv.ExternalID); c != nil {
			if srv.DiscoveryMissingSince != nil {
				transitions = append(transitions, transition{srv.ID, "discovery_found", fmt.Sprintf("%s (%s) is reported again by %s", srv.Name, c.ExternalID, src.Name)})
			}
			u.ExternalID, u.MissingSince = c.ExternalID, nil
		} else if res.Covers(srv.ExternalID) && srv.DiscoveryMissingSince == nil {
			u.MissingSince = &now
			transitions = append(transitions, transition{srv.ID, "discovery_missing", fmt.Sprintf("%s (%s) is no longer reported by %s", srv.Name, srv.ExternalID, src.Name)})
		}
		updates = append(updates, u)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	if err := s.db.RecordDiscoveryRun(src.ID, now, string(blob), updates); err != nil {
		return nil, err
	}
	if audit != nil {
		audit("discovery_source", src.ID, "discovery_run",
			fmt.Sprintf("%s: %d machines, %d warnings", src.Name, len(res.Candidates), len(res.Warnings)))
		for _, t := range transitions {
			audit("server", t.server, t.action, t.details)
		}
	}
	return s.View(src.ID)
}

func findCandidate(d discovery.Discoverer, cands []discovery.Candidate, externalID string) *discovery.Candidate {
	for i := range cands {
		if cands[i].ExternalID == externalID {
			return &cands[i]
		}
	}
	for i := range cands {
		if discovery.SameMachine(d, cands[i].ExternalID, externalID) {
			return &cands[i]
		}
	}
	return nil
}

func (s *Service) lastResult(sourceID string) (*discovery.Result, error) {
	raw, err := s.db.GetDiscoveryResult(sourceID)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	var res discovery.Result
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil, fmt.Errorf("stored discovery result is corrupt: %w", err)
	}
	return &res, nil
}

// View returns the source's last stored result without contacting it.
func (s *Service) View(sourceID string) (*View, error) {
	src, err := s.db.GetDiscoverySource(sourceID)
	if err != nil {
		return nil, err
	}
	d, err := s.Discoverer(src.Type)
	if err != nil {
		return nil, err
	}
	res, err := s.lastResult(src.ID)
	if err != nil {
		return nil, err
	}
	servers, err := s.db.ListServersByDiscoverySource(src.ID)
	if err != nil {
		return nil, err
	}
	v := &View{SourceID: src.ID, LastRunAt: src.LastRunAt, LastError: src.LastError,
		Candidates: []CandidateView{}, Missing: []models.Server{}}
	for _, srv := range servers {
		if srv.DiscoveryMissingSince != nil {
			v.Missing = append(v.Missing, srv)
		}
	}
	if res == nil {
		return v, nil
	}
	v.HasResult = true
	v.Warnings = res.Warnings
	for _, c := range res.Candidates {
		cv := CandidateView{Candidate: c}
		if cv.Addresses == nil {
			cv.Addresses = []discovery.Address{}
		}
		for _, srv := range servers {
			if discovery.SameMachine(d, srv.ExternalID, c.ExternalID) {
				cv.ServerID, cv.ServerName, cv.AgentID = srv.ID, srv.Name, srv.AgentID
				break
			}
		}
		v.Candidates = append(v.Candidates, cv)
	}
	return v, nil
}

// ImportItem selects one candidate to import. Empty fields take the
// candidate's values.
type ImportItem struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name,omitempty"`
	Address    string `json:"address,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// Skipped is a selected candidate that was not imported.
type Skipped struct {
	ExternalID string `json:"external_id"`
	ServerID   string `json:"server_id,omitempty"`
	Reason     string `json:"reason"`
}

// ImportResult lists what an import created and skipped.
type ImportResult struct {
	Created []models.Server `json:"created"`
	Skipped []Skipped       `json:"skipped"`
}

// InvalidImportError is a request problem (unknown candidate, no address).
type InvalidImportError struct{ Msg string }

func (e *InvalidImportError) Error() string { return e.Msg }

// Import creates servers under agentID for the selected candidates of the
// source's last result. Candidates already imported (under any agent) are
// skipped. Every item is checked before anything is created.
func (s *Service) Import(agentID, sourceID string, items []ImportItem, audit Auditor) (*ImportResult, error) {
	if len(items) == 0 {
		return nil, &InvalidImportError{"select at least one machine to import"}
	}
	l := s.lock(sourceID)
	l.Lock()
	defer l.Unlock()

	src, err := s.db.GetDiscoverySource(sourceID)
	if err != nil {
		return nil, err
	}
	d, err := s.Discoverer(src.Type)
	if err != nil {
		return nil, err
	}
	res, err := s.lastResult(src.ID)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, &InvalidImportError{ErrNoResult.Error()}
	}
	existing, err := s.db.ListServersByDiscoverySource(src.ID)
	if err != nil {
		return nil, err
	}

	out := &ImportResult{Created: []models.Server{}, Skipped: []Skipped{}}
	var toCreate []*models.Server
	seen := map[string]bool{}
	for _, it := range items {
		c := findCandidate(nil, res.Candidates, it.ExternalID)
		if c == nil {
			return nil, &InvalidImportError{fmt.Sprintf("%s is not in the last discovery result of %s: run discovery again", it.ExternalID, src.Name)}
		}
		if seen[c.ExternalID] {
			continue
		}
		seen[c.ExternalID] = true
		if srv := findServer(d, existing, c.ExternalID); srv != nil {
			out.Skipped = append(out.Skipped, Skipped{ExternalID: c.ExternalID, ServerID: srv.ID, Reason: "already imported as " + srv.Name})
			continue
		}
		srv := &models.Server{
			ID:                uuid.New().String(),
			AgentID:           agentID,
			Name:              firstNonEmpty(it.Name, c.Name),
			Address:           firstNonEmpty(it.Address, c.SuggestedAddress),
			Notes:             firstNonEmpty(it.Notes, c.Notes),
			DiscoverySourceID: src.ID,
			ExternalID:        c.ExternalID,
		}
		if srv.Address == "" {
			return nil, &InvalidImportError{fmt.Sprintf("no address was detected for %s (%s): enter one", c.Name, c.ExternalID)}
		}
		toCreate = append(toCreate, srv)
	}
	for _, srv := range toCreate {
		if err := s.db.CreateServer(srv); err != nil {
			if errors.Is(err, db.ErrServerAlreadyImported) {
				out.Skipped = append(out.Skipped, Skipped{ExternalID: srv.ExternalID, Reason: "already imported"})
				continue
			}
			return out, err
		}
		out.Created = append(out.Created, *srv)
		if audit != nil {
			audit("server", srv.ID, "create", fmt.Sprintf("%s (imported from %s, %s)", srv.Name, src.Name, srv.ExternalID))
		}
	}
	return out, nil
}

func findServer(d discovery.Discoverer, servers []models.Server, externalID string) *models.Server {
	for i := range servers {
		if discovery.SameMachine(d, servers[i].ExternalID, externalID) {
			return &servers[i]
		}
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ValidSyncInterval reports whether seconds is an allowed sync interval.
func ValidSyncInterval(seconds int) bool {
	return seconds == 0 || (seconds >= MinSyncInterval && seconds <= MaxSyncInterval)
}

// Start runs sources with a sync interval in the background until ctx ends.
func (s *Service) Start(ctx context.Context, tick time.Duration) {
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.syncDue(ctx, time.Now())
			}
		}
	}()
}

func (s *Service) syncDue(ctx context.Context, now time.Time) {
	sources, err := s.db.ListDiscoverySources()
	if err != nil {
		log.Printf("discovery: listing sources: %v", err)
		return
	}
	source := models.AuditSourceSystem
	if s.dryRun {
		source = models.AuditSourceDryRun
	}
	audit := func(entityType, entityID, action, details string) {
		if err := s.db.InsertAuditLog(&models.AuditLogEntry{
			EntityType: entityType, EntityID: entityID, Action: action,
			Actor: "discovery", Source: source, Details: details,
		}); err != nil {
			log.Printf("discovery: audit: %v", err)
		}
	}
	for _, src := range sources {
		if src.SyncInterval <= 0 {
			continue
		}
		if src.LastRunAt != nil && now.Sub(*src.LastRunAt) < time.Duration(src.SyncInterval)*time.Second {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if _, err := s.Run(ctx, src.ID, audit); err != nil {
			log.Printf("discovery: periodic sync of %q failed: %v", src.Name, err)
		}
	}
}
