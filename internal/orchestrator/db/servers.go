package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// CreateServer inserts a new server record.
func (d *DB) CreateServer(s *models.Server) error {
	now := time.Now().UTC()
	s.CreatedAt = now

	_, err := d.sql.Exec(`
		INSERT INTO servers (id, agent_id, name, address, notes, created_at, discovery_source_id, external_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.AgentID, s.Name, s.Address, s.Notes, now.Format(time.RFC3339), s.DiscoverySourceID, s.ExternalID,
	)
	if err != nil {
		if isUniqueViolation(err) && s.ExternalID != "" {
			return ErrServerAlreadyImported
		}
		return fmt.Errorf("inserting server: %w", err)
	}
	return nil
}

// ErrServerAlreadyImported is returned by CreateServer when a server for the
// same discovered machine already exists.
var ErrServerAlreadyImported = errors.New("a server for this discovered machine already exists")

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const serverColumns = `id, agent_id, name, address, notes, created_at, discovery_source_id, external_id, discovery_missing_since`

func scanServer(sc interface {
	Scan(dest ...any) error
}) (*models.Server, error) {
	var s models.Server
	var createdAt, missingSince string

	err := sc.Scan(&s.ID, &s.AgentID, &s.Name, &s.Address, &s.Notes, &createdAt,
		&s.DiscoverySourceID, &s.ExternalID, &missingSince)
	if err != nil {
		return nil, err
	}

	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if missingSince != "" {
		if t, err := time.Parse(time.RFC3339, missingSince); err == nil {
			s.DiscoveryMissingSince = &t
		}
	}
	return &s, nil
}

// GetServer retrieves a server by ID.
func (d *DB) GetServer(id string) (*models.Server, error) {
	row := d.read.QueryRow(`
		SELECT `+serverColumns+`
		FROM servers WHERE id = ?`, id)

	s, err := scanServer(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("server not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying server: %w", err)
	}
	return s, nil
}

// CheckDomainBackendOptions normalizes a domain's per-domain logging settings
// and refuses proxy settings the backend of the agent serving the domain's
// server cannot render as asked: logging options it lacks, and header values
// with "${" on Apache. Shared by the REST API and the MCP tools so both
// reject the same requests.
func (d *DB) CheckDomainBackendOptions(dom *models.Domain) error {
	if err := dom.ProxyConfig.NormalizeLogging(); err != nil {
		return err
	}
	logging := dom.ProxyConfig.AccessLog != "" || dom.ProxyConfig.ErrorLogLevel != ""
	headerVars := proxymodel.CheckHeaderConfigVars(dom.ProxyConfig.CustomRequestHeaders, dom.ProxyConfig.CustomResponseHeaders) != nil
	if !logging && !headerVars {
		return nil
	}
	srv, err := d.GetServer(dom.ServerID)
	if err != nil {
		if !logging {
			return nil
		}
		return fmt.Errorf("logging settings need the domain's server %q, which was not found", dom.ServerID)
	}
	agent, err := d.GetAgent(srv.AgentID)
	if err != nil {
		// No agent row yet: nothing reported, nothing to check against.
		return nil
	}
	backend, kind := "the built-in Caddy", ""
	if agent.ProxyMode == "existing" && agent.ProxyDetection != nil && agent.ProxyDetection.Kind != "" {
		backend, kind = agent.ProxyDetection.Kind, agent.ProxyDetection.Kind
	}
	if err := dom.ProxyConfig.CheckLoggingSupported(agent.ProxyCapabilities, backend); err != nil {
		return err
	}
	return dom.ProxyConfig.CheckHeadersSupported(agent.ProxyCapabilities, kind)
}

// ListServersByAgent returns all servers belonging to the given agent.
func (d *DB) ListServersByAgent(agentID string) ([]models.Server, error) {
	rows, err := d.read.Query(`
		SELECT `+serverColumns+`
		FROM servers WHERE agent_id = ? ORDER BY created_at`, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing servers: %w", err)
	}
	return collectServers(rows)
}

// ListServersByDiscoverySource returns the servers imported from a source.
func (d *DB) ListServersByDiscoverySource(sourceID string) ([]models.Server, error) {
	rows, err := d.read.Query(`
		SELECT `+serverColumns+`
		FROM servers WHERE discovery_source_id = ? AND external_id <> '' ORDER BY created_at`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("listing servers: %w", err)
	}
	return collectServers(rows)
}

func collectServers(rows *sql.Rows) ([]models.Server, error) {
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning server: %w", err)
		}
		servers = append(servers, *s)
	}
	return servers, rows.Err()
}

// UpdateServer updates a server's mutable fields.
func (d *DB) UpdateServer(s *models.Server) error {
	res, err := d.sql.Exec(`
		UPDATE servers SET name = ?, address = ?, notes = ? WHERE id = ?`,
		s.Name, s.Address, s.Notes, s.ID,
	)
	if err != nil {
		return fmt.Errorf("updating server: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("server not found: %s", s.ID)
	}
	return nil
}

// DeleteServer removes a server by ID. It fails with ErrParentInUse while domains
// still reference the server.
func (d *DB) DeleteServer(id string) error {
	res, err := d.sql.Exec("DELETE FROM servers WHERE id = ?", id)
	if err != nil {
		return parentDeleteError("server", id, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("server not found: %s", id)
	}
	return nil
}
