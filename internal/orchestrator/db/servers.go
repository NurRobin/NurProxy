package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// CreateServer inserts a new server record.
func (d *DB) CreateServer(s *models.Server) error {
	now := time.Now().UTC()
	s.CreatedAt = now

	_, err := d.sql.Exec(`
		INSERT INTO servers (id, agent_id, name, address, notes, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.AgentID, s.Name, s.Address, s.Notes, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting server: %w", err)
	}
	return nil
}

func scanServer(sc interface {
	Scan(dest ...any) error
}) (*models.Server, error) {
	var s models.Server
	var createdAt string

	err := sc.Scan(&s.ID, &s.AgentID, &s.Name, &s.Address, &s.Notes, &createdAt)
	if err != nil {
		return nil, err
	}

	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &s, nil
}

// GetServer retrieves a server by ID.
func (d *DB) GetServer(id string) (*models.Server, error) {
	row := d.read.QueryRow(`
		SELECT id, agent_id, name, address, notes, created_at
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

// PathRouteAddrs resolves the servers of a domain's path routes to their
// addresses. Each server must exist and belong to the same agent as the
// domain's server: that agent proxies every path of the domain, so a server
// of another agent would be dialed from the wrong host.
func (d *DB) PathRouteAddrs(dom models.Domain) (map[string]string, error) {
	if len(dom.ProxyConfig.Routes) == 0 {
		return nil, nil
	}
	srv, err := d.GetServer(dom.ServerID)
	if err != nil {
		return nil, fmt.Errorf("path routes need the domain's server %q, which was not found", dom.ServerID)
	}
	addrs := make(map[string]string, len(dom.ProxyConfig.Routes))
	for _, p := range dom.ProxyConfig.Routes {
		if _, done := addrs[p.ServerID]; done {
			continue
		}
		if p.ServerID == "" {
			return nil, fmt.Errorf("path route %q has no server_id", p.Path)
		}
		rs, err := d.GetServer(p.ServerID)
		if err != nil {
			return nil, fmt.Errorf("path route %q: server %q not found", p.Path, p.ServerID)
		}
		if rs.AgentID != srv.AgentID {
			return nil, fmt.Errorf("path route %q: server %q belongs to another agent than the domain's server %q; the domain's agent proxies every path, so route servers must be on the same agent", p.Path, rs.Name, srv.Name)
		}
		addrs[p.ServerID] = rs.Address
	}
	return addrs, nil
}

// CheckDomainRoutes validates a domain's path routes as the REST API and the
// MCP tools accept them: shape, route servers on the domain's agent, and a
// backend on that agent that can render them.
func (d *DB) CheckDomainRoutes(dom *models.Domain) error {
	if len(dom.ProxyConfig.Routes) == 0 {
		return nil
	}
	if dom.CertOnly {
		return fmt.Errorf("a cert-only domain serves no vhost and cannot have path routes")
	}
	intents := make([]proxymodel.PathRoute, 0, len(dom.ProxyConfig.Routes))
	for _, p := range dom.ProxyConfig.Routes {
		intents = append(intents, p.Intent(""))
	}
	if err := proxymodel.ValidatePathRoutes(intents, false); err != nil {
		return err
	}
	if _, err := d.PathRouteAddrs(*dom); err != nil {
		return err
	}
	srv, err := d.GetServer(dom.ServerID)
	if err != nil {
		return err
	}
	agent, err := d.GetAgent(srv.AgentID)
	if err != nil {
		return nil
	}
	return dom.ProxyConfig.CheckRoutesSupported(agent.ProxyCapabilities, agentBackendName(agent))
}

// agentBackendName names the proxy an agent serves domains with, for error
// messages.
func agentBackendName(agent *models.Agent) string {
	if agent.ProxyMode == "existing" && agent.ProxyDetection != nil && agent.ProxyDetection.Kind != "" {
		return agent.ProxyDetection.Kind
	}
	return "the built-in Caddy"
}

// ListServersByAgent returns all servers belonging to the given agent.
func (d *DB) ListServersByAgent(agentID string) ([]models.Server, error) {
	rows, err := d.read.Query(`
		SELECT id, agent_id, name, address, notes, created_at
		FROM servers WHERE agent_id = ? ORDER BY created_at`, agentID)
	if err != nil {
		return nil, fmt.Errorf("listing servers: %w", err)
	}
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
