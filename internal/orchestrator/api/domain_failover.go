package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// GET /api/v1/domains/{id}/failover — the servers that may serve the domain,
// their agents' health and which one the CNAME points at (#74).
func (s *Server) handleGetDomainFailover(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}
	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	status, err := s.db.DomainFailoverStatus(dom, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read failover status")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// PUT /api/v1/domains/{id}/backups — replace the domain's backup servers.
// Body: {"server_ids": ["srv-b", "srv-c"]}, most preferred first; an empty
// list removes failover. Each backup must be on its own agent, other than the
// primary's, that serves the domain's zone. Every agent that gains or loses a
// standby route is pushed at once.
func (s *Server) handleSetDomainBackups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(pathParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}
	var req struct {
		ServerIDs []string `json:"server_ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ServerIDs == nil {
		writeError(w, http.StatusBadRequest, "server_ids is required (an empty list removes all backups)")
		return
	}
	before, err := s.db.ListDomainBackups(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read backup servers")
		return
	}
	removed, err := s.db.SetDomainBackups(id, req.ServerIDs, time.Now().UTC())
	switch {
	case errors.Is(err, db.ErrDomainNotFound):
		writeError(w, http.StatusNotFound, "domain not found")
		return
	case errors.Is(err, db.ErrInvalidBackups):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		log.Printf("backups: domain %d: %v", id, err)
		writeError(w, http.StatusInternalServerError, "failed to store backup servers")
		return
	}
	s.audit(r, "domain", strconv.FormatInt(id, 10), "backups_set", backupsAuditDetail(before, req.ServerIDs))

	for _, agentID := range removed {
		s.pushAgent(agentID)
	}
	after, _ := s.db.ListDomainBackups(id)
	for _, b := range after {
		s.pushAgent(b.AgentID)
	}
	// The DNS target may change at once, e.g. when the primary is down
	// already or the active backup was removed.
	s.triggerDNSReconcile(id)

	dom, err := s.db.GetDomain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	status, err := s.db.DomainFailoverStatus(dom, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read failover status")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func backupsAuditDetail(before []db.DomainBackup, after []string) string {
	prev := make([]string, 0, len(before))
	for _, b := range before {
		prev = append(prev, b.ServerID)
	}
	return fmt.Sprintf("backup servers: [%s] -> [%s]", strings.Join(prev, ", "), strings.Join(after, ", "))
}

// fillFailover adds backup servers and the active server to domains for the
// response. A read failure leaves the fields empty rather than failing the
// listing.
func (s *Server) fillFailover(doms []models.Domain) {
	if err := s.db.FillDomainFailover(doms); err != nil {
		log.Printf("domains: cannot read failover state: %v", err)
	}
}

// guardBackupServer refuses to delete a server that is a backup for other
// domains: the standby routes on its agent would be left behind. With
// cascade the server is taken out of those backup lists first, which
// tombstones the standby routes. It writes the response and returns true when
// deletion must abort.
func (s *Server) guardBackupServer(w http.ResponseWriter, serverID string, cascade bool) bool {
	ids, err := s.db.DomainsBackedByServer(serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check backup references")
		return true
	}
	if len(ids) == 0 {
		return false
	}
	if cascade {
		agents, err := s.db.RemoveServerFromBackups(serverID, time.Now().UTC())
		if err != nil {
			log.Printf("server delete: removing server %s from backup lists: %v", serverID, err)
			writeError(w, http.StatusInternalServerError, "failed to remove the server from backup lists")
			return true
		}
		for _, agentID := range agents {
			s.pushAgent(agentID)
		}
		for _, id := range ids {
			s.triggerDNSReconcile(id)
		}
		return false
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"error":          fmt.Sprintf("server is a backup for %d domain(s); remove it from their backup servers first", len(ids)),
		"backup_domains": ids,
	})
	return true
}

// validFailoverSetting checks the failover settings written through the
// settings endpoint.
func validFailoverSetting(key, value string) error {
	switch key {
	case "failover_grace", "failover_failback_delay":
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 || n > 86400 {
			return fmt.Errorf("%s must be a number of seconds between 0 and 86400", key)
		}
	case "failover_failback":
		if value != "true" && value != "false" {
			return fmt.Errorf("%s must be true or false", key)
		}
	}
	return nil
}
