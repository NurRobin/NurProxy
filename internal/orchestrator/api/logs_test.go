package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/logbroker"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// startTailAgent registers an adopted agent that has reported a log path, and
// returns its token and the dashboard session cookie.
func startTailAgent(t *testing.T, srv *Server, database interface {
	CreateAgent(*models.Agent) error
	UpdateAgentDetection(string, *models.ProxyDetection) error
}, logPath string) (handler http.Handler, agentTok string, cookie *http.Cookie) {
	t.Helper()
	handler = srv.Handler()
	cookie = setupAdmin(t, handler)
	agentTok = makeAgent(t, database, "agent-1", "edge1.example.com", models.AgentStatusAdopted, nil)
	if err := database.UpdateAgentDetection("agent-1", &models.ProxyDetection{
		Installed: true,
		Kind:      "nginx",
		LogPaths:  []string{logPath},
	}); err != nil {
		t.Fatalf("UpdateAgentDetection: %v", err)
	}
	return handler, agentTok, cookie
}

func TestLogTail_endToEnd_startChunkPollStop(t *testing.T) {
	srv, database := testServer(t)
	hub := agenthub.New()
	srv.SetAgentHub(hub, &stubPusher{hub: hub})
	handler, agentTok, cookie := startTailAgent(t, srv, database, "/var/log/nginx/access.log")

	// The agent must be "connected" for a start to succeed: subscribe a fake conn.
	events, unsub := hub.Subscribe("agent-1")
	defer unsub()

	// Dashboard opens the tail.
	w := doRequest(t, handler, "POST", "/api/v1/agents/agent-1/logs/tail",
		map[string]any{"path": "/var/log/nginx/access.log"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("start tail = %d %s", w.Code, w.Body.String())
	}
	var startResp struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	if startResp.SessionID == "" {
		t.Fatal("start did not return a session id")
	}
	// A log_tail event must have been pushed down the agent stream.
	select {
	case ev := <-events:
		if ev.Type != agenthub.EventLogTail {
			t.Fatalf("pushed event type = %q, want %q", ev.Type, agenthub.EventLogTail)
		}
	default:
		t.Fatal("no log_tail event pushed to the agent")
	}

	// The agent posts a chunk (agent auth).
	w = doRequestWithAuth(t, handler, "POST", "/api/v1/agents/agent-1/logs/chunk",
		map[string]any{"session_id": startResp.SessionID, "lines": []string{"hello", "world"}}, agentTok)
	if w.Code != http.StatusOK {
		t.Fatalf("post chunk = %d %s", w.Code, w.Body.String())
	}

	// The dashboard polls and sees the lines.
	w = doRequest(t, handler, "GET",
		"/api/v1/agents/agent-1/logs/tail/"+startResp.SessionID+"?cursor=0", nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("poll = %d %s", w.Code, w.Body.String())
	}
	var poll logbroker.Poll
	if err := json.Unmarshal(w.Body.Bytes(), &poll); err != nil {
		t.Fatal(err)
	}
	if len(poll.Lines) != 2 || poll.Lines[0].Text != "hello" || poll.Lines[1].Text != "world" {
		t.Fatalf("poll lines = %+v, want [hello world]", poll.Lines)
	}

	// Closing the view stops the session and pushes a stop event.
	w = doRequest(t, handler, "DELETE",
		"/api/v1/agents/agent-1/logs/tail/"+startResp.SessionID, nil, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("stop = %d %s", w.Code, w.Body.String())
	}
	select {
	case ev := <-events:
		if ev.Type != agenthub.EventLogTailStop {
			t.Fatalf("stop event type = %q, want %q", ev.Type, agenthub.EventLogTailStop)
		}
	default:
		t.Fatal("no log_tail_stop event pushed to the agent")
	}
}

func TestLogTail_start_refusesUnknownPath(t *testing.T) {
	srv, database := testServer(t)
	hub := agenthub.New()
	srv.SetAgentHub(hub, &stubPusher{hub: hub})
	handler, _, cookie := startTailAgent(t, srv, database, "/var/log/nginx/access.log")
	_, unsub := hub.Subscribe("agent-1")
	defer unsub()

	w := doRequest(t, handler, "POST", "/api/v1/agents/agent-1/logs/tail",
		map[string]any{"path": "/etc/passwd"}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tailing an unreported path = %d, want 403", w.Code)
	}
}

func TestLogTail_start_disconnectedAgentConflicts(t *testing.T) {
	srv, database := testServer(t)
	hub := agenthub.New()
	srv.SetAgentHub(hub, &stubPusher{hub: hub})
	handler, _, cookie := startTailAgent(t, srv, database, "/var/log/nginx/access.log")
	// No Subscribe: the agent is not connected.

	w := doRequest(t, handler, "POST", "/api/v1/agents/agent-1/logs/tail",
		map[string]any{"path": "/var/log/nginx/access.log"}, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("tail on a disconnected agent = %d, want 409", w.Code)
	}
}

func TestLogChunk_unknownSession_tellsAgentToStop(t *testing.T) {
	srv, database := testServer(t)
	hub := agenthub.New()
	srv.SetAgentHub(hub, &stubPusher{hub: hub})
	handler, agentTok, _ := startTailAgent(t, srv, database, "/var/log/nginx/access.log")
	events, unsub := hub.Subscribe("agent-1")
	defer unsub()

	w := doRequestWithAuth(t, handler, "POST", "/api/v1/agents/agent-1/logs/chunk",
		map[string]any{"session_id": "ghost", "lines": []string{"x"}}, agentTok)
	if w.Code != http.StatusOK {
		t.Fatalf("chunk for unknown session = %d %s", w.Code, w.Body.String())
	}
	select {
	case ev := <-events:
		if ev.Type != agenthub.EventLogTailStop {
			t.Fatalf("event = %q, want a stop for the orphaned tail", ev.Type)
		}
	default:
		t.Fatal("expected a stop event for the orphaned tail")
	}
}
