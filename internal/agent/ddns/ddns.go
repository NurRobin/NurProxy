package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Heartbeat periodically sends heartbeats with the agent's public IP to the
// orchestrator.
type Heartbeat struct {
	orchestratorURL string
	agentID         string
	token           string
	version         string
	interval        time.Duration
	client          *http.Client
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// heartbeatPayload is the JSON body sent to the orchestrator.
type heartbeatPayload struct {
	AgentID  string `json:"agent_id"`
	PublicIP string `json:"public_ip"`
	Version  string `json:"version"`
}

// New creates a new Heartbeat sender.
func New(orchestratorURL, agentID, token, version string, interval time.Duration) *Heartbeat {
	return &Heartbeat{
		orchestratorURL: strings.TrimRight(orchestratorURL, "/"),
		agentID:         agentID,
		token:           token,
		version:         version,
		interval:        interval,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Start begins the heartbeat loop. It blocks until the context is canceled.
func (h *Heartbeat) Start(ctx context.Context) {
	ctx, h.cancel = context.WithCancel(ctx)
	h.wg.Add(1)

	go func() {
		defer h.wg.Done()

		// Send initial heartbeat immediately.
		h.sendHeartbeat(ctx)

		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.sendHeartbeat(ctx)
			}
		}
	}()
}

// Stop cancels the heartbeat loop and waits for it to finish.
func (h *Heartbeat) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
	h.wg.Wait()
}

func (h *Heartbeat) sendHeartbeat(ctx context.Context) {
	ip, err := DetectPublicIP(ctx)
	if err != nil {
		log.Printf("Heartbeat: failed to detect public IP: %v", err)
		return
	}

	payload := heartbeatPayload{
		AgentID:  h.agentID,
		PublicIP: ip,
		Version:  h.version,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Heartbeat: failed to marshal payload: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/heartbeat", h.orchestratorURL, h.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		log.Printf("Heartbeat: failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token)

	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("Heartbeat: failed to send: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Heartbeat: orchestrator returned status %d", resp.StatusCode)
		return
	}

	log.Printf("Heartbeat sent (IP: %s)", ip)
}

// defaultServices is the list of public IP detection services.
var defaultServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

// DetectPublicIP tries multiple services to determine the agent's public IP.
func DetectPublicIP(ctx context.Context) (string, error) {
	return detectPublicIPFromServices(ctx, defaultServices)
}

// detectPublicIPFromServices queries the given services in order and returns
// the first successfully detected IP.
func detectPublicIPFromServices(ctx context.Context, services []string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	for _, svc := range services {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var buf [64]byte
		n, _ := resp.Body.Read(buf[:])
		if n > 0 {
			return strings.TrimSpace(string(buf[:n])), nil
		}
	}

	return "", fmt.Errorf("all IP detection services failed")
}
