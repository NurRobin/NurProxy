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

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// Heartbeat periodically sends heartbeats with the agent's public IP to the
// orchestrator.
type Heartbeat struct {
	orchestratorURL string
	agentID         string
	token           string
	version         string
	interval        time.Duration
	healthFn        func() (caddyRunning bool, lastError string)
	detectionFn     func() *models.ProxyDetection
	capabilitiesFn  func() *models.ProxyCapabilities
	client          *http.Client
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// heartbeatPayload is the JSON body sent to the orchestrator.
type heartbeatPayload struct {
	AgentID      string `json:"agent_id"`
	PublicIP     string `json:"public_ip"`
	Version      string `json:"version"`
	CaddyRunning bool   `json:"caddy_running"`
	LastError    string `json:"last_error"`
	// ProxyDetection re-reports the read-only Phase-0 detection on every beat
	// (§13.0/§2.1/§9) so the orchestrator's stored copy stays fresh as the host
	// changes (e.g. an Existing proxy stops releasing :443). Omitted when unknown.
	ProxyDetection *models.ProxyDetection `json:"proxy_detection,omitempty"`
	// ProxyCapabilities re-reports the backend capability matrix (§8) on every beat
	// so the orchestrator's stored copy tracks module changes (e.g. caddy-ratelimit
	// installed/removed). Omitted when unknown.
	ProxyCapabilities *models.ProxyCapabilities `json:"proxy_capabilities,omitempty"`
}

// New creates a new Heartbeat sender. healthFn supplies the agent's current
// operational state (Caddy running? last error?) on each beat; it may be nil,
// in which case the agent is reported as healthy.
func New(orchestratorURL, agentID, token, version string, interval time.Duration, healthFn func() (bool, string)) *Heartbeat {
	return &Heartbeat{
		orchestratorURL: strings.TrimRight(orchestratorURL, "/"),
		agentID:         agentID,
		token:           token,
		version:         version,
		interval:        interval,
		healthFn:        healthFn,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SetDetectionFn supplies the read-only proxy detection re-reported on each beat.
// It may be nil (no detection sent). The function is called per beat so the
// agent can refresh detection over time without restarting the heartbeat.
func (h *Heartbeat) SetDetectionFn(fn func() *models.ProxyDetection) {
	h.detectionFn = fn
}

// SetCapabilitiesFn supplies the backend capability matrix (§8) re-reported on
// each beat. It may be nil (no capabilities sent). The function is called per
// beat so the agent can refresh capabilities over time (e.g. after a module is
// installed) without restarting the heartbeat.
func (h *Heartbeat) SetCapabilitiesFn(fn func() *models.ProxyCapabilities) {
	h.capabilitiesFn = fn
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
	caddyRunning, lastError := true, ""
	if h.healthFn != nil {
		caddyRunning, lastError = h.healthFn()
	}

	// A failed IP lookup must not skip the heartbeat: liveness and health
	// reporting matter even when we can't refresh the public IP. Send a blank IP
	// (the orchestrator keeps the last known value) and carry on.
	ip, err := DetectPublicIP(ctx)
	if err != nil {
		log.Printf("Heartbeat: failed to detect public IP: %v", err)
		ip = ""
	}

	var detection *models.ProxyDetection
	if h.detectionFn != nil {
		detection = h.detectionFn()
	}

	var capabilities *models.ProxyCapabilities
	if h.capabilitiesFn != nil {
		capabilities = h.capabilitiesFn()
	}

	payload := heartbeatPayload{
		AgentID:           h.agentID,
		PublicIP:          ip,
		Version:           h.version,
		CaddyRunning:      caddyRunning,
		LastError:         lastError,
		ProxyDetection:    detection,
		ProxyCapabilities: capabilities,
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
