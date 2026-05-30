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
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
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
	modeFn          func() string
	detectionFn     func() *models.ProxyDetection
	capabilitiesFn  func() *models.ProxyCapabilities
	checksumsFn     func() []proxymodel.ArtifactChecksum
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
	// ProxyMode re-reports the agent's CURRENT live reverse-proxy mode ("built-in"
	// | "existing") on every beat (§19) so the orchestrator/dashboard reflect a
	// hot-switch. Omitted when unknown (the orchestrator keeps the stored value).
	ProxyMode string `json:"proxy_mode,omitempty"`
	// ProxyDetection re-reports the read-only Phase-0 detection on every beat
	// (§13.0/§2.1/§9) so the orchestrator's stored copy stays fresh as the host
	// changes (e.g. an Existing proxy stops releasing :443). Omitted when unknown.
	ProxyDetection *models.ProxyDetection `json:"proxy_detection,omitempty"`
	// ProxyCapabilities re-reports the backend capability matrix (§8) on every beat
	// so the orchestrator's stored copy tracks module changes (e.g. caddy-ratelimit
	// installed/removed). Omitted when unknown.
	ProxyCapabilities *models.ProxyCapabilities `json:"proxy_capabilities,omitempty"`
	// ArtifactChecksums reports each managed artifact's current on-disk/live
	// checksum (§11) so the orchestrator can detect drift against the accepted
	// state. Omitted when the agent manages nothing.
	ArtifactChecksums []proxymodel.ArtifactChecksum `json:"artifact_checksums,omitempty"`
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

// SetModeFn supplies the agent's current live reverse-proxy mode ("built-in" |
// "existing") reported on each beat (§19). It may be nil (no mode sent). The
// function is called per beat so a §19 hot-switch is reflected on the next beat
// without restarting the heartbeat.
func (h *Heartbeat) SetModeFn(fn func() string) {
	h.modeFn = fn
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

// SetArtifactChecksumsFn supplies the managed-artifact checksum snapshot (§11)
// reported on each beat for drift detection. It may be nil (no checksums sent).
// The function is called per beat so the agent reports its current live set
// without restarting the heartbeat.
func (h *Heartbeat) SetArtifactChecksumsFn(fn func() []proxymodel.ArtifactChecksum) {
	h.checksumsFn = fn
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

	var mode string
	if h.modeFn != nil {
		mode = h.modeFn()
	}

	var detection *models.ProxyDetection
	if h.detectionFn != nil {
		detection = h.detectionFn()
	}

	var capabilities *models.ProxyCapabilities
	if h.capabilitiesFn != nil {
		capabilities = h.capabilitiesFn()
	}

	var checksums []proxymodel.ArtifactChecksum
	if h.checksumsFn != nil {
		checksums = h.checksumsFn()
	}

	payload := heartbeatPayload{
		AgentID:           h.agentID,
		PublicIP:          ip,
		Version:           h.version,
		CaddyRunning:      caddyRunning,
		LastError:         lastError,
		ProxyMode:         mode,
		ProxyDetection:    detection,
		ProxyCapabilities: capabilities,
		ArtifactChecksums: checksums,
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
