package adoption

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/ddns"
	"github.com/NurRobin/NurProxy/internal/shared/auth"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/google/uuid"
)

// Manager handles agent registration and adoption with the orchestrator.
type Manager struct {
	orchestratorURL string
	fqdn            string
	token           string
	agentID         string
	dataDir         string
	apiPort         int
	version         string
	detection       *models.ProxyDetection
	capabilities    *models.ProxyCapabilities
	client          *http.Client
}

// registerRequest is the JSON body for POST /api/v1/agents/register.
type registerRequest struct {
	ID        string `json:"id"`
	FQDN      string `json:"fqdn"`
	Token     string `json:"token"`
	APIURL    string `json:"api_url"`
	PublicIP  string `json:"public_ip"`
	PublicIP6 string `json:"public_ip6,omitempty"`
	Version   string `json:"version"`
	// ProxyDetection is the agent's read-only Phase-0 detection (§13.0/§2.1/§9):
	// installed proxy + version + paths + bind-conflict holder. The agent dials
	// out and carries it here so the orchestrator can store it on the agent row.
	ProxyDetection *models.ProxyDetection `json:"proxy_detection,omitempty"`
	// ProxyCapabilities is the agent's capability matrix (§8) for its selected
	// backend, including module-probed options. Carried on the outbound register
	// payload so the orchestrator stores it from first contact.
	ProxyCapabilities *models.ProxyCapabilities `json:"proxy_capabilities,omitempty"`
}

// statusResponse is the JSON body from GET /api/v1/agents/{id}/status.
type statusResponse struct {
	Status string `json:"status"`
}

// New creates a Manager, loading or generating the agent token and ID.
func New(orchestratorURL, fqdn, dataDir string, apiPort int) (*Manager, error) {
	m := &Manager{
		orchestratorURL: strings.TrimRight(orchestratorURL, "/"),
		fqdn:            fqdn,
		dataDir:         dataDir,
		apiPort:         apiPort,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	token, err := m.loadOrGenerateToken()
	if err != nil {
		return nil, fmt.Errorf("loading token: %w", err)
	}
	m.token = token

	agentID, err := m.loadOrGenerateAgentID()
	if err != nil {
		return nil, fmt.Errorf("loading agent ID: %w", err)
	}
	m.agentID = agentID

	return m, nil
}

// SetVersion records the agent build version sent during registration.
func (m *Manager) SetVersion(v string) {
	m.version = v
}

// SetDetection records the read-only proxy detection result carried in the
// registration request, so the orchestrator can store it on the agent row from
// first contact (it is also refreshed on every heartbeat).
func (m *Manager) SetDetection(d *models.ProxyDetection) {
	m.detection = d
}

// SetCapabilities records the backend capability matrix (§8) carried in the
// registration request, so the orchestrator can store it on the agent row from
// first contact (it is also refreshed on every heartbeat).
func (m *Manager) SetCapabilities(c *models.ProxyCapabilities) {
	m.capabilities = c
}

// Token returns the agent token.
func (m *Manager) Token() string {
	return m.token
}

// AgentID returns the agent ID.
func (m *Manager) AgentID() string {
	return m.agentID
}

// Register sends a registration request to the orchestrator.
func (m *Manager) Register(ctx context.Context) error {
	publicIP, _ := detectPublicIPSimple(ctx)
	// IPv6 is best-effort and never gates registration; a v6-less host just omits
	// it. The heartbeat re-reports both families every beat regardless.
	publicIP6, _ := ddns.DetectPublicIP6(ctx)

	apiURL := fmt.Sprintf("http://%s:%d", m.fqdn, m.apiPort)
	if publicIP != "" {
		apiURL = fmt.Sprintf("http://%s:%d", publicIP, m.apiPort)
	}

	body := registerRequest{
		ID:                m.agentID,
		FQDN:              m.fqdn,
		Token:             m.token,
		APIURL:            apiURL,
		PublicIP:          publicIP,
		PublicIP6:         publicIP6,
		Version:           m.version,
		ProxyDetection:    m.detection,
		ProxyCapabilities: m.capabilities,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling register request: %w", err)
	}

	url := m.orchestratorURL + "/api/v1/agents/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending register request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	log.Printf("Registered agent %s with orchestrator", m.agentID)
	return nil
}

// WaitForAdoption polls the orchestrator until the agent is adopted.
func (m *Manager) WaitForAdoption(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/agents/%s/status", m.orchestratorURL, m.agentID)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Printf("Waiting for adoption... (agent ID: %s)", m.agentID)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := m.checkStatus(ctx, url)
			if err != nil {
				log.Printf("Error checking adoption status: %v", err)
				continue
			}

			if status != "pending" {
				log.Printf("Agent adopted (status: %s)", status)
				return nil
			}

			log.Printf("Waiting for adoption...")
		}
	}
}

func (m *Manager) checkStatus(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status check returned %d", resp.StatusCode)
	}

	var sr statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return "", fmt.Errorf("decoding status response: %w", err)
	}
	return sr.Status, nil
}

func (m *Manager) loadOrGenerateToken() (string, error) {
	tokenPath := filepath.Join(m.dataDir, "token")
	data, err := os.ReadFile(tokenPath)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token, nil
		}
	}

	token, err := auth.GenerateAgentToken()
	if err != nil {
		return "", fmt.Errorf("generating agent token: %w", err)
	}

	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("saving token: %w", err)
	}

	return token, nil
}

func (m *Manager) loadOrGenerateAgentID() (string, error) {
	idPath := filepath.Join(m.dataDir, "agent-id")
	data, err := os.ReadFile(idPath)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	}

	id := uuid.New().String()

	if err := os.WriteFile(idPath, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("saving agent ID: %w", err)
	}

	return id, nil
}

// detectPublicIPSimple is a minimal IP detection for the registration request.
// The full implementation lives in the ddns package.
func detectPublicIPSimple(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

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

		var buf [64]byte
		n, _ := resp.Body.Read(buf[:])
		if n > 0 {
			return strings.TrimSpace(string(buf[:n])), nil
		}
	}

	return "", fmt.Errorf("could not detect public IP")
}
