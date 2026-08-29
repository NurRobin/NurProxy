package recoverycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/helperclient"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const maxResponseBytes = 2 << 20

type HTTP struct {
	baseURL string
	agentID string
	token   string
	client  *http.Client
}

type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("recovery control request returned status %d", e.StatusCode)
}

func (e *HTTPError) Retryable() bool {
	return e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

func NewHTTP(orchestratorURL, agentID, token string, client *http.Client) (*HTTP, error) {
	parsed, err := url.Parse(strings.TrimRight(orchestratorURL, "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.TrimSpace(agentID) == "" || strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("invalid recovery control HTTP configuration")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &HTTP{baseURL: strings.TrimRight(parsed.String(), "/"), agentID: agentID, token: token, client: client}, nil
}

func (h *HTTP) HelperPin(ctx context.Context) (helperclient.Pin, error) {
	var response struct {
		AgentID              string `json:"agent_id"`
		HelperInstanceID     string `json:"helper_instance_id"`
		HelperBuildID        string `json:"helper_build_id"`
		AttestationKeyID     string `json:"attestation_key_id"`
		AttestationPublicKey string `json:"attestation_public_key"`
		HelloDigest          string `json:"hello_digest"`
		EnrolledAt           string `json:"enrolled_at"`
	}
	if err := h.getJSON(ctx, h.basePath()+"/helper", &response); err != nil {
		return helperclient.Pin{}, err
	}
	pin := helperclient.Pin{
		HelperInstanceID: response.HelperInstanceID, AttestationKeyID: response.AttestationKeyID,
		AttestationPublicKey: response.AttestationPublicKey,
	}
	if response.AgentID != h.agentID || pin.Validate() != nil {
		return helperclient.Pin{}, fmt.Errorf("orchestrator returned an invalid helper enrollment pin")
	}
	return pin, nil
}

func (h *HTTP) ListPlans(ctx context.Context) ([]ExecutionRecord, error) {
	records := make([]ExecutionRecord, 0)
	if err := h.getJSON(ctx, h.basePath()+"/plans", &records); err != nil {
		return nil, err
	}
	if len(records) > 256 {
		return nil, fmt.Errorf("orchestrator returned too many recovery execution plans")
	}
	return records, nil
}

func (h *HTTP) SubmitPlan(ctx context.Context, plan helperprotocol.Signed[helperprotocol.HelperPlan]) error {
	return h.postJSON(ctx, h.basePath()+"/plans", plan, http.StatusOK, http.StatusCreated)
}

func (h *HTTP) SubmitReceipt(ctx context.Context, helperPlanID string, receipt helperprotocol.Signed[helperprotocol.HelperReceipt]) error {
	if strings.TrimSpace(helperPlanID) == "" || strings.Contains(helperPlanID, "/") {
		return fmt.Errorf("invalid helper plan identity")
	}
	return h.postJSON(ctx, h.basePath()+"/plans/"+url.PathEscape(helperPlanID)+"/receipt", receipt, http.StatusNoContent)
}

func (h *HTTP) basePath() string {
	return "/api/v1/agents/" + url.PathEscape(h.agentID) + "/recovery"
}

func (h *HTTP) getJSON(ctx context.Context, path string, destination any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+path, nil)
	if err != nil {
		return err
	}
	h.authorize(req)
	response, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &HTTPError{StatusCode: response.StatusCode}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maxResponseBytes {
		return fmt.Errorf("invalid bounded recovery control response")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode recovery control response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("recovery control response contains trailing data")
	}
	return nil
}

func (h *HTTP) postJSON(ctx context.Context, path string, value any, accepted ...int) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > helperprotocol.MaxFrameBytes {
		return fmt.Errorf("encode bounded recovery control request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	h.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	response, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	for _, status := range accepted {
		if response.StatusCode == status {
			return nil
		}
	}
	return &HTTPError{StatusCode: response.StatusCode}
}

func (h *HTTP) authorize(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+h.token)
}
