package stream

// report.go carries the agent's outbound report of the config artifacts it READ
// off the host (the operator's existing nginx/apache config) into the
// orchestrator's central versioned store (§17 "adoption reads all files"). This
// is independent of the apply path: the agent reports what it can read even when
// it cannot reload the service, so a limited-permission agent still surfaces the
// host's config under Config. The agent dials out (control-plane invariant #2:
// never inbound).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// ReportAdopted POSTs the artifacts the agent read off the host into the central
// store so they appear under Config — even before NurProxy applies any domain,
// and even when the agent lacks reload permission (reading is enough). It maps
// each proxy.Artifact (Target{Kind,Path} + Content) to the wire shape, deriving a
// stable ID from backend+path so re-reports upsert the same row. Best-effort and
// idempotent: an empty set is a no-op; the call returns an error the caller logs
// without crashing (mirrors the never-die-on-host-problems posture).
func (c *Client) ReportAdopted(ctx context.Context, host, backend string, arts []proxy.Artifact) error {
	if len(arts) == 0 {
		return nil
	}

	out := make([]proxymodel.AdoptedArtifact, 0, len(arts))
	for _, a := range arts {
		out = append(out, proxymodel.AdoptedArtifact{
			ArtifactID: proxymodel.AdoptedArtifactID(backend, a.Target.Path),
			Backend:    backend,
			TargetKind: string(a.Target.Kind),
			TargetPath: a.Target.Path,
			Content:    a.Content,
			Checksum:   checksum(a.Content),
			Enabled:    a.Enabled,
			Adopted:    a.Adopted,
		})
	}

	body, err := json.Marshal(proxymodel.AdoptedArtifactReport{Host: host, Artifacts: out})
	if err != nil {
		return fmt.Errorf("marshaling adopted artifacts: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/artifacts/adopt", c.orchestratorURL, c.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building adopted-artifact request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("sending adopted-artifact report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("adopted-artifact report returned status %d", resp.StatusCode)
	}
	return nil
}
