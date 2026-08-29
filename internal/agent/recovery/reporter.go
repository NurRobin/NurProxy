package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type ReportQueue interface {
	Enqueue(proxymodel.RecoveryReport) bool
}

type ReportSender func(context.Context, proxymodel.RecoveryReport) error

func NewHTTPReportSender(orchestratorURL, agentID, token string, client *http.Client) ReportSender {
	base := strings.TrimRight(orchestratorURL, "/")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return func(ctx context.Context, report proxymodel.RecoveryReport) error {
		envelope := proxymodel.RecoveryReportEnvelope{Report: report}
		if err := envelope.Validate(); err != nil {
			return err
		}
		body, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		url := fmt.Sprintf("%s/api/v1/agents/%s/recovery/report", base, agentID)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("recovery report returned status %d", resp.StatusCode)
		}
		return nil
	}
}

type queuedReport struct {
	key    string
	report proxymodel.RecoveryReport
	final  bool
}

// BoundedReporter keeps recovery telemetry bounded while the orchestrator is
// unreachable. Terminal failures displace progress records so the outcome that
// needs operator attention is not lost behind transient state updates.
type BoundedReporter struct {
	mu        sync.Mutex
	limit     int
	queue     []queuedReport
	keys      map[string]struct{}
	sent      map[string]struct{}
	sentOrder []string
	sender    ReportSender
	backoff   time.Duration
}

func NewBoundedReporter(limit int, sender ReportSender) *BoundedReporter {
	if limit < 1 {
		limit = 1
	}
	return &BoundedReporter{limit: limit, keys: make(map[string]struct{}), sent: make(map[string]struct{}), sender: sender, backoff: time.Second}
}

func (r *BoundedReporter) SetBackoff(backoff time.Duration) {
	if r == nil || backoff <= 0 {
		return
	}
	r.mu.Lock()
	r.backoff = backoff
	r.mu.Unlock()
}

func (r *BoundedReporter) Enqueue(report proxymodel.RecoveryReport) bool {
	if r == nil || r.sender == nil || (proxymodel.RecoveryReportEnvelope{Report: report}).Validate() != nil {
		return false
	}
	item := queuedReport{key: reportKey(report), report: report, final: finalFailureReport(report)}
	if item.key == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.keys[item.key]; duplicate {
		return true
	}
	if _, delivered := r.sent[item.key]; delivered {
		return true
	}
	if len(r.queue) >= r.limit {
		drop := -1
		if item.final {
			for i := range r.queue {
				if !r.queue[i].final {
					drop = i
					break
				}
			}
		}
		if drop < 0 {
			return false
		}
		delete(r.keys, r.queue[drop].key)
		r.queue = append(r.queue[:drop], r.queue[drop+1:]...)
	}
	r.queue = append(r.queue, item)
	r.keys[item.key] = struct{}{}
	return true
}

func (r *BoundedReporter) Flush(ctx context.Context) error {
	if r == nil || r.sender == nil {
		return fmt.Errorf("recovery reporter is not configured")
	}
	for {
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.mu.Unlock()
			return nil
		}
		item := r.queue[0]
		backoff := r.backoff
		r.mu.Unlock()

		var err error
		for attempt := 0; attempt < 5; attempt++ {
			if err = r.sender(ctx, item.report); err == nil {
				break
			}
			delay := backoff << attempt
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		if err != nil {
			return err
		}
		r.mu.Lock()
		if len(r.queue) > 0 && r.queue[0].key == item.key {
			r.queue = r.queue[1:]
			delete(r.keys, item.key)
			r.sent[item.key] = struct{}{}
			r.sentOrder = append(r.sentOrder, item.key)
			if len(r.sentOrder) > r.limit {
				delete(r.sent, r.sentOrder[0])
				r.sentOrder = r.sentOrder[1:]
			}
		}
		r.mu.Unlock()
	}
}

func (r *BoundedReporter) Run(ctx context.Context) {
	for ctx.Err() == nil {
		_ = r.Flush(ctx)
		r.mu.Lock()
		backoff := r.backoff
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func reportKey(report proxymodel.RecoveryReport) string {
	if len(report.Operations) == 1 && len(report.Diagnostics) == 0 {
		op := report.Operations[0]
		return "operation:" + op.OperationID + ":" + string(op.State)
	}
	if len(report.Diagnostics) == 1 && len(report.Operations) == 0 {
		d := report.Diagnostics[0]
		return fmt.Sprintf("diagnostic:%s:%d", d.ID, d.Occurrences)
	}
	if report.Capability != nil && len(report.Diagnostics) == 0 && len(report.Operations) == 0 {
		return "capability"
	}
	return ""
}

func finalFailureReport(report proxymodel.RecoveryReport) bool {
	if len(report.Operations) != 1 {
		return false
	}
	switch report.Operations[0].State {
	case recoverymodel.OperationStateRolledBack, recoverymodel.OperationStateRollbackFailed:
		return true
	default:
		return false
	}
}
