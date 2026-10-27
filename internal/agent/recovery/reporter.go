package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
			return &ReportHTTPError{StatusCode: resp.StatusCode}
		}
		return nil
	}
}

type ReportHTTPError struct{ StatusCode int }

func (e *ReportHTTPError) Error() string {
	return fmt.Sprintf("recovery report returned status %d", e.StatusCode)
}
func (e *ReportHTTPError) Retryable() bool {
	return e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

type queuedReport struct {
	key           string
	report        proxymodel.RecoveryReport
	diagnosticSeq uint64
}

// BoundedReporter keeps recovery telemetry bounded while preserving every
// admitted operation's ordered state sequence through its terminal outcome.
type BoundedReporter struct {
	mu                sync.Mutex
	limit             int
	queue             []queuedReport
	keys              map[string]struct{}
	sent              map[string]struct{}
	sentOrder         []string
	operations        map[string]operationLane
	diagnosticPending map[string]int
	nextDiagnosticSeq uint64
	sender            ReportSender
	backoff           time.Duration
}

func NewBoundedReporter(limit int, sender ReportSender) *BoundedReporter {
	if limit < 1 {
		limit = 1
	}
	return &BoundedReporter{limit: limit, keys: make(map[string]struct{}), sent: make(map[string]struct{}), operations: make(map[string]operationLane), diagnosticPending: make(map[string]int), sender: sender, backoff: time.Second}
}

type operationLane struct {
	pending     int
	terminal    bool
	quarantined bool
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
	item := queuedReport{key: reportKey(report), report: report}
	if item.key == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if report.Diagnostics != nil {
		r.nextDiagnosticSeq++
		item.diagnosticSeq = r.nextDiagnosticSeq
	}
	if report.Diagnostics != nil && len(report.Operations) == 0 && report.Capability == nil {
		for i := len(r.queue) - 1; i >= 0; i-- {
			if reportOperationID(r.queue[i].report) != "" {
				break
			}
			if strings.HasPrefix(r.queue[i].key, "diagnostic-snapshot:") {
				r.releasePendingDiagnostics(r.queue[i].report)
				delete(r.keys, r.queue[i].key)
				r.queue = append(r.queue[:i], r.queue[i+1:]...)
			}
		}
	}
	if _, duplicate := r.keys[item.key]; duplicate {
		return true
	}
	if _, delivered := r.sent[item.key]; delivered && report.Diagnostics == nil {
		return true
	}
	opID := reportOperationID(report)
	if opID != "" {
		if _, admitted := r.operations[opID]; !admitted && len(r.operations) >= r.limit {
			return false
		}
	} else if report.Diagnostics == nil && report.Capability == nil && len(r.queue) >= r.limit {
		return false
	}
	r.queue = append(r.queue, item)
	r.keys[item.key] = struct{}{}
	if opID != "" {
		lane := r.operations[opID]
		lane.pending++
		lane.terminal = lane.terminal || terminalOperationReport(report)
		r.operations[opID] = lane
	} else if report.Diagnostics != nil {
		r.addPendingDiagnostics(report)
	}
	return true
}

func (r *BoundedReporter) Flush(ctx context.Context) error {
	if r == nil || r.sender == nil {
		return fmt.Errorf("recovery reporter is not configured")
	}
	r.mu.Lock()
	remaining := len(r.queue)
	r.mu.Unlock()
	var failures []error
	blockedOperations := make(map[string]struct{})
	for remaining > 0 {
		remaining--
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.mu.Unlock()
			return nil
		}
		item := r.queue[0]
		backoff := r.backoff
		opID := reportOperationID(item.report)
		lane := r.operations[opID]
		_, blocked := blockedOperations[opID]
		diagnosticBlocked := opID != "" && r.diagnosticPending[item.report.Operations[0].DiagnosticID] > 0
		diagnosticOutOfOrder := item.diagnosticSeq != 0 && item.diagnosticSeq != earliestDiagnosticSequence(r.queue)
		if (opID != "" && (blocked || lane.quarantined || diagnosticBlocked)) || diagnosticOutOfOrder {
			r.queue = append(r.queue[1:], item)
			r.mu.Unlock()
			continue
		}
		r.mu.Unlock()

		var err error
		attempts := 5
		for attempt := 0; attempt < attempts; attempt++ {
			if err = r.sender(ctx, item.report); err == nil {
				break
			}
			var status *ReportHTTPError
			if errors.As(err, &status) && !status.Retryable() {
				break
			}
			if attempt == attempts-1 {
				break
			}
			delay := backoff << attempt
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		r.mu.Lock()
		if len(r.queue) > 0 && r.queue[0].key == item.key {
			if err == nil {
				r.queue = r.queue[1:]
				delete(r.keys, item.key)
				if item.report.Diagnostics == nil {
					r.sent[item.key] = struct{}{}
					r.sentOrder = append(r.sentOrder, item.key)
				} else {
					r.releasePendingDiagnostics(item.report)
				}
				if opID := reportOperationID(item.report); opID != "" {
					lane := r.operations[opID]
					lane.pending--
					if lane.pending == 0 && lane.terminal {
						delete(r.operations, opID)
					} else {
						r.operations[opID] = lane
					}
				}
				if len(r.sentOrder) > r.limit*8 {
					delete(r.sent, r.sentOrder[0])
					r.sentOrder = r.sentOrder[1:]
				}
			} else {
				if opID != "" {
					blockedOperations[opID] = struct{}{}
					var status *ReportHTTPError
					if errors.As(err, &status) && !status.Retryable() {
						lane := r.operations[opID]
						lane.quarantined = true
						r.operations[opID] = lane
					}
				}
				r.queue = append(r.queue[1:], item)
			}
		}
		r.mu.Unlock()
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func earliestDiagnosticSequence(queue []queuedReport) uint64 {
	var earliest uint64
	for _, item := range queue {
		if item.diagnosticSeq != 0 && (earliest == 0 || item.diagnosticSeq < earliest) {
			earliest = item.diagnosticSeq
		}
	}
	return earliest
}

func (r *BoundedReporter) addPendingDiagnostics(report proxymodel.RecoveryReport) {
	for _, diagnostic := range report.Diagnostics {
		r.diagnosticPending[diagnostic.ID]++
	}
}

func (r *BoundedReporter) releasePendingDiagnostics(report proxymodel.RecoveryReport) {
	for _, diagnostic := range report.Diagnostics {
		r.diagnosticPending[diagnostic.ID]--
		if r.diagnosticPending[diagnostic.ID] <= 0 {
			delete(r.diagnosticPending, diagnostic.ID)
		}
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
	if report.Diagnostics != nil && len(report.Operations) == 0 && report.Capability == nil {
		return "diagnostic-snapshot:" + diagnosticSnapshotKey(report.Diagnostics)
	}
	if report.Capability != nil && len(report.Diagnostics) == 0 && len(report.Operations) == 0 {
		return "capability"
	}
	return ""
}

func reportOperationID(report proxymodel.RecoveryReport) string {
	if len(report.Operations) == 1 && len(report.Diagnostics) == 0 && report.Capability == nil {
		return report.Operations[0].OperationID
	}
	return ""
}

func diagnosticSnapshotKey(diagnostics []recoverymodel.Diagnostic) string {
	var b strings.Builder
	for _, diagnostic := range diagnostics {
		fmt.Fprintf(&b, "%s:%d;", diagnostic.ID, diagnostic.Occurrences)
	}
	return b.String()
}

func terminalOperationReport(report proxymodel.RecoveryReport) bool {
	if len(report.Operations) != 1 {
		return false
	}
	switch report.Operations[0].State {
	case recoverymodel.OperationStateSucceeded, recoverymodel.OperationStateRolledBack,
		recoverymodel.OperationStateRollbackFailed, recoverymodel.OperationStateDiagnosisOnly,
		recoverymodel.OperationStateSuppressed:
		return true
	default:
		return false
	}
}
