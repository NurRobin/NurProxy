package recoverycontrol

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverypolicy"
)

type Helper interface {
	Plan(context.Context, helperprotocol.Action, helperprotocol.LogicalTarget, string) (helperprotocol.Signed[helperprotocol.HelperPlan], error)
	Execute(context.Context, helperprotocol.Signed[helperprotocol.ExecutionGrant]) (helperprotocol.Signed[helperprotocol.HelperReceipt], string, error)
	GetReceipt(context.Context, string, string) (helperprotocol.Signed[helperprotocol.HelperReceipt], error)
}

type Orchestrator interface {
	ListPlans(context.Context) ([]ExecutionRecord, error)
	SubmitPlan(context.Context, helperprotocol.Signed[helperprotocol.HelperPlan]) error
	SubmitReceipt(context.Context, string, helperprotocol.Signed[helperprotocol.HelperReceipt]) error
}

type ExecutionRecord struct {
	HelperPlanID        string                                                `json:"helper_plan_id"`
	DiagnosticID        string                                                `json:"diagnostic_id"`
	Action              helperprotocol.Action                                 `json:"action"`
	ResourceFingerprint string                                                `json:"resource_fingerprint"`
	ExpiresAt           time.Time                                             `json:"expires_at"`
	SignedGrant         *helperprotocol.Signed[helperprotocol.ExecutionGrant] `json:"signed_execution_grant,omitempty"`
	SignedReceipt       *helperprotocol.Signed[helperprotocol.HelperReceipt]  `json:"signed_helper_receipt,omitempty"`
}

type Controller struct {
	mu      sync.Mutex
	helper  Helper
	remote  Orchestrator
	now     func() time.Time
	pending map[string]helperprotocol.Signed[helperprotocol.HelperPlan]
}

func New(helper Helper, remote Orchestrator) *Controller {
	return &Controller{helper: helper, remote: remote, now: func() time.Time { return time.Now().UTC() }, pending: make(map[string]helperprotocol.Signed[helperprotocol.HelperPlan])}
}

func (c *Controller) Reconcile(ctx context.Context, diagnostics []recoverymodel.Diagnostic) error {
	if c == nil || c.helper == nil || c.remote == nil {
		return fmt.Errorf("hard recovery controller is not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	records, err := c.remote.ListPlans(ctx)
	if err != nil {
		return err
	}
	now := c.now().UTC()
	var failures []error
	for _, record := range records {
		if record.SignedGrant == nil || record.SignedReceipt != nil {
			continue
		}
		grant := record.SignedGrant.Envelope.Payload
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
		if parseErr != nil || !now.Before(expiresAt) {
			continue
		}
		receipt, requestDigest, executeErr := c.helper.Execute(ctx, *record.SignedGrant)
		if executeErr != nil && requestDigest != "" {
			recovered, receiptErr := c.helper.GetReceipt(ctx, grant.OperationID, requestDigest)
			if receiptErr == nil {
				receipt, executeErr = recovered, nil
			} else {
				executeErr = errors.Join(executeErr, receiptErr)
			}
		}
		if executeErr != nil {
			failures = append(failures, fmt.Errorf("execute helper plan %s: %w", record.HelperPlanID, executeErr))
			continue
		}
		if err := c.remote.SubmitReceipt(ctx, record.HelperPlanID, receipt); err != nil {
			failures = append(failures, fmt.Errorf("submit helper receipt %s: %w", record.HelperPlanID, err))
		}
	}
	for _, diagnostic := range diagnostics {
		if !diagnostic.HardChange || !diagnostic.RepairEligible {
			continue
		}
		action, target, ok := recoverypolicy.HardActionForDiagnostic(diagnostic.Code, diagnostic.RepairScope)
		if !ok {
			continue
		}
		if activeRecord(records, diagnostic, now) {
			delete(c.pending, diagnostic.ID)
			continue
		}
		if pending, exists := c.pending[diagnostic.ID]; exists {
			payload := pending.Envelope.Payload
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
			if parseErr == nil && now.Before(expiresAt) && payload.Action == action && payload.LogicalTarget == target && payload.ResourceFingerprint == diagnostic.ResourceFingerprint {
				if err := c.remote.SubmitPlan(ctx, pending); err != nil {
					failures = append(failures, fmt.Errorf("resubmit helper plan %s: %w", payload.HelperPlanID, err))
				} else {
					delete(c.pending, diagnostic.ID)
				}
				continue
			}
			delete(c.pending, diagnostic.ID)
		}
		plan, err := c.helper.Plan(ctx, action, target, diagnostic.ID)
		if err != nil {
			failures = append(failures, fmt.Errorf("plan hard diagnostic %s: %w", diagnostic.ID, err))
			continue
		}
		payload := plan.Envelope.Payload
		if payload.DiagnosticID != diagnostic.ID || payload.Action != action || payload.LogicalTarget != target ||
			payload.ResourceFingerprint != diagnostic.ResourceFingerprint {
			failures = append(failures, fmt.Errorf("helper plan does not match hard diagnostic %s", diagnostic.ID))
			continue
		}
		if err := c.remote.SubmitPlan(ctx, plan); err != nil {
			c.pending[diagnostic.ID] = plan
			failures = append(failures, fmt.Errorf("submit helper plan %s: %w", payload.HelperPlanID, err))
		}
	}
	return errors.Join(failures...)
}

func activeRecord(records []ExecutionRecord, diagnostic recoverymodel.Diagnostic, now time.Time) bool {
	for _, record := range records {
		if record.DiagnosticID == diagnostic.ID && record.ResourceFingerprint == diagnostic.ResourceFingerprint &&
			record.SignedReceipt == nil && now.Before(record.ExpiresAt) {
			return true
		}
	}
	return false
}
