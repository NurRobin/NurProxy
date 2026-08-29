package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type CoordinatorBackend interface {
	Info() proxy.Info
	InspectRecovery(context.Context, proxy.RecoveryDesired) ([]proxy.RecoveryCandidate, error)
	ExecuteRecovery(context.Context, proxy.RecoveryCandidate, map[string]proxy.CertBundle) error
	Validate(context.Context) error
}

type DesiredState struct {
	Recovery       proxy.RecoveryDesired
	Bundles        map[string]proxy.CertBundle
	Classification Context
}

type Coordinator struct {
	mu          sync.Mutex
	agentID     string
	backend     CoordinatorBackend
	store       *SnapshotStore
	breaker     *Breaker
	reporter    ReportQueue
	guard       *PathGuard
	clock       func() time.Time
	desired     func() DesiredState
	baseContext Context
	policy      bool
	policyKnown bool
	diagnostics map[string]recoverymodel.Diagnostic
	candidates  map[string]proxy.RecoveryCandidate
	operations  map[string]recoverymodel.OperationReport
	sequence    uint64
	lastNow     time.Time
}

func NewCoordinator(agentID string, backend CoordinatorBackend, store *SnapshotStore, breaker *Breaker, reporter ReportQueue, guard *PathGuard, clock func() time.Time) *Coordinator {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if breaker == nil {
		breaker = NewBreaker()
	}
	return &Coordinator{agentID: agentID, backend: backend, store: store, breaker: breaker, reporter: reporter, guard: guard, clock: clock, diagnostics: make(map[string]recoverymodel.Diagnostic), candidates: make(map[string]proxy.RecoveryCandidate), operations: make(map[string]recoverymodel.OperationReport)}
}

func (c *Coordinator) SetDesired(desired func() DesiredState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.desired = desired
}

func (c *Coordinator) SetContext(classification Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	classification.AgentID = c.agentID
	c.baseContext = classification
}

func (c *Coordinator) SetPolicy(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy, c.policyKnown = enabled, true
}

func (c *Coordinator) Policy() (enabled, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policy, c.policyKnown
}

func (c *Coordinator) ActiveDiagnostics() []recoverymodel.Diagnostic {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]recoverymodel.Diagnostic, 0, len(c.diagnostics))
	for _, diagnostic := range c.diagnostics {
		out = append(out, diagnostic)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (c *Coordinator) ReconcileSucceeded() {
	c.mu.Lock()
	defer c.mu.Unlock()
	latched := make(map[string]struct{})
	for _, operation := range c.operations {
		if operation.State == recoverymodel.OperationStateRollbackFailed {
			latched[operation.DiagnosticID] = struct{}{}
		}
	}
	for id := range c.diagnostics {
		if _, keep := latched[id]; !keep {
			delete(c.diagnostics, id)
			delete(c.candidates, id)
		}
	}
}

func (c *Coordinator) Capability() recoverymodel.Capability {
	c.mu.Lock()
	defer c.mu.Unlock()
	return recoverymodel.Capability{Stage: 1, Actions: []recoverymodel.Action{
		recoverymodel.ActionPruneManagedOrphan,
		recoverymodel.ActionRemoveManagedTemp,
		recoverymodel.ActionRematerializeCertBundle,
		recoverymodel.ActionRematerializeRuntimeKey,
	}}
}

func (c *Coordinator) Observe(_ context.Context, err error) recoverymodel.Diagnostic {
	c.mu.Lock()
	defer c.mu.Unlock()
	desired := c.currentDesired()
	desired.Classification.AgentID = c.agentID
	if desired.Classification.ProxyInfo.Kind == proxy.KindUnknown && c.backend != nil {
		desired.Classification.ProxyInfo = c.backend.Info()
	}
	diagnostic := Classify(desired.Classification, err)
	candidate := proxy.RecoveryCandidate{}
	for _, existing := range c.candidates {
		if existing.Action != diagnostic.ProposedAction {
			continue
		}
		if len(diagnostic.AffectedPaths) == 0 || pathsOverlap(existing.Paths, diagnostic.AffectedPaths) {
			candidate = existing
			break
		}
	}
	c.recordDiagnostic(diagnostic, candidate)
	return diagnostic
}

func pathsOverlap(left, right []string) bool {
	seen := make(map[string]struct{}, len(left))
	for _, path := range left {
		seen[path] = struct{}{}
	}
	for _, path := range right {
		if _, ok := seen[path]; ok {
			return true
		}
	}
	return false
}

func (c *Coordinator) Inspect(ctx context.Context) ([]recoverymodel.Diagnostic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.backend == nil {
		return nil, fmt.Errorf("recovery backend is not configured")
	}
	desired := c.currentDesired()
	candidates, err := c.backend.InspectRecovery(ctx, desired.Recovery)
	if err != nil {
		return nil, err
	}
	diagnostics := make([]recoverymodel.Diagnostic, 0, len(candidates))
	for _, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			continue
		}
		diagnostic := diagnosticForCandidate(c.agentID, candidate, c.now())
		if candidate.Action == recoverymodel.ActionRematerializeCertBundle {
			bundle, ok := desired.Bundles[candidate.Host]
			if !ok || bundle.Host != candidate.Host || len(bundle.CertPEM) == 0 || len(bundle.KeyPEM) == 0 {
				diagnostic.AutoRepairEligible = false
			}
		}
		c.recordDiagnostic(diagnostic, candidate)
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics, nil
}

func (c *Coordinator) AutoRepair(ctx context.Context, diagnostic recoverymodel.Diagnostic) (recoverymodel.OperationReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.repairLocked(ctx, diagnostic, recoverymodel.RepairRequest{}, recoverymodel.RequestSourceAutomatic)
}

func (c *Coordinator) HandleRequest(ctx context.Context, request recoverymodel.RepairRequest) (recoverymodel.OperationReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := request.Validate(); err != nil {
		return recoverymodel.OperationReport{}, err
	}
	if previous, exists := c.operations[request.OperationID]; exists {
		if previous.DiagnosticID != request.DiagnosticID || previous.Action != request.Action {
			return recoverymodel.OperationReport{}, fmt.Errorf("repair operation ID was already used for a different request")
		}
		return previous, nil
	}
	diagnostic, exists := c.diagnostics[request.DiagnosticID]
	if !exists {
		return recoverymodel.OperationReport{}, fmt.Errorf("repair diagnostic is not active on this agent")
	}
	if diagnostic.ProposedAction != request.Action {
		return recoverymodel.OperationReport{}, fmt.Errorf("repair action does not match diagnostic")
	}
	return c.repairLocked(ctx, diagnostic, request, recoverymodel.RequestSourceUser)
}

// Recover resumes only validation or rollback from a durable manifest. It never
// repeats a mutation whose completion became ambiguous during a crash.
func (c *Coordinator) Recover(ctx context.Context, operationID string) (recoverymodel.OperationReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.store == nil {
		return recoverymodel.OperationReport{}, fmt.Errorf("recovery store is not configured")
	}
	manifest, err := c.store.Load(operationID)
	if err != nil {
		return recoverymodel.OperationReport{}, err
	}
	diagnosticID := "restart-" + manifest.Fingerprint
	for id, diagnostic := range c.diagnostics {
		if diagnostic.ResourceFingerprint == manifest.Fingerprint && diagnostic.ProposedAction == manifest.Action {
			diagnosticID = id
			break
		}
	}
	report := recoverymodel.OperationReport{OperationID: operationID, DiagnosticID: diagnosticID, Action: manifest.Action, Source: recoverymodel.RequestSourceAutomatic, State: manifest.State, SnapshotReference: manifest.OperationID, StartedAt: manifest.CreatedAt}
	if c.lastNow.Before(manifest.CreatedAt) {
		c.lastNow = manifest.CreatedAt
	}
	disposition, err := c.store.PrepareRestart(operationID)
	if err != nil {
		return report, err
	}
	key := BreakerKey{Action: manifest.Action, Fingerprint: manifest.Fingerprint}
	var validationCause error
	if disposition == RestartResumeValidation {
		validationErr := c.backend.Validate(ctx)
		if validationErr == nil {
			validationErr = c.activateValidated(ctx)
		}
		if validationErr == nil {
			if _, err = c.store.Transition(operationID, recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded, c.now()); err != nil {
				return report, err
			}
			report.State, report.ValidationOutcome = recoverymodel.OperationStateSucceeded, "valid"
			c.addStep(&report, report.State, "post-crash validation succeeded")
			at := c.now()
			report.FinishedAt = &at
			c.operations[operationID] = report
			c.emitOperation(report)
			_ = c.breaker.Record(key, report.State, at, false)
			return report, nil
		}
		validationCause = validationErr
		report.ValidationOutcome = recoverymodel.SanitizeEvidence(validationErr.Error())
		if _, err = c.store.Transition(operationID, recoverymodel.OperationStateValidating, recoverymodel.OperationStateRollingBack, c.now()); err != nil {
			return report, err
		}
		disposition = RestartResumeRollback
	}
	if disposition != RestartResumeRollback {
		return report, fmt.Errorf("operation state %q is not crash-resumable", manifest.State)
	}
	report.State = recoverymodel.OperationStateRollingBack
	c.addStep(&report, report.State, "resuming rollback after restart")
	rollbackErr := c.store.Rollback(operationID)
	if rollbackErr == nil {
		rollbackErr = c.backend.Validate(ctx)
	}
	if rollbackErr == nil {
		rollbackErr = c.activateValidated(ctx)
	}
	final := recoverymodel.OperationStateRolledBack
	if rollbackErr != nil {
		final = recoverymodel.OperationStateRollbackFailed
	}
	if _, err = c.store.Transition(operationID, recoverymodel.OperationStateRollingBack, final, c.now()); err != nil && rollbackErr == nil {
		rollbackErr = err
		final = recoverymodel.OperationStateRollbackFailed
	}
	report.State = final
	if rollbackErr == nil {
		report.RollbackOutcome = "restored and valid"
	} else {
		report.RollbackOutcome = recoverymodel.SanitizeEvidence(rollbackErr.Error())
	}
	c.addStep(&report, final, report.RollbackOutcome)
	at := c.now()
	report.FinishedAt = &at
	c.operations[operationID] = report
	c.emitOperation(report)
	_ = c.breaker.Record(key, final, at, false)
	if rollbackErr != nil {
		return report, rollbackErr
	}
	if validationCause != nil {
		return report, fmt.Errorf("post-crash validation failed and was rolled back: %w", validationCause)
	}
	return report, nil
}

func (c *Coordinator) repairLocked(ctx context.Context, diagnostic recoverymodel.Diagnostic, request recoverymodel.RepairRequest, source recoverymodel.RequestSource) (recoverymodel.OperationReport, error) {
	if err := diagnostic.Validate(); err != nil {
		return recoverymodel.OperationReport{}, err
	}
	candidate, exists := c.candidates[diagnostic.ID]
	if !exists || candidate.Action != diagnostic.ProposedAction {
		return recoverymodel.OperationReport{}, fmt.Errorf("repair candidate is unavailable")
	}
	now := c.now()
	opID := request.OperationID
	if opID == "" {
		c.sequence++
		opID = fmt.Sprintf("auto-%d-%d", now.UnixNano(), c.sequence)
	}
	report := recoverymodel.OperationReport{OperationID: opID, DiagnosticID: diagnostic.ID, Action: diagnostic.ProposedAction, Source: source, State: recoverymodel.OperationStateDetected, StartedAt: now}
	c.addStep(&report, recoverymodel.OperationStateDetected, "recovery condition detected")
	c.emitOperation(report)
	finish := func(state recoverymodel.OperationState, message string) recoverymodel.OperationReport {
		report.State = state
		c.addStep(&report, state, message)
		at := c.now()
		report.FinishedAt = &at
		report.Error = recoverymodel.SanitizeEvidence(message)
		c.operations[opID] = report
		c.emitOperation(report)
		return report
	}
	if !diagnostic.AutoRepairEligible || diagnostic.HardChange || diagnostic.Ownership != recoverymodel.OwnershipNurProxy {
		return finish(recoverymodel.OperationStateDiagnosisOnly, "diagnostic is not eligible for safe repair"), nil
	}
	if source == recoverymodel.RequestSourceAutomatic && (!c.policyKnown || !c.policy) {
		return finish(recoverymodel.OperationStateDiagnosisOnly, "automatic repair policy is disabled or unavailable"), nil
	}
	key := BreakerKey{Action: diagnostic.ProposedAction, Fingerprint: diagnostic.ResourceFingerprint}
	decision := c.breaker.Allow(key, source, now)
	if !decision.Allowed {
		return finish(recoverymodel.OperationStateSuppressed, decision.Reason), nil
	}

	report.State = recoverymodel.OperationStatePlanned
	c.addStep(&report, recoverymodel.OperationStatePlanned, "safe typed repair planned")
	paths, err := c.resolveCandidate(candidate)
	if err != nil {
		report.Steps = report.Steps[:1]
		return finish(recoverymodel.OperationStateDiagnosisOnly, err.Error()), err
	}
	manifest, err := c.store.Create(opID, candidate.Action, diagnostic.ResourceFingerprint, paths, c.now())
	if err != nil {
		report.Steps = report.Steps[:1]
		return finish(recoverymodel.OperationStateDiagnosisOnly, err.Error()), err
	}
	c.emitOperation(report)
	report.SnapshotReference = manifest.OperationID
	report.State = recoverymodel.OperationStateSnapshotted
	c.addStep(&report, report.State, "prior filesystem state captured")
	c.emitOperation(report)
	if _, err = c.store.Transition(opID, recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying, c.now()); err != nil {
		return c.rollbackLocked(ctx, key, &report, recoverymodel.OperationStateSnapshotted, err)
	}
	report.State = recoverymodel.OperationStateApplying
	c.addStep(&report, report.State, "typed recovery action started")
	c.emitOperation(report)
	desired := c.currentDesired()
	if err = c.backend.ExecuteRecovery(ctx, candidate, desired.Bundles); err != nil {
		return c.rollbackLocked(ctx, key, &report, recoverymodel.OperationStateApplying, err)
	}
	if _, err = c.store.Transition(opID, recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating, c.now()); err != nil {
		return c.rollbackLocked(ctx, key, &report, recoverymodel.OperationStateApplying, err)
	}
	report.State = recoverymodel.OperationStateValidating
	c.addStep(&report, report.State, "full proxy validation started")
	c.emitOperation(report)
	if err = c.backend.Validate(ctx); err != nil {
		return c.rollbackLocked(ctx, key, &report, recoverymodel.OperationStateValidating, err)
	}
	if err = c.activateValidated(ctx); err != nil {
		return c.rollbackLocked(ctx, key, &report, recoverymodel.OperationStateValidating, err)
	}
	if _, err = c.store.Transition(opID, recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded, c.now()); err != nil {
		return report, err
	}
	report.ValidationOutcome = "valid"
	report.State = recoverymodel.OperationStateSucceeded
	c.addStep(&report, report.State, "repair validated and activated")
	at := c.now()
	report.FinishedAt = &at
	c.operations[opID] = report
	delete(c.diagnostics, diagnostic.ID)
	delete(c.candidates, diagnostic.ID)
	_ = c.breaker.Record(key, report.State, at, source == recoverymodel.RequestSourceUser)
	c.emitOperation(report)
	return report, nil
}

func (c *Coordinator) rollbackLocked(ctx context.Context, key BreakerKey, report *recoverymodel.OperationReport, expected recoverymodel.OperationState, cause error) (recoverymodel.OperationReport, error) {
	_, transitionErr := c.store.Transition(report.OperationID, expected, recoverymodel.OperationStateRollingBack, c.now())
	report.State = recoverymodel.OperationStateRollingBack
	c.addStep(report, report.State, "restoring captured state")
	c.emitOperation(*report)
	rollbackErr := transitionErr
	if rollbackErr == nil {
		rollbackErr = c.store.Rollback(report.OperationID)
	}
	if rollbackErr == nil {
		rollbackErr = c.backend.Validate(ctx)
	}
	if rollbackErr == nil {
		rollbackErr = c.activateValidated(ctx)
	}
	final := recoverymodel.OperationStateRolledBack
	if rollbackErr != nil {
		final = recoverymodel.OperationStateRollbackFailed
	}
	if _, err := c.store.Transition(report.OperationID, recoverymodel.OperationStateRollingBack, final, c.now()); err != nil && rollbackErr == nil {
		rollbackErr = err
		final = recoverymodel.OperationStateRollbackFailed
	}
	report.State = final
	report.Error = recoverymodel.SanitizeEvidence(cause.Error())
	if rollbackErr == nil {
		report.RollbackOutcome = "restored and valid"
	} else {
		report.RollbackOutcome = recoverymodel.SanitizeEvidence(rollbackErr.Error())
	}
	c.addStep(report, final, report.RollbackOutcome)
	at := c.now()
	report.FinishedAt = &at
	c.operations[report.OperationID] = *report
	_ = c.breaker.Record(key, final, at, false)
	c.emitOperation(*report)
	if rollbackErr != nil {
		return *report, fmt.Errorf("repair failed: %w; rollback failed: %v", cause, rollbackErr)
	}
	return *report, fmt.Errorf("repair failed and was rolled back: %w", cause)
}

func (c *Coordinator) activateValidated(ctx context.Context) error {
	if c.backend == nil {
		return fmt.Errorf("recovery backend is not configured")
	}
	kind := c.backend.Info().Kind
	if kind != proxy.KindNginx && kind != proxy.KindApache {
		return nil
	}
	backend, ok := c.backend.(interface {
		Apply(context.Context, []proxy.Artifact) error
	})
	if !ok {
		return fmt.Errorf("file proxy backend cannot activate validated recovery")
	}
	return backend.Apply(ctx, nil)
}

func (c *Coordinator) currentDesired() DesiredState {
	state := DesiredState{}
	if c.desired != nil {
		state = c.desired()
	}
	base := c.baseContext
	if state.Classification.AgentID == "" {
		state.Classification.AgentID = base.AgentID
	}
	if state.Classification.ProxyInfo.Kind == proxy.KindUnknown {
		state.Classification.ProxyInfo = base.ProxyInfo
	}
	if len(state.Classification.ManagedRoots) == 0 {
		state.Classification.ManagedRoots = append([]string(nil), base.ManagedRoots...)
	}
	if state.Classification.AgentDataRoot == "" {
		state.Classification.AgentDataRoot = base.AgentDataRoot
	}
	return state
}
func (c *Coordinator) now() time.Time {
	now := c.clock().UTC()
	if now.Before(c.lastNow) {
		return c.lastNow
	}
	c.lastNow = now
	return now
}
func (c *Coordinator) resolveCandidate(candidate proxy.RecoveryCandidate) ([]GuardedPath, error) {
	if c.store == nil {
		return nil, fmt.Errorf("recovery snapshot safety is not configured")
	}
	guard := c.guard
	desired := c.currentDesired().Classification
	roots := append([]string(nil), desired.ManagedRoots...)
	if desired.AgentDataRoot != "" {
		roots = append(roots, desired.AgentDataRoot)
	}
	if len(roots) > 0 {
		refreshed, err := NewPathGuard(roots...)
		if err != nil {
			return nil, err
		}
		guard = refreshed
	}
	if guard == nil {
		return nil, fmt.Errorf("recovery path guard is not configured")
	}
	paths := make([]GuardedPath, 0, len(candidate.Paths))
	for _, path := range candidate.Paths {
		checked, err := guard.Resolve(path)
		if err != nil {
			return nil, err
		}
		paths = append(paths, checked)
	}
	return paths, nil
}
func (c *Coordinator) addStep(report *recoverymodel.OperationReport, state recoverymodel.OperationState, summary string) {
	report.Steps = append(report.Steps, recoverymodel.Step{Name: string(state), Summary: recoverymodel.SanitizeEvidence(summary), State: state, At: c.now()})
}
func (c *Coordinator) emitOperation(report recoverymodel.OperationReport) {
	if c.reporter != nil {
		c.reporter.Enqueue(proxymodel.RecoveryReport{Operations: []recoverymodel.OperationReport{report}})
	}
}
func (c *Coordinator) recordDiagnostic(d recoverymodel.Diagnostic, candidate proxy.RecoveryCandidate) {
	if previous, ok := c.diagnostics[d.ID]; ok {
		d.FirstSeenAt = previous.FirstSeenAt
		d.Occurrences = previous.Occurrences + 1
	}
	c.diagnostics[d.ID] = d
	if candidate.Action.Valid() {
		c.candidates[d.ID] = candidate
	}
	if c.reporter != nil {
		c.reporter.Enqueue(proxymodel.RecoveryReport{Diagnostics: []recoverymodel.Diagnostic{d}})
	}
}

func diagnosticForCandidate(agentID string, candidate proxy.RecoveryCandidate, now time.Time) recoverymodel.Diagnostic {
	code := recoverymodel.CodeUnknownProxyError
	summary := "Managed recovery candidate detected"
	switch candidate.Action {
	case recoverymodel.ActionPruneManagedOrphan:
		code, summary = recoverymodel.CodeManagedOrphanConfig, "Managed orphan proxy configuration detected"
	case recoverymodel.ActionRemoveManagedTemp:
		code, summary = recoverymodel.CodeManagedStaleTemp, "Managed stale temporary file detected"
	case recoverymodel.ActionRematerializeCertBundle:
		code, summary = recoverymodel.CodeManagedCertFileMissing, "Managed certificate bundle requires restoration"
	case recoverymodel.ActionRematerializeRuntimeKey:
		code, summary = recoverymodel.CodeManagedRuntimeKeyMissing, "Managed runtime key requires restoration"
	}
	paths := append([]string(nil), candidate.Paths...)
	sort.Strings(paths)
	sum := sha256.Sum256([]byte(string(candidate.Action) + "\x00" + candidate.Host + "\x00" + strings.Join(paths, "\x00")))
	fingerprint := hex.EncodeToString(sum[:])
	d := recoverymodel.Diagnostic{Code: code, Subsystem: "proxy", Severity: recoverymodel.SeverityError, Ownership: recoverymodel.OwnershipNurProxy, Summary: summary, AffectedPaths: paths, ResourceFingerprint: fingerprint, ProposedAction: candidate.Action, AutoRepairEligible: true, FirstSeenAt: now, LastSeenAt: now, Occurrences: 1}
	d.ID = recoverymodel.StableDiagnosticID(agentID, d.Code, fingerprint)
	return d
}
