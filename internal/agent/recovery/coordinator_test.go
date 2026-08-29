package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type coordinatorBackend struct {
	mu            sync.Mutex
	candidates    []proxy.RecoveryCandidate
	executeErr    error
	validateErr   error
	validateQueue []error
	executions    int
	validations   int
	activations   int
	active        int
	maxActive     int
}

func (b *coordinatorBackend) Info() proxy.Info { return proxy.Info{Kind: proxy.KindNginx} }
func (b *coordinatorBackend) InspectRecovery(context.Context, proxy.RecoveryDesired) ([]proxy.RecoveryCandidate, error) {
	return append([]proxy.RecoveryCandidate(nil), b.candidates...), nil
}
func (b *coordinatorBackend) ExecuteRecovery(_ context.Context, _ proxy.RecoveryCandidate, _ map[string]proxy.CertBundle) error {
	b.mu.Lock()
	b.executions++
	b.active++
	if b.active > b.maxActive {
		b.maxActive = b.active
	}
	err := b.executeErr
	b.mu.Unlock()
	time.Sleep(time.Millisecond)
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
	return err
}
func (b *coordinatorBackend) Validate(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.validations++
	if len(b.validateQueue) > 0 {
		err := b.validateQueue[0]
		b.validateQueue = b.validateQueue[1:]
		return err
	}
	return b.validateErr
}
func (b *coordinatorBackend) ReloadRecovery(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.activations++
	return nil
}

func TestCoordinatorValidationFailureRestoresAndValidatesSnapshot(t *testing.T) {
	c, backend, _, _, path := newCoordinatorFixture(t)
	c.SetPolicy(true)
	diagnostics, _ := c.Inspect(context.Background())
	backend.validateQueue = []error{errors.New("new config invalid"), nil}
	report, err := c.AutoRepair(context.Background(), diagnostics[0])
	if err == nil || report.State != recoverymodel.OperationStateRolledBack || report.RollbackOutcome != "restored and valid" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "stale" {
		t.Fatalf("restored=%q err=%v", data, readErr)
	}
}

type collectingReporter struct {
	mu      sync.Mutex
	reports []proxymodel.RecoveryReport
}

func (r *collectingReporter) Enqueue(report proxymodel.RecoveryReport) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, report)
	return true
}

func newCoordinatorFixture(t *testing.T) (*Coordinator, *coordinatorBackend, *collectingReporter, proxy.RecoveryCandidate, string) {
	t.Helper()
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(managed, "nurproxy-stale.example.test.conf.nurproxy-tmp")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := proxy.CaptureRecoveryPath(path)
	if err != nil {
		t.Fatal(err)
	}
	candidate := proxy.NewRecoveryCandidate(recoverymodel.ActionRemoveManagedTemp, "stale.example.test", identity)
	backend := &coordinatorBackend{candidates: []proxy.RecoveryCandidate{candidate}}
	reporter := &collectingReporter{}
	store, err := NewSnapshotStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	guard, err := NewPathGuard(managed)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC) }
	coordinator := NewCoordinator("agent-1", backend, store, NewBreaker(), reporter, guard, clock)
	coordinator.SetDesired(func() DesiredState { return DesiredState{} })
	return coordinator, backend, reporter, candidate, path
}

func TestCoordinatorFailsClosedUntilPolicyAndSupportsDiagnosisOnly(t *testing.T) {
	c, backend, _, _, _ := newCoordinatorFixture(t)
	diagnostics, err := c.Inspect(context.Background())
	if err != nil || len(diagnostics) != 1 {
		t.Fatalf("inspect = %#v, %v", diagnostics, err)
	}
	report, err := c.AutoRepair(context.Background(), diagnostics[0])
	if err != nil {
		t.Fatal(err)
	}
	if report.State != recoverymodel.OperationStateDiagnosisOnly || backend.executions != 0 {
		t.Fatalf("report=%+v executions=%d", report, backend.executions)
	}
	if len(report.Steps) != 2 || report.Steps[0].State != recoverymodel.OperationStateDetected || report.Steps[1].State != recoverymodel.OperationStateDiagnosisOnly {
		t.Fatalf("diagnosis steps=%+v", report.Steps)
	}
	c.SetPolicy(false)
	report, err = c.AutoRepair(context.Background(), diagnostics[0])
	if err != nil || report.State != recoverymodel.OperationStateDiagnosisOnly || backend.executions != 0 {
		t.Fatalf("disabled report=%+v err=%v executions=%d", report, err, backend.executions)
	}
}

func TestCoordinatorClearsRecoveredDiagnosticsOnlyAfterFreshInspection(t *testing.T) {
	c, backend, reporter, _, _ := newCoordinatorFixture(t)
	if diagnostics, _ := c.Inspect(context.Background()); len(diagnostics) != 1 {
		t.Fatalf("diagnostics=%v", diagnostics)
	}
	backend.candidates = nil
	if err := c.ReconcileSucceeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active := c.ActiveDiagnostics(); len(active) != 0 {
		t.Fatalf("active=%v", active)
	}
	reporter.mu.Lock()
	last := reporter.reports[len(reporter.reports)-1]
	reporter.mu.Unlock()
	if last.Diagnostics == nil || len(last.Diagnostics) != 0 {
		t.Fatalf("resolution was not emitted as authoritative empty snapshot: %#v", last)
	}
}

func TestCoordinatorFreshInspectionDoesNotClearPersistentDiagnosis(t *testing.T) {
	c, _, _, _, _ := newCoordinatorFixture(t)
	if diagnostics, _ := c.Inspect(context.Background()); len(diagnostics) != 1 {
		t.Fatalf("diagnostics=%v", diagnostics)
	}
	if err := c.ReconcileSucceeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active := c.ActiveDiagnostics(); len(active) != 1 {
		t.Fatalf("persistent diagnostic was cleared: %v", active)
	}
}

func TestCoordinatorAutomaticRepairRunsSnapshotMutationAndFullValidation(t *testing.T) {
	c, backend, _, _, _ := newCoordinatorFixture(t)
	c.SetPolicy(true)
	diagnostics, _ := c.Inspect(context.Background())
	report, err := c.AutoRepair(context.Background(), diagnostics[0])
	if err != nil {
		t.Fatal(err)
	}
	if report.State != recoverymodel.OperationStateSucceeded || backend.executions != 1 || backend.validations != 1 || backend.activations != 1 {
		t.Fatalf("report=%+v executions=%d validations=%d activations=%d", report, backend.executions, backend.validations, backend.activations)
	}
	want := []recoverymodel.OperationState{recoverymodel.OperationStateDetected, recoverymodel.OperationStatePlanned, recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying, recoverymodel.OperationStateValidating, recoverymodel.OperationStateSucceeded}
	if len(report.Steps) != len(want) {
		t.Fatalf("steps=%+v", report.Steps)
	}
	for i := range want {
		if report.Steps[i].State != want[i] {
			t.Fatalf("step %d=%s want %s", i, report.Steps[i].State, want[i])
		}
	}
}

func TestCoordinatorValidationFailureRollsBackAndRollbackFailureLatches(t *testing.T) {
	c, backend, _, _, path := newCoordinatorFixture(t)
	c.SetPolicy(true)
	diagnostics, _ := c.Inspect(context.Background())
	backend.validateErr = errors.New("nginx -t failed")
	report, err := c.AutoRepair(context.Background(), diagnostics[0])
	if err == nil || report.State != recoverymodel.OperationStateRollbackFailed {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("snapshot was not restored: %v", statErr)
	}
	second, _ := c.AutoRepair(context.Background(), diagnostics[0])
	if second.State != recoverymodel.OperationStateSuppressed || backend.executions != 1 {
		t.Fatalf("breaker did not suppress: %+v executions=%d", second, backend.executions)
	}
	if len(second.Steps) != 2 || second.Steps[0].State != recoverymodel.OperationStateDetected || second.Steps[1].State != recoverymodel.OperationStateSuppressed {
		t.Fatalf("suppressed steps=%+v", second.Steps)
	}
}

func TestCoordinatorSnapshotFailureDoesNotMutate(t *testing.T) {
	c, backend, reporter, _, path := newCoordinatorFixture(t)
	c.SetPolicy(true)
	diagnostics, _ := c.Inspect(context.Background())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	report, err := c.AutoRepair(context.Background(), diagnostics[0])
	if err == nil || report.State != recoverymodel.OperationStateDiagnosisOnly || backend.executions != 0 {
		t.Fatalf("report=%+v err=%v executions=%d", report, err, backend.executions)
	}
	for _, queued := range reporter.reports {
		if len(queued.Operations) == 1 && queued.Operations[0].State == recoverymodel.OperationStatePlanned {
			t.Fatal("snapshot failure published an impossible planned transition")
		}
	}
	if len(report.Steps) != 2 || report.Steps[0].State != recoverymodel.OperationStateDetected || report.Steps[1].State != recoverymodel.OperationStateDiagnosisOnly {
		t.Fatalf("snapshot failure steps=%+v", report.Steps)
	}
}

func TestCoordinatorSerializesConcurrentRepairAndRejectsReplayMismatch(t *testing.T) {
	c, backend, _, _, _ := newCoordinatorFixture(t)
	c.SetPolicy(true)
	diagnostics, _ := c.Inspect(context.Background())
	started := testTime()
	req := recoverymodel.RepairRequest{OperationID: "manual-op", DiagnosticID: diagnostics[0].ID, Action: diagnostics[0].ProposedAction, StartedAt: started, InitialStep: recoverymodel.Step{Name: "planned", Summary: "safe typed repair requested", State: recoverymodel.OperationStatePlanned, At: started}}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = c.HandleRequest(context.Background(), req) }()
	}
	wg.Wait()
	if backend.maxActive != 1 || backend.executions != 1 {
		t.Fatalf("max active=%d executions=%d", backend.maxActive, backend.executions)
	}
	var manualStates []recoverymodel.OperationState
	for _, queued := range c.reporter.(*collectingReporter).reports {
		if len(queued.Operations) == 1 && queued.Operations[0].OperationID == req.OperationID {
			manualStates = append(manualStates, queued.Operations[0].State)
		}
	}
	if len(manualStates) == 0 || manualStates[0] != recoverymodel.OperationStatePlanned {
		t.Fatalf("manual states=%v", manualStates)
	}
	for _, state := range manualStates {
		if state == recoverymodel.OperationStateDetected {
			t.Fatalf("manual operation emitted detected: %v", manualStates)
		}
	}
	bad := req
	bad.OperationID = "other-op"
	bad.Action = recoverymodel.ActionPruneManagedOrphan
	if _, err := c.HandleRequest(context.Background(), bad); err == nil {
		t.Fatal("action mismatch accepted")
	}
	reused := req
	reused.Action = recoverymodel.ActionPruneManagedOrphan
	if _, err := c.HandleRequest(context.Background(), reused); err == nil {
		t.Fatal("reused ID with changed action accepted")
	}
	reused = req
	reused.StartedAt = reused.StartedAt.Add(time.Second)
	reused.InitialStep.At = reused.StartedAt
	if _, err := c.HandleRequest(context.Background(), reused); err == nil {
		t.Fatal("reused ID with changed persisted start identity accepted")
	}
}

func TestCoordinatorCapabilityIsStableAndCrashRecoveryNeverRepeatsMutation(t *testing.T) {
	c, backend, _, candidate, _ := newCoordinatorFixture(t)
	capability := c.Capability()
	if err := capability.Validate(); err != nil || capability.Stage != 1 {
		t.Fatalf("capability=%+v err=%v", capability, err)
	}
	c.SetPolicy(true)
	diagnostics, _ := c.Inspect(context.Background())
	// A request that already completed is replayed from memory without mutation.
	started := testTime()
	req := recoverymodel.RepairRequest{OperationID: "crash-safe-op", DiagnosticID: diagnostics[0].ID, Action: candidate.Action, StartedAt: started, InitialStep: recoverymodel.Step{Name: "planned", Summary: "safe typed repair requested", State: recoverymodel.OperationStatePlanned, At: started}}
	first, err := c.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.HandleRequest(context.Background(), req)
	if err != nil || second.State != first.State || backend.executions != 1 {
		t.Fatalf("replay=%+v err=%v executions=%d", second, err, backend.executions)
	}
}

func TestCoordinatorCrashRecoveryRollsBackUnknownApplyingMutation(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(managed, "nurproxy-crash.example.test.conf.nurproxy-tmp")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, _ := proxy.CaptureRecoveryPath(path)
	candidate := proxy.NewRecoveryCandidate(recoverymodel.ActionRemoveManagedTemp, "crash.example.test", identity)
	backend := &coordinatorBackend{candidates: []proxy.RecoveryCandidate{candidate}}
	store, _ := NewSnapshotStore(filepath.Join(root, "data"))
	defer store.Close()
	guard, _ := NewPathGuard(managed)
	c := NewCoordinator("agent-1", backend, store, NewBreaker(), &collectingReporter{}, guard, func() time.Time { return testTime() })
	diagnostics, _ := c.Inspect(context.Background())
	checked, _ := guard.Resolve(path)
	if _, err := store.Create("op-crash", candidate.Action, diagnostics[0].ResourceFingerprint, []GuardedPath{checked}, testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition("op-crash", recoverymodel.OperationStateSnapshotted, recoverymodel.OperationStateApplying, testTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	report, err := c.Recover(context.Background(), "op-crash")
	if err != nil || report.State != recoverymodel.OperationStateRolledBack || backend.executions != 0 {
		t.Fatalf("report=%+v err=%v executions=%d", report, err, backend.executions)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "before" {
		t.Fatalf("restored=%q err=%v", data, err)
	}
}

func TestCoordinatorRestartKeepsRollbackFailedDiagnosticLatched(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := persistTestManifest(store, "failed-restart", recoverymodel.OperationStateRollbackFailed, testTime()); err != nil {
		t.Fatal(err)
	}
	backend := &coordinatorBackend{}
	c := NewCoordinator("agent-1", backend, store, NewBreaker(), &collectingReporter{}, nil, func() time.Time { return testTime() })
	report, err := c.Recover(context.Background(), "failed-restart")
	if err != nil || report.State != recoverymodel.OperationStateRollbackFailed {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if err := c.ReconcileSucceeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active := c.ActiveDiagnostics(); len(active) != 1 || active[0].ID != report.DiagnosticID {
		t.Fatalf("latched diagnostics=%+v", active)
	}
}
