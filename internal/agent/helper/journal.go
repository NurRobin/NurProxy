package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

var (
	ErrRequestConflict = errors.New("helper request identity conflict")
	ErrGrantReplay     = errors.New("helper grant replay")
	ErrJournalCorrupt  = errors.New("helper journal corrupt")
	ErrPlanNotFound    = errors.New("helper plan not found")
	ErrReceiptNotFound = errors.New("helper receipt not found")
	ErrPlanQuota       = errors.New("helper plan quota exceeded")
)

const maxStoredPlans = 128

// Retention for finished operations. Every terminal record per action is kept
// while it is younger than operationRetentionAge, and the newest
// operationRetentionPerAction are kept regardless of age. maxRetainedOperations
// is a backstop that may cut into the age window, but never below the per-action
// floor and never for records younger than operationRetentionMinAge, which is far
// longer than any grant lifetime, so a pruned grant can no longer be replayed.
const (
	operationRetentionPerAction = 50
	operationRetentionAge       = 14 * 24 * time.Hour
	operationRetentionMinAge    = time.Hour
	maxRetainedOperations       = 1000
	journalPruneInterval        = time.Hour
	pruneBatchSize              = 256
)

// PruneResult counts the journal files one prune pass removed.
type PruneResult struct {
	Operations int
	Grants     int
	Snapshots  int
}

type OperationRecord struct {
	OperationID            string                        `json:"operation_id"`
	GrantID                string                        `json:"grant_id"`
	CanonicalRequestDigest string                        `json:"canonical_request_digest"`
	Action                 helperprotocol.Action         `json:"action"`
	State                  helperprotocol.JournalState   `json:"state"`
	Receipt                *helperprotocol.HelperReceipt `json:"receipt,omitempty"`
	UpdatedAt              string                        `json:"updated_at"`
}

func (r OperationRecord) Validate() error {
	if !validConfigID(r.OperationID) || !validConfigID(r.GrantID) || !validDigest(r.CanonicalRequestDigest) ||
		!r.Action.Valid() || !r.State.Valid() || !canonicalTime(r.UpdatedAt) {
		return fmt.Errorf("invalid operation journal record")
	}
	if r.Receipt != nil {
		if err := r.Receipt.Validate(); err != nil || r.Receipt.OperationID != r.OperationID ||
			r.Receipt.CanonicalRequestDigest != r.CanonicalRequestDigest || r.Receipt.Action != r.Action || r.Receipt.State != r.State {
			return fmt.Errorf("invalid operation receipt binding")
		}
	}
	return nil
}

type planRecord struct {
	Plan   helperprotocol.HelperPlan `json:"plan"`
	Digest string                    `json:"digest"`
}

type managedPlanRecord struct {
	Plan         helperprotocol.ManagedApplyPlan                   `json:"plan"`
	Intent       helperprotocol.Signed[helperprotocol.ApplyIntent] `json:"signed_apply_intent"`
	PlanDigest   string                                            `json:"plan_digest"`
	IntentDigest string                                            `json:"intent_digest"`
}

func (r managedPlanRecord) Validate() error {
	if r.Plan.Validate() != nil || r.Intent.Validate() != nil || r.Intent.Envelope.MessageType != helperprotocol.MessageApplyIntent ||
		!validDigest(r.PlanDigest) || !validDigest(r.IntentDigest) {
		return fmt.Errorf("invalid managed helper plan record")
	}
	planDigest, planErr := helperprotocol.Digest(r.Plan)
	intentDigest, intentErr := helperprotocol.Digest(r.Intent)
	if planErr != nil || intentErr != nil || planDigest != r.PlanDigest || intentDigest != r.IntentDigest ||
		r.Plan.OperationID != r.Intent.Envelope.Payload.OperationID || r.Plan.DesiredStateRevision != r.Intent.Envelope.Payload.DesiredStateRevision {
		return fmt.Errorf("managed helper plan digest mismatch")
	}
	return nil
}

func (r planRecord) Validate() error {
	if err := r.Plan.Validate(); err != nil || !validDigest(r.Digest) {
		return fmt.Errorf("invalid helper plan record")
	}
	digest, err := helperprotocol.Digest(r.Plan)
	if err != nil || digest != r.Digest {
		return fmt.Errorf("helper plan digest mismatch")
	}
	return nil
}

type grantClaim struct {
	GrantID                string `json:"grant_id"`
	OperationID            string `json:"operation_id"`
	CanonicalRequestDigest string `json:"canonical_request_digest"`
}

func (r grantClaim) Validate() error {
	if !validConfigID(r.GrantID) || !validConfigID(r.OperationID) || !validDigest(r.CanonicalRequestDigest) {
		return fmt.Errorf("invalid grant claim")
	}
	return nil
}

type breakerRecord struct {
	Reason    string `json:"reason"`
	OpenedAt  string `json:"opened_at"`
	Permanent bool   `json:"permanent"`
}

func (r breakerRecord) Validate() error {
	if strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 512 || !canonicalTime(r.OpenedAt) || !r.Permanent {
		return fmt.Errorf("invalid breaker record")
	}
	return nil
}

type Journal struct {
	mu              sync.Mutex
	root            string
	ownerUID        uint32
	plansDir        string
	managedPlansDir string
	operationsDir   string
	grantsDir       string
	snapshotsDir    string
	breakerPath     string
	breakerIsOpen   bool
	lastPrune       time.Time
	pruneMu         sync.Mutex
}

func NewJournal(root string, ownerUID uint32) (*Journal, error) {
	if err := ensurePrivateDirectory(root, ownerUID); err != nil {
		return nil, fmt.Errorf("create helper journal root: %w", err)
	}
	j := &Journal{
		root:            root,
		ownerUID:        ownerUID,
		plansDir:        filepath.Join(root, "plans"),
		managedPlansDir: filepath.Join(root, "managed-plans"),
		operationsDir:   filepath.Join(root, "operations"),
		grantsDir:       filepath.Join(root, "grants"),
		snapshotsDir:    filepath.Join(root, "snapshots"),
		breakerPath:     filepath.Join(root, "breaker.json"),
	}
	for _, dir := range []string{j.plansDir, j.managedPlansDir, j.operationsDir, j.grantsDir, j.snapshotsDir} {
		if err := ensurePrivateDirectory(dir, ownerUID); err != nil {
			return nil, fmt.Errorf("create helper journal directory: %w", err)
		}
	}
	if _, err := os.Lstat(j.breakerPath); err == nil {
		payload, readErr := readTrustedFile(j.breakerPath, ownerUID, helperprotocol.MaxFrameBytes, true)
		if readErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrJournalCorrupt, readErr)
		}
		if _, decodeErr := helperprotocol.Decode[breakerRecord](payload); decodeErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrJournalCorrupt, decodeErr)
		}
		j.breakerIsOpen = true
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return j, nil
}

func (j *Journal) StoreSnapshot(operationID string, value any) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !validConfigID(operationID) {
		return "", fmt.Errorf("invalid snapshot operation identity")
	}
	payload, err := helperprotocol.CanonicalBytes(value)
	if err != nil {
		return "", err
	}
	digest, err := helperprotocol.Digest(value)
	if err != nil {
		return "", err
	}
	path := filepath.Join(j.snapshotsDir, operationID+".json")
	if err := j.writeRecord(path, value, true); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		existing, readErr := readTrustedFile(path, j.ownerUID, helperprotocol.MaxFrameBytes, true)
		if readErr != nil || string(existing) != string(payload) {
			return "", ErrRequestConflict
		}
	}
	return digest, nil
}

func (j *Journal) LoadSnapshot(operationID, expectedDigest string) ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !validConfigID(operationID) || !validDigest(expectedDigest) {
		return nil, fmt.Errorf("invalid snapshot identity")
	}
	payload, err := readTrustedFile(filepath.Join(j.snapshotsDir, operationID+".json"), j.ownerUID, helperprotocol.MaxFrameBytes, true)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return nil, ErrJournalCorrupt
	}
	return payload, nil
}

func (j *Journal) StorePlan(plan helperprotocol.HelperPlan) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := plan.Validate(); err != nil {
		return err
	}
	digest, err := helperprotocol.Digest(plan)
	if err != nil {
		return err
	}
	record := planRecord{Plan: plan, Digest: digest}
	path := filepath.Join(j.plansDir, plan.HelperPlanID+".json")
	if _, err := os.Lstat(path); err == nil {
		existing, loadErr := j.loadPlanLocked(plan.HelperPlanID)
		if loadErr != nil {
			return loadErr
		}
		existingDigest, digestErr := helperprotocol.Digest(existing)
		if digestErr != nil || existingDigest != digest {
			return ErrRequestConflict
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := j.ensurePlanCapacityLocked(time.Now().UTC()); err != nil {
		return err
	}
	if err := j.writeRecord(path, record, true); err != nil {
		return err
	}
	return nil
}

func (j *Journal) StoreManagedPlan(plan helperprotocol.ManagedApplyPlan, intent helperprotocol.Signed[helperprotocol.ApplyIntent]) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if plan.Validate() != nil || intent.Validate() != nil || intent.Envelope.MessageType != helperprotocol.MessageApplyIntent {
		return fmt.Errorf("invalid managed helper plan")
	}
	planDigest, err := helperprotocol.Digest(plan)
	if err != nil {
		return err
	}
	intentDigest, err := helperprotocol.Digest(intent)
	if err != nil {
		return err
	}
	record := managedPlanRecord{Plan: plan, Intent: intent, PlanDigest: planDigest, IntentDigest: intentDigest}
	path := filepath.Join(j.managedPlansDir, plan.HelperPlanID+".json")
	if _, err := os.Lstat(path); err == nil {
		existingPlan, existingIntent, loadErr := j.loadManagedPlanLocked(plan.HelperPlanID)
		if loadErr != nil {
			return loadErr
		}
		existingPlanDigest, planErr := helperprotocol.Digest(existingPlan)
		existingIntentDigest, intentErr := helperprotocol.Digest(existingIntent)
		if planErr != nil || intentErr != nil || existingPlanDigest != planDigest || existingIntentDigest != intentDigest {
			return ErrRequestConflict
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := j.ensureManagedPlanCapacityLocked(time.Now().UTC()); err != nil {
		return err
	}
	return j.writeRecord(path, record, true)
}

func (j *Journal) ensureManagedPlanCapacityLocked(now time.Time) error {
	entries, err := os.ReadDir(j.managedPlansDir)
	if err != nil {
		return err
	}
	remaining := 0
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return fmt.Errorf("%w: unexpected managed plan journal entry", ErrJournalCorrupt)
		}
		planID := strings.TrimSuffix(name, ".json")
		plan, _, err := j.loadManagedPlanLocked(planID)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
		}
		if !timeAfter(now, plan.ExpiresAt) {
			if err := os.Remove(filepath.Join(j.managedPlansDir, name)); err != nil {
				return err
			}
			removed = true
			continue
		}
		remaining++
	}
	if removed {
		if err := syncDirectory(j.managedPlansDir); err != nil {
			return err
		}
	}
	if remaining >= maxStoredPlans {
		return ErrPlanQuota
	}
	return nil
}

func (j *Journal) ensurePlanCapacityLocked(now time.Time) error {
	entries, err := os.ReadDir(j.plansDir)
	if err != nil {
		return err
	}
	remaining := 0
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return fmt.Errorf("%w: unexpected plan journal entry", ErrJournalCorrupt)
		}
		planID := strings.TrimSuffix(name, ".json")
		plan, err := j.loadPlanLocked(planID)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
		}
		if !timeAfter(now, plan.ExpiresAt) {
			if err := os.Remove(filepath.Join(j.plansDir, name)); err != nil {
				return err
			}
			removed = true
			continue
		}
		remaining++
	}
	if removed {
		if err := syncDirectory(j.plansDir); err != nil {
			return err
		}
	}
	if remaining >= maxStoredPlans {
		return ErrPlanQuota
	}
	return nil
}

func (j *Journal) LoadPlan(planID string) (helperprotocol.HelperPlan, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.loadPlanLocked(planID)
}

func (j *Journal) LoadManagedPlan(planID string) (helperprotocol.ManagedApplyPlan, helperprotocol.Signed[helperprotocol.ApplyIntent], error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.loadManagedPlanLocked(planID)
}

func (j *Journal) FindCompatibleManagedPlan(intent helperprotocol.Signed[helperprotocol.ApplyIntent], candidate helperprotocol.ManagedApplyPlan, now time.Time) (helperprotocol.ManagedApplyPlan, bool, error) {
	if intent.Validate() != nil || candidate.Validate() != nil || now.IsZero() {
		return helperprotocol.ManagedApplyPlan{}, false, ErrPlanNotFound
	}
	intentDigest, err := helperprotocol.Digest(intent)
	if err != nil {
		return helperprotocol.ManagedApplyPlan{}, false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.managedPlansDir)
	if err != nil {
		return helperprotocol.ManagedApplyPlan{}, false, err
	}
	var selected helperprotocol.ManagedApplyPlan
	var selectedModTime time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return helperprotocol.ManagedApplyPlan{}, false, ErrJournalCorrupt
		}
		planID := strings.TrimSuffix(entry.Name(), ".json")
		plan, storedIntent, loadErr := j.loadManagedPlanLocked(planID)
		if loadErr != nil {
			return helperprotocol.ManagedApplyPlan{}, false, loadErr
		}
		storedDigest, digestErr := helperprotocol.Digest(storedIntent)
		if digestErr != nil {
			return helperprotocol.ManagedApplyPlan{}, false, digestErr
		}
		if storedDigest != intentDigest || !timeAfter(now, plan.ExpiresAt) || !compatibleManagedPlan(plan, candidate) {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return helperprotocol.ManagedApplyPlan{}, false, statErr
		}
		if selected.HelperPlanID == "" || info.ModTime().Before(selectedModTime) || (info.ModTime().Equal(selectedModTime) && plan.HelperPlanID < selected.HelperPlanID) {
			selected, selectedModTime = plan, info.ModTime()
		}
	}
	return selected, selected.HelperPlanID != "", nil
}

func compatibleManagedPlan(stored, candidate helperprotocol.ManagedApplyPlan) bool {
	stored.HelperPlanID, stored.ExpiresAt = "", ""
	candidate.HelperPlanID, candidate.ExpiresAt = "", ""
	return stored == candidate
}

func (j *Journal) loadManagedPlanLocked(planID string) (helperprotocol.ManagedApplyPlan, helperprotocol.Signed[helperprotocol.ApplyIntent], error) {
	if !validConfigID(planID) {
		return helperprotocol.ManagedApplyPlan{}, helperprotocol.Signed[helperprotocol.ApplyIntent]{}, ErrPlanNotFound
	}
	payload, err := readTrustedFile(filepath.Join(j.managedPlansDir, planID+".json"), j.ownerUID, helperprotocol.MaxFrameBytes, true)
	if os.IsNotExist(rootCause(err)) {
		return helperprotocol.ManagedApplyPlan{}, helperprotocol.Signed[helperprotocol.ApplyIntent]{}, ErrPlanNotFound
	}
	if err != nil {
		return helperprotocol.ManagedApplyPlan{}, helperprotocol.Signed[helperprotocol.ApplyIntent]{}, err
	}
	record, err := helperprotocol.Decode[managedPlanRecord](payload)
	if err != nil {
		return helperprotocol.ManagedApplyPlan{}, helperprotocol.Signed[helperprotocol.ApplyIntent]{}, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	return record.Plan, record.Intent, nil
}

func (j *Journal) loadPlanLocked(planID string) (helperprotocol.HelperPlan, error) {
	if !validConfigID(planID) {
		return helperprotocol.HelperPlan{}, ErrPlanNotFound
	}
	payload, err := readTrustedFile(filepath.Join(j.plansDir, planID+".json"), j.ownerUID, helperprotocol.MaxFrameBytes, true)
	if os.IsNotExist(rootCause(err)) {
		return helperprotocol.HelperPlan{}, ErrPlanNotFound
	}
	if err != nil {
		return helperprotocol.HelperPlan{}, err
	}
	record, err := helperprotocol.Decode[planRecord](payload)
	if err != nil {
		return helperprotocol.HelperPlan{}, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	return record.Plan, nil
}

func (j *Journal) BeginOperation(operationID, grantID, requestDigest string, action helperprotocol.Action) (OperationRecord, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !validConfigID(operationID) || !validConfigID(grantID) || !validDigest(requestDigest) || !action.Valid() {
		return OperationRecord{}, false, fmt.Errorf("invalid operation identity")
	}
	if existing, err := j.loadOperationLocked(operationID); err == nil {
		if existing.GrantID != grantID || existing.CanonicalRequestDigest != requestDigest || existing.Action != action {
			return OperationRecord{}, false, ErrRequestConflict
		}
		return existing, true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return OperationRecord{}, false, err
	}
	claim := grantClaim{GrantID: grantID, OperationID: operationID, CanonicalRequestDigest: requestDigest}
	claimPath := filepath.Join(j.grantsDir, grantID+".json")
	if err := j.writeRecord(claimPath, claim, true); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return OperationRecord{}, false, err
		}
		existingClaim, loadErr := j.loadGrantLocked(grantID)
		if loadErr != nil {
			return OperationRecord{}, false, loadErr
		}
		if existingClaim.OperationID != operationID || existingClaim.CanonicalRequestDigest != requestDigest {
			return OperationRecord{}, false, ErrGrantReplay
		}
	}
	record := OperationRecord{
		OperationID:            operationID,
		GrantID:                grantID,
		CanonicalRequestDigest: requestDigest,
		Action:                 action,
		State:                  helperprotocol.JournalAuthorized,
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := j.writeRecord(filepath.Join(j.operationsDir, operationID+".json"), record, true); err != nil {
		if errors.Is(err, fs.ErrExist) {
			existing, loadErr := j.loadOperationLocked(operationID)
			if loadErr == nil && existing.GrantID == grantID && existing.CanonicalRequestDigest == requestDigest && existing.Action == action {
				return existing, true, nil
			}
			return OperationRecord{}, false, ErrRequestConflict
		}
		return OperationRecord{}, false, err
	}
	return record, false, nil
}

func (j *Journal) Transition(operationID string, next helperprotocol.JournalState, receipt helperprotocol.HelperReceipt) (OperationRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, err := j.loadOperationLocked(operationID)
	if err != nil {
		return OperationRecord{}, err
	}
	if !helperprotocol.CanTransition(record.State, next) {
		return OperationRecord{}, fmt.Errorf("invalid journal transition %s -> %s", record.State, next)
	}
	if err := receipt.Validate(); err != nil || receipt.OperationID != record.OperationID ||
		receipt.CanonicalRequestDigest != record.CanonicalRequestDigest || receipt.Action != record.Action || receipt.State != next {
		return OperationRecord{}, fmt.Errorf("receipt does not bind to journal transition")
	}
	record.State = next
	record.Receipt = &receipt
	record.UpdatedAt = receipt.UpdatedAt
	if err := j.writeRecord(filepath.Join(j.operationsDir, operationID+".json"), record, false); err != nil {
		return OperationRecord{}, err
	}
	return record, nil
}

func (j *Journal) GetReceipt(operationID, requestDigest string) (helperprotocol.HelperReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, err := j.loadOperationLocked(operationID)
	if err != nil {
		return helperprotocol.HelperReceipt{}, err
	}
	if record.CanonicalRequestDigest != requestDigest {
		return helperprotocol.HelperReceipt{}, ErrRequestConflict
	}
	if record.Receipt == nil {
		return helperprotocol.HelperReceipt{}, ErrReceiptNotFound
	}
	return *record.Receipt, nil
}

func (j *Journal) Recover() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.operationsDir)
	if err != nil {
		j.openBreakerLocked("helper journal directory cannot be read")
		return fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			j.openBreakerLocked("helper journal contains an unexpected entry")
			return ErrJournalCorrupt
		}
		operationID := strings.TrimSuffix(entry.Name(), ".json")
		record, loadErr := j.loadOperationLocked(operationID)
		if loadErr != nil {
			j.openBreakerLocked("helper journal record is corrupt")
			return fmt.Errorf("%w: %v", ErrJournalCorrupt, loadErr)
		}
		switch record.State {
		case helperprotocol.JournalRunning, helperprotocol.JournalMutated,
			helperprotocol.JournalValidated, helperprotocol.JournalRollbackRunning:
			if record.Receipt == nil {
				j.openBreakerLocked("privileged execution has no durable recovery receipt")
				return ErrJournalCorrupt
			}
			receipt := *record.Receipt
			receipt.State = helperprotocol.JournalOutcomeIndeterminate
			receipt.SanitizedResult = "previous privileged execution outcome is indeterminate"
			receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			record.State = helperprotocol.JournalOutcomeIndeterminate
			record.Receipt = &receipt
			record.UpdatedAt = receipt.UpdatedAt
			if writeErr := j.writeRecord(filepath.Join(j.operationsDir, operationID+".json"), record, false); writeErr != nil {
				j.openBreakerLocked("failed to persist indeterminate execution state")
				return writeErr
			}
			j.openBreakerLocked("previous privileged execution outcome is indeterminate")
		}
	}
	return nil
}

// Prune removes finished operations, with their grant claim and snapshot, that
// fall outside the retention window. Non-terminal records, records Recover turns
// into incidents (rollback_failed, outcome_indeterminate) and anything unreadable
// are never touched. A snapshot or grant that is already gone is not an error.
//
// The directory scan runs without the journal lock; removal happens in batches
// of pruneBatchSize, each under the lock and each re-reading the record first,
// so a large backlog never blocks a request for more than one batch. A failed
// removal is skipped and reported in the joined error; the pass goes on. Only
// one pass runs at a time; a concurrent call returns immediately.
func (j *Journal) Prune(now time.Time) (PruneResult, error) {
	if !j.pruneMu.TryLock() {
		return PruneResult{}, nil
	}
	defer j.pruneMu.Unlock()
	j.mu.Lock()
	j.lastPrune = now
	j.mu.Unlock()
	return j.prune(now)
}

// PruneIfDue runs Prune at most once per journalPruneInterval.
func (j *Journal) PruneIfDue(now time.Time) (PruneResult, bool, error) {
	j.mu.Lock()
	due := j.lastPrune.IsZero() || now.Sub(j.lastPrune) >= journalPruneInterval
	j.mu.Unlock()
	if !due {
		return PruneResult{}, false, nil
	}
	result, err := j.Prune(now)
	return result, true, err
}

type pruneCandidate struct {
	record  OperationRecord
	updated time.Time
}

func (j *Journal) prune(now time.Time) (PruneResult, error) {
	expired, err := j.pruneCandidates(now)
	if err != nil {
		return PruneResult{}, err
	}
	var result PruneResult
	var errs []error
	for start := 0; start < len(expired); start += pruneBatchSize {
		end := min(start+pruneBatchSize, len(expired))
		errs = append(errs, j.removeOperationBatch(expired[start:end], &result)...)
	}
	return result, errors.Join(errs...)
}

// pruneCandidates reads the operation directory without holding the journal
// lock. Terminal records never change state again, and removal re-checks each
// record under the lock, so a stale read can only make a pass skip a record.
func (j *Journal) pruneCandidates(now time.Time) ([]pruneCandidate, error) {
	entries, err := os.ReadDir(j.operationsDir)
	if err != nil {
		return nil, err
	}
	byAction := make(map[helperprotocol.Action][]pruneCandidate)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		operationID := strings.TrimSuffix(name, ".json")
		record, loadErr := j.loadOperationLocked(operationID)
		if loadErr != nil || record.OperationID != operationID || !prunableJournalState(record.State) {
			continue
		}
		updated, parseErr := time.Parse(time.RFC3339Nano, record.UpdatedAt)
		if parseErr != nil {
			continue
		}
		byAction[record.Action] = append(byAction[record.Action], pruneCandidate{record: record, updated: updated})
	}
	var expired, overflow []pruneCandidate
	retained := 0
	for _, candidates := range byAction {
		sortCandidatesNewestFirst(candidates)
		for index, candidate := range candidates {
			switch {
			case index < operationRetentionPerAction:
				retained++
			case now.Sub(candidate.updated) > operationRetentionAge:
				expired = append(expired, candidate)
			default:
				retained++
				overflow = append(overflow, candidate)
			}
		}
	}
	if retained > maxRetainedOperations {
		sortCandidatesNewestFirst(overflow)
		for index := len(overflow) - 1; index >= 0 && retained > maxRetainedOperations; index-- {
			if now.Sub(overflow[index].updated) < operationRetentionMinAge {
				break
			}
			expired = append(expired, overflow[index])
			retained--
		}
	}
	return expired, nil
}

// removeOperationBatch deletes and fsyncs every snapshot and grant of the batch
// before it deletes any operation record. After a crash an operation record may
// outlive its snapshot or grant (the next pass finishes it), but a grant claim
// never outlives the record that consumed it.
func (j *Journal) removeOperationBatch(batch []pruneCandidate, result *PruneResult) []error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var errs []error
	removable := make([]OperationRecord, 0, len(batch))
	for _, candidate := range batch {
		current, err := j.loadOperationLocked(candidate.record.OperationID)
		if err != nil || current.State != candidate.record.State || current.UpdatedAt != candidate.record.UpdatedAt ||
			current.GrantID != candidate.record.GrantID || !validConfigID(current.GrantID) {
			continue
		}
		if err := removeIfPresent(filepath.Join(j.snapshotsDir, current.OperationID+".json"), &result.Snapshots); err != nil {
			errs = append(errs, fmt.Errorf("prune snapshot %s: %w", current.OperationID, err))
			continue
		}
		// A grant claim that is missing, unreadable or bound to another operation
		// is left alone; only the claim this operation consumed is removed.
		if claim, err := j.loadGrantLocked(current.GrantID); err == nil && claim.OperationID == current.OperationID {
			if err := removeIfPresent(filepath.Join(j.grantsDir, current.GrantID+".json"), &result.Grants); err != nil {
				errs = append(errs, fmt.Errorf("prune grant %s: %w", current.GrantID, err))
				continue
			}
		}
		removable = append(removable, current)
	}
	if len(removable) == 0 {
		return errs
	}
	for _, dir := range []string{j.snapshotsDir, j.grantsDir} {
		if err := syncDirectory(dir); err != nil {
			return append(errs, err)
		}
	}
	for _, record := range removable {
		if err := removeIfPresent(filepath.Join(j.operationsDir, record.OperationID+".json"), &result.Operations); err != nil {
			errs = append(errs, fmt.Errorf("prune operation %s: %w", record.OperationID, err))
		}
	}
	if err := syncDirectory(j.operationsDir); err != nil {
		errs = append(errs, err)
	}
	return errs
}

func removeIfPresent(path string, removed *int) error {
	err := os.Remove(path)
	if err == nil {
		*removed++
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func sortCandidatesNewestFirst(candidates []pruneCandidate) {
	sort.Slice(candidates, func(a, b int) bool {
		if !candidates[a].updated.Equal(candidates[b].updated) {
			return candidates[a].updated.After(candidates[b].updated)
		}
		return candidates[a].record.OperationID > candidates[b].record.OperationID
	})
}

func prunableJournalState(state helperprotocol.JournalState) bool {
	switch state {
	case helperprotocol.JournalSucceeded, helperprotocol.JournalFailedBeforeMutation, helperprotocol.JournalRolledBack:
		return true
	default:
		return false
	}
}

func (j *Journal) BreakerOpen() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.breakerIsOpen
}

func (j *Journal) OpenBreaker(reason string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if strings.TrimSpace(reason) == "" || len(reason) > 512 {
		return fmt.Errorf("invalid breaker reason")
	}
	j.breakerIsOpen = true
	record := breakerRecord{Reason: reason, OpenedAt: time.Now().UTC().Format(time.RFC3339Nano), Permanent: true}
	return j.writeRecord(j.breakerPath, record, false)
}

func (j *Journal) loadOperationLocked(operationID string) (OperationRecord, error) {
	if !validConfigID(operationID) {
		return OperationRecord{}, fs.ErrNotExist
	}
	payload, err := readTrustedFile(filepath.Join(j.operationsDir, operationID+".json"), j.ownerUID, helperprotocol.MaxFrameBytes, true)
	if err != nil {
		if os.IsNotExist(rootCause(err)) {
			return OperationRecord{}, fs.ErrNotExist
		}
		return OperationRecord{}, err
	}
	record, err := helperprotocol.Decode[OperationRecord](payload)
	if err != nil {
		return OperationRecord{}, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	return record, nil
}

func (j *Journal) loadGrantLocked(grantID string) (grantClaim, error) {
	payload, err := readTrustedFile(filepath.Join(j.grantsDir, grantID+".json"), j.ownerUID, helperprotocol.MaxFrameBytes, true)
	if err != nil {
		return grantClaim{}, err
	}
	claim, err := helperprotocol.Decode[grantClaim](payload)
	if err != nil {
		return grantClaim{}, fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
	}
	return claim, nil
}

func (j *Journal) writeRecord(path string, value any, createOnly bool) error {
	payload, err := helperprotocol.CanonicalBytes(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".journal-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if createOnly {
		if err := os.Link(tmpPath, path); err != nil {
			return err
		}
	} else if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func (j *Journal) openBreakerLocked(reason string) {
	j.breakerIsOpen = true
	record := breakerRecord{Reason: reason, OpenedAt: time.Now().UTC().Format(time.RFC3339Nano), Permanent: true}
	_ = j.writeRecord(j.breakerPath, record, false)
}

func ensurePrivateDirectory(path string, ownerUID uint32) error {
	if err := validatePrivatePath(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := validateTrustedDirectory(parent, ownerUID); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileOwnerUID(info) != ownerUID || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("helper journal directory is not private and trusted")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func canonicalTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}
