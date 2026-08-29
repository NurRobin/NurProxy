package recoverycontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const DefaultStagingRoot = "/var/lib/nurproxy-agent/helper-staging"

var ErrManagedStagingAccess = errors.New("exclusive managed staging access denied")

type ManagedHelper interface {
	PlanManagedApply(context.Context, helperprotocol.Signed[helperprotocol.ApplyIntent]) (helperprotocol.Signed[helperprotocol.ManagedApplyPlan], error)
	ExecuteManagedApply(context.Context, helperprotocol.Signed[helperprotocol.ApplyGrant]) (helperprotocol.Signed[helperprotocol.HelperReceipt], string, error)
	GetReceipt(context.Context, string, string) (helperprotocol.Signed[helperprotocol.HelperReceipt], error)
}

type ManagedOrchestrator interface {
	AuthorizeManagedApply(context.Context, string, helperprotocol.Signed[helperprotocol.ManagedApplyPlan]) (ManagedExecutionRecord, error)
	SubmitManagedReceipt(context.Context, string, helperprotocol.Signed[helperprotocol.HelperReceipt]) error
}

type ManagedExecutionRecord struct {
	OperationID   string                                               `json:"operation_id"`
	SignedGrant   *helperprotocol.Signed[helperprotocol.ApplyGrant]    `json:"signed_apply_grant,omitempty"`
	SignedReceipt *helperprotocol.Signed[helperprotocol.HelperReceipt] `json:"signed_helper_receipt,omitempty"`
}

type ManagedController struct {
	mu          sync.Mutex
	helper      ManagedHelper
	remote      ManagedOrchestrator
	stagingRoot string
}

func NewManaged(helper ManagedHelper, remote ManagedOrchestrator, stagingRoot string) (*ManagedController, error) {
	if helper == nil || remote == nil || !filepath.IsAbs(stagingRoot) || filepath.Clean(stagingRoot) != stagingRoot || stagingRoot == string(filepath.Separator) {
		return nil, fmt.Errorf("managed apply controller is not safely configured")
	}
	return &ManagedController{helper: helper, remote: remote, stagingRoot: stagingRoot}, nil
}

func (c *ManagedController) Apply(ctx context.Context, envelope helperprotocol.ManagedIntentSetEnvelope) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	if c == nil || envelope.Validate() != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("invalid managed desired-state envelope")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	operationID := envelope.Intent.Envelope.Payload.OperationID
	cleanup, err := c.stage(envelope)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, err
	}
	defer cleanup()
	plan, err := c.helper.PlanManagedApply(ctx, envelope.Intent)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("plan managed proxy state: %w", err)
	}
	if plan.Envelope.Payload.OperationID != operationID || plan.Envelope.Payload.HelperInstanceID != envelope.Intent.Envelope.Payload.HelperInstanceID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("helper managed plan changed the authorized identity")
	}
	record, err := c.remote.AuthorizeManagedApply(ctx, operationID, plan)
	if err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("authorize managed proxy state: %w", err)
	}
	if record.OperationID != operationID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("orchestrator returned another managed operation")
	}
	if record.SignedReceipt != nil {
		return *record.SignedReceipt, nil
	}
	if record.SignedGrant == nil || record.SignedGrant.Envelope.Payload.OperationID != operationID ||
		record.SignedGrant.Envelope.Payload.HelperPlanID != plan.Envelope.Payload.HelperPlanID {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("orchestrator returned no exact managed apply grant")
	}
	receipt, requestDigest, executeErr := c.helper.ExecuteManagedApply(ctx, *record.SignedGrant)
	if executeErr != nil && requestDigest != "" {
		if recovered, receiptErr := c.helper.GetReceipt(ctx, operationID, requestDigest); receiptErr == nil {
			receipt, executeErr = recovered, nil
		} else {
			executeErr = errors.Join(executeErr, receiptErr)
		}
	}
	if executeErr != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("execute managed proxy state: %w", executeErr)
	}
	if receipt.Envelope.Payload.OperationID != operationID || receipt.Envelope.Payload.Action != helperprotocol.ActionApplyManagedProxyState ||
		!managedTerminalState(receipt.Envelope.Payload.State) {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("helper returned an invalid managed apply receipt")
	}
	if err := c.remote.SubmitManagedReceipt(ctx, operationID, receipt); err != nil {
		return helperprotocol.Signed[helperprotocol.HelperReceipt]{}, fmt.Errorf("submit managed apply receipt: %w", err)
	}
	return receipt, nil
}

func (c *ManagedController) stage(envelope helperprotocol.ManagedIntentSetEnvelope) (func(), error) {
	rootInfo, err := os.Lstat(c.stagingRoot)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%w: inspect staging root: %w", ErrManagedStagingAccess, err)
		}
		return nil, fmt.Errorf("managed staging root is unavailable or not bounded")
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("managed staging root is unavailable or not bounded")
	}
	if rootInfo.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("%w: staging root grants access outside its owner and group", ErrManagedStagingAccess)
	}
	root, err := os.OpenRoot(c.stagingRoot)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%w: open staging root: %w", ErrManagedStagingAccess, err)
		}
		return nil, fmt.Errorf("open managed staging root: %w", err)
	}
	operationID := envelope.Intent.Envelope.Payload.OperationID
	_ = root.RemoveAll(operationID)
	if err := root.Mkdir(operationID, 0o700); err != nil {
		root.Close()
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%w: create staging operation: %w", ErrManagedStagingAccess, err)
		}
		return nil, fmt.Errorf("create managed staging operation: %w", err)
	}
	cleanup := func() {
		_ = root.RemoveAll(operationID)
		_ = root.Close()
	}
	operationRoot, err := root.OpenRoot(operationID)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open managed staging operation: %w", err)
	}
	defer operationRoot.Close()
	certificates := make(map[string]struct{ cert, key []byte }, len(envelope.IntentSet.Certs))
	for _, certificate := range envelope.IntentSet.Certs {
		certificates[certificate.Host] = struct{ cert, key []byte }{cert: []byte(certificate.CertPEM), key: []byte(certificate.KeyPEM)}
	}
	for _, artifact := range envelope.Intent.Envelope.Payload.Artifacts {
		pair, ok := certificates[artifact.Name]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("signed artifact has no desired certificate material")
		}
		var data []byte
		switch artifact.Kind {
		case "certificate":
			data = pair.cert
		case "source_key":
			data = pair.key
		default:
			cleanup()
			return nil, fmt.Errorf("unsupported managed staged artifact kind")
		}
		digest := sha256.Sum256(data)
		if int64(len(data)) != artifact.Size || hex.EncodeToString(digest[:]) != artifact.SHA256 {
			cleanup()
			return nil, fmt.Errorf("desired certificate bytes do not match signed artifact manifest")
		}
		name, err := helperprotocol.StagedArtifactFileName(artifact)
		if err != nil {
			cleanup()
			return nil, err
		}
		file, err := operationRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("create staged artifact: %w", err)
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			cleanup()
			return nil, fmt.Errorf("write staged artifact: %w", err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			cleanup()
			return nil, fmt.Errorf("sync staged artifact: %w", err)
		}
		if err := file.Close(); err != nil {
			cleanup()
			return nil, fmt.Errorf("close staged artifact: %w", err)
		}
	}
	if err := syncRoot(operationRoot); err != nil {
		cleanup()
		return nil, err
	}
	if err := syncRoot(root); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, fs.ErrInvalid) {
		return err
	}
	return nil
}

func managedTerminalState(state helperprotocol.JournalState) bool {
	switch state {
	case helperprotocol.JournalSucceeded, helperprotocol.JournalRolledBack,
		helperprotocol.JournalRollbackFailed, helperprotocol.JournalFailedBeforeMutation,
		helperprotocol.JournalOutcomeIndeterminate:
		return true
	default:
		return false
	}
}
