package recoverycontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

type fakeHelper struct {
	plan       helperprotocol.Signed[helperprotocol.HelperPlan]
	receipt    helperprotocol.Signed[helperprotocol.HelperReceipt]
	planCalls  int
	execCalls  int
	getCalls   int
	executeErr error
	digest     string
}

func (h *fakeHelper) Plan(context.Context, helperprotocol.Action, helperprotocol.LogicalTarget, string) (helperprotocol.Signed[helperprotocol.HelperPlan], error) {
	h.planCalls++
	return h.plan, nil
}

func (h *fakeHelper) Execute(context.Context, helperprotocol.Signed[helperprotocol.ExecutionGrant]) (helperprotocol.Signed[helperprotocol.HelperReceipt], string, error) {
	h.execCalls++
	return h.receipt, h.digest, h.executeErr
}

func (h *fakeHelper) GetReceipt(context.Context, string, string) (helperprotocol.Signed[helperprotocol.HelperReceipt], error) {
	h.getCalls++
	return h.receipt, nil
}

type fakeRemote struct {
	records          []ExecutionRecord
	submittedPlans   []helperprotocol.Signed[helperprotocol.HelperPlan]
	submittedReceipt []helperprotocol.Signed[helperprotocol.HelperReceipt]
	submitPlanErr    error
}

func (r *fakeRemote) ListPlans(context.Context) ([]ExecutionRecord, error) {
	return append([]ExecutionRecord(nil), r.records...), nil
}
func (r *fakeRemote) SubmitPlan(_ context.Context, plan helperprotocol.Signed[helperprotocol.HelperPlan]) error {
	r.submittedPlans = append(r.submittedPlans, plan)
	return r.submitPlanErr
}
func (r *fakeRemote) SubmitReceipt(_ context.Context, _ string, receipt helperprotocol.Signed[helperprotocol.HelperReceipt]) error {
	r.submittedReceipt = append(r.submittedReceipt, receipt)
	return nil
}

func hardDiagnostic() recoverymodel.Diagnostic {
	return recoverymodel.Diagnostic{
		ID: "diagnostic-1", Code: recoverymodel.CodeProxyReloadFailed,
		RepairScope: recoverymodel.RepairScopeDetectedProxyService, RepairEligible: true, HardChange: true,
		ResourceFingerprint: strings.Repeat("b", 64),
	}
}

func helperPlan() helperprotocol.Signed[helperprotocol.HelperPlan] {
	return helperprotocol.Signed[helperprotocol.HelperPlan]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageHelperPlan, helperprotocol.HelperPlan{
		HelperPlanID: "plan-1", DiagnosticID: "diagnostic-1", Action: helperprotocol.ActionValidateReloadProxy,
		LogicalTarget: helperprotocol.LogicalTargetDetectedProxy, ResourceFingerprint: strings.Repeat("b", 64),
	})}
}

func TestControllerPlansOnlyMappedHardDiagnostics(t *testing.T) {
	helper := &fakeHelper{plan: helperPlan()}
	remote := &fakeRemote{}
	controller := New(helper, remote)
	if err := controller.Reconcile(context.Background(), []recoverymodel.Diagnostic{hardDiagnostic()}); err != nil {
		t.Fatal(err)
	}
	if helper.planCalls != 1 || len(remote.submittedPlans) != 1 || helper.execCalls != 0 {
		t.Fatalf("calls: plan=%d submit=%d execute=%d", helper.planCalls, len(remote.submittedPlans), helper.execCalls)
	}
	unsupported := hardDiagnostic()
	unsupported.ID = "diagnostic-unsupported"
	unsupported.Code = recoverymodel.CodePortConflict
	unsupported.RepairScope = recoverymodel.RepairScopeUnsupportedEnvironment
	unsupported.RepairEligible = false
	if err := controller.Reconcile(context.Background(), []recoverymodel.Diagnostic{unsupported}); err != nil {
		t.Fatal(err)
	}
	if helper.planCalls != 1 {
		t.Fatal("unsupported diagnostic reached the root helper")
	}
}

func TestControllerExecutesGrantAndSubmitsAttestedReceipt(t *testing.T) {
	receipt := helperprotocol.Signed[helperprotocol.HelperReceipt]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, helperprotocol.HelperReceipt{
		OperationID: "operation-1", CanonicalRequestDigest: strings.Repeat("d", 64),
	})}
	helper := &fakeHelper{receipt: receipt, digest: strings.Repeat("d", 64)}
	grant := helperprotocol.Signed[helperprotocol.ExecutionGrant]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, helperprotocol.ExecutionGrant{
		OperationID: "operation-1", HelperPlanID: "plan-1", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
	})}
	remote := &fakeRemote{records: []ExecutionRecord{{
		HelperPlanID: "plan-1", DiagnosticID: "diagnostic-1", ResourceFingerprint: strings.Repeat("b", 64),
		ExpiresAt: time.Now().UTC().Add(time.Minute), SignedGrant: &grant,
	}}}
	controller := New(helper, remote)
	if err := controller.Reconcile(context.Background(), []recoverymodel.Diagnostic{hardDiagnostic()}); err != nil {
		t.Fatal(err)
	}
	if helper.execCalls != 1 || len(remote.submittedReceipt) != 1 || helper.planCalls != 0 {
		t.Fatalf("calls: execute=%d receipt=%d plan=%d", helper.execCalls, len(remote.submittedReceipt), helper.planCalls)
	}
}

func TestControllerRecoversReceiptAfterAmbiguousExecuteResponse(t *testing.T) {
	receipt := helperprotocol.Signed[helperprotocol.HelperReceipt]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageHelperReceipt, helperprotocol.HelperReceipt{
		OperationID: "operation-1", CanonicalRequestDigest: strings.Repeat("d", 64),
	})}
	helper := &fakeHelper{receipt: receipt, digest: strings.Repeat("d", 64), executeErr: errors.New("response lost")}
	grant := helperprotocol.Signed[helperprotocol.ExecutionGrant]{Envelope: helperprotocol.NewEnvelope(helperprotocol.MessageExecutionGrant, helperprotocol.ExecutionGrant{
		OperationID: "operation-1", HelperPlanID: "plan-1", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
	})}
	remote := &fakeRemote{records: []ExecutionRecord{{
		HelperPlanID: "plan-1", DiagnosticID: "diagnostic-1", ResourceFingerprint: strings.Repeat("b", 64),
		ExpiresAt: time.Now().UTC().Add(time.Minute), SignedGrant: &grant,
	}}}
	if err := New(helper, remote).Reconcile(context.Background(), []recoverymodel.Diagnostic{hardDiagnostic()}); err != nil {
		t.Fatal(err)
	}
	if helper.execCalls != 1 || helper.getCalls != 1 || len(remote.submittedReceipt) != 1 {
		t.Fatalf("calls: execute=%d get=%d submit=%d", helper.execCalls, helper.getCalls, len(remote.submittedReceipt))
	}
}

func TestControllerRetriesTheSameUnsubmittedHelperPlan(t *testing.T) {
	plan := helperPlan()
	plan.Envelope.Payload.ExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	helper := &fakeHelper{plan: plan}
	remote := &fakeRemote{submitPlanErr: errors.New("orchestrator unavailable")}
	controller := New(helper, remote)
	if err := controller.Reconcile(context.Background(), []recoverymodel.Diagnostic{hardDiagnostic()}); err == nil {
		t.Fatal("first submission failure was hidden")
	}
	remote.submitPlanErr = nil
	if err := controller.Reconcile(context.Background(), []recoverymodel.Diagnostic{hardDiagnostic()}); err != nil {
		t.Fatal(err)
	}
	if helper.planCalls != 1 || len(remote.submittedPlans) != 2 || remote.submittedPlans[0].Envelope.Payload.HelperPlanID != remote.submittedPlans[1].Envelope.Payload.HelperPlanID {
		t.Fatalf("plan calls=%d submissions=%#v", helper.planCalls, remote.submittedPlans)
	}
}
