package recovery

import "github.com/NurRobin/NurProxy/internal/shared/recoverymodel"

type RestartDisposition string

const (
	RestartNone             RestartDisposition = "none"
	RestartBeginRollback    RestartDisposition = "begin_rollback"
	RestartResumeValidation RestartDisposition = "resume_validation"
	RestartResumeRollback   RestartDisposition = "resume_rollback"
)

func ValidTransition(from, to recoverymodel.OperationState) bool {
	if from == to {
		return from.Valid()
	}
	switch from {
	case recoverymodel.OperationStatePlanned:
		return to == recoverymodel.OperationStateSnapshotted
	case recoverymodel.OperationStateSnapshotted:
		return to == recoverymodel.OperationStateApplying || to == recoverymodel.OperationStateRollingBack
	case recoverymodel.OperationStateApplying:
		return to == recoverymodel.OperationStateValidating || to == recoverymodel.OperationStateRollingBack
	case recoverymodel.OperationStateValidating:
		return to == recoverymodel.OperationStateSucceeded || to == recoverymodel.OperationStateRollingBack
	case recoverymodel.OperationStateRollingBack:
		return to == recoverymodel.OperationStateRolledBack || to == recoverymodel.OperationStateRollbackFailed
	default:
		return false
	}
}

func RestartDispositionFor(state recoverymodel.OperationState) RestartDisposition {
	switch state {
	case recoverymodel.OperationStateApplying:
		return RestartBeginRollback
	case recoverymodel.OperationStateValidating:
		return RestartResumeValidation
	case recoverymodel.OperationStateRollingBack:
		return RestartResumeRollback
	default:
		return RestartNone
	}
}
