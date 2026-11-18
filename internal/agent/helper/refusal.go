package helper

import (
	"errors"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// maxRefusalReasonBytes keeps a refusal reason, with the fixed message in
// front of it, inside the 512-byte protocol error message.
const maxRefusalReasonBytes = 400

// localPolicyRefusal is a managed apply refusal by the helper's own host
// policy whose reason is written for the operator: it names the domain and
// what to change, and carries no secret or file content. The engine sends
// the reason back to the agent, which puts it into the domain's error.
type localPolicyRefusal struct {
	reason string
}

func refuseLocally(format string, args ...any) error {
	return &localPolicyRefusal{reason: sanitizeNativeDiagnostic(fmt.Sprintf(format, args...))}
}

func (e *localPolicyRefusal) Error() string { return e.reason }

// localPolicyRefusalReason returns the operator-facing reason in err's
// chain, or "" when err is not a local policy refusal.
func localPolicyRefusalReason(err error) string {
	var refusal *localPolicyRefusal
	if errors.As(err, &refusal) {
		return truncateUTF8(refusal.reason, maxRefusalReasonBytes)
	}
	return ""
}

// managedPlanRefusedMessage is the protocol message for a refused managed
// plan, with the refusal reason appended when err carries one.
func managedPlanRefusedMessage(err error) string {
	if reason := localPolicyRefusalReason(err); reason != "" {
		return helperprotocol.ManagedPlanRefusedMessage + ": " + reason
	}
	return helperprotocol.ManagedPlanRefusedMessage
}
