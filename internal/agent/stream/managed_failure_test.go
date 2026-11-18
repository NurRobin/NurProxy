package stream

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/helperclient"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func TestManagedApplyFailureMessage(t *testing.T) {
	const base = "privileged managed proxy reconciliation failed"
	refused := func(reason string) error {
		return fmt.Errorf("plan managed proxy state: %w", &helperclient.RemoteError{
			Code: helperprotocol.ErrorAmbiguousLocalTarget, Message: helperprotocol.ManagedPlanRefusedMessage + ": " + reason,
		})
	}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"plain error", errors.New("dial unix: no such file"), base},
		{"refusal without reason", fmt.Errorf("x: %w", &helperclient.RemoteError{Code: helperprotocol.ErrorAmbiguousLocalTarget, Message: helperprotocol.ManagedPlanRefusedMessage}), base},
		{"other code keeps text out", fmt.Errorf("x: %w", &helperclient.RemoteError{Code: helperprotocol.ErrorRequestConflict, Message: helperprotocol.ManagedPlanRefusedMessage + ": secret"}), base},
		{"refusal reason", refused("raw apache config for a.example.com refused: line 1: LoadModule: not allowed"), base + ": raw apache config for a.example.com refused: line 1: LoadModule: not allowed"},
		{"control characters dropped", refused("a\nb\x00c"), base + ": abc"},
		{"long reason bounded", refused(strings.Repeat("x", 2000)), base + ": " + strings.Repeat("x", maxManagedRefusalBytes)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := managedApplyFailureMessage(tt.err); got != tt.want {
				t.Fatalf("managedApplyFailureMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}
