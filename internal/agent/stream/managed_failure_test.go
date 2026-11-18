package stream

import (
	"errors"
	"fmt"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/helperclient"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func TestManagedApplyFailureCarriesHelperReason(t *testing.T) {
	const fixed = "privileged managed proxy reconciliation failed"
	reason := `local managed apply planning refused the desired state: raw nginx config for app.example.com: line 5: nginx directive "include" is not allowed in the server block`
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "helper refusal",
			err:  fmt.Errorf("plan managed proxy state: %w", &helperclient.RemoteError{Code: helperprotocol.ErrorAmbiguousLocalTarget, Message: reason}),
			want: fixed + ": " + reason,
		},
		{name: "empty helper message", err: &helperclient.RemoteError{Code: helperprotocol.ErrorAmbiguousLocalTarget, Message: " "}, want: fixed},
		{name: "local error", err: errors.New("authorize managed proxy state: connection refused"), want: fixed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := managedApplyFailure(tt.err); got != tt.want {
				t.Fatalf("managedApplyFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}
