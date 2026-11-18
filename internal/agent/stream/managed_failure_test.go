package stream

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/helperclient"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
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

func TestAttributeManagedFailureBlamesTheNamedVhost(t *testing.T) {
	const base = "privileged managed proxy reconciliation did not succeed"
	nginxResult := `managed apply failed and privileged pre-state was fully restored; native validation: nginx: [emerg] "gzip" directive is duplicate in /etc/nginx/sites-enabled/nurproxy-b.example.com.conf:9 | nginx: configuration file /etc/nginx/nginx.conf test failed`
	apacheResult := `managed apply failed and privileged pre-state was fully restored; native validation: AH00526: Syntax error on line 4 of /etc/apache2/sites-enabled/nurproxy-a.example.com.conf: | Invalid command 'Foo'`
	tests := []struct {
		name   string
		kind   proxy.Kind
		result string
		want   []string
	}{
		{
			name: "nginx names one vhost", kind: proxy.KindNginx, result: nginxResult,
			want: []string{
				base + ": the proxy rejected the config of b.example.com, so no domain on this agent was applied",
				base + ": the proxy rejected this domain's config: " + nginxResult,
				base + ": the proxy rejected the config of b.example.com, so no domain on this agent was applied",
			},
		},
		{
			name: "apache names one vhost", kind: proxy.KindApache, result: apacheResult,
			want: []string{
				base + ": the proxy rejected this domain's config: " + apacheResult,
				base + ": the proxy rejected the config of a.example.com, so no domain on this agent was applied",
				base + ": the proxy rejected the config of a.example.com, so no domain on this agent was applied",
			},
		},
		{
			name: "no managed file named", kind: proxy.KindNginx,
			result: "native validation: nginx: [emerg] unknown directive in /etc/nginx/conf.d/other.conf:3",
			want:   []string{base, base, base},
		},
		{
			name: "suffix of another host is not a match", kind: proxy.KindNginx,
			result: "nginx: [emerg] x in /etc/nginx/sites-enabled/nurproxy-x.b.example.com.conf:1",
			want:   []string{base, base, base},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := proxymodel.IntentSet{}
			reports := make([]proxymodel.ArtifactReport, 0, 3)
			for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
				set.Intents = append(set.Intents, proxymodel.RouteIntent{ArtifactID: host, Route: proxymodel.Route{Host: host}})
				reports = append(reports, proxymodel.ArtifactReport{ArtifactID: host, Host: host, Error: base})
			}
			attributeManagedFailure(reports, set, tt.kind, base, tt.result)
			for i, report := range reports {
				if report.Error != tt.want[i] {
					t.Errorf("%s: error = %q, want %q", report.Host, report.Error, tt.want[i])
				}
			}
		})
	}
}
