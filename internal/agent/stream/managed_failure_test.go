package stream

import (
	"errors"
	"fmt"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/helperclient"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

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
