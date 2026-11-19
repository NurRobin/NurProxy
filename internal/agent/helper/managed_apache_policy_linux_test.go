//go:build linux

package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const boundedApacheRaw = `<VirtualHost *:80>
    ServerName app.example.com
    Header always set X-Frame-Options "DENY"
    ProxyPreserveHost On
    ProxyPass / http://10.0.0.2:8080/
    ProxyPassReverse / http://10.0.0.2:8080/
</VirtualHost>
`

// apacheApplyTest is a managed apply action for an Apache target with one
// raw route whose content set replaces.
type apacheApplyTest struct {
	action *managedApplyAction
	intent *helperprotocol.ApplyIntent
}

func newApacheManagedApplyTest(t *testing.T) apacheApplyTest {
	t.Helper()
	action, intent, _ := newManagedApplyTest(t)
	action.target.Kind = "apache"
	intent.Routes[0].Backend = "apache"
	return apacheApplyTest{action: action, intent: &intent}
}

func (a apacheApplyTest) set(raw string) {
	a.intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "apache", Content: raw}
}

func (a apacheApplyTest) plan() error {
	_, err := a.action.Plan(context.Background(), *a.intent)
	return err
}

func (a apacheApplyTest) compile() (managedCompilation, error) { return a.action.compile(*a.intent) }

func TestManagedApplyRawApachePolicy(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		// want is "" when the config is written, else text the refusal must
		// carry.
		want []string
	}{
		{name: "bounded vhost", raw: boundedApacheRaw},
		{name: "load module", raw: "LoadModule cgi_module modules/mod_cgi.so\n" + boundedApacheRaw, want: []string{"app.example.com", "LoadModule", "loads a module"}},
		{name: "piped error log", raw: strings.Replace(boundedApacheRaw, "    ProxyPreserveHost On\n", "    ErrorLog \"|/bin/sh -c id\"\n", 1), want: []string{"ErrorLog", "line 4"}},
		{name: "include", raw: strings.Replace(boundedApacheRaw, "    ProxyPreserveHost On\n", "    Include /etc/shadow\n", 1), want: []string{"Include", "reads another file"}},
		{name: "directory exposure", raw: strings.Replace(boundedApacheRaw, "    ProxyPreserveHost On\n", "    <Directory />\n    </Directory>\n", 1), want: []string{"<Directory>"}},
		{name: "config variable in header", raw: strings.Replace(boundedApacheRaw, `"DENY"`, `"${APACHE_RUN_USER}"`, 1), want: []string{"${"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test := newApacheManagedApplyTest(t)
			test.set(tt.raw)
			err := test.plan()
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("bounded raw Apache config refused: %v", err)
				}
				compilation, err := test.compile()
				if err != nil || len(compilation.Files) != 1 || compilation.Files[0].Preserve ||
					!proxy.HasManagedArtifactMarker(string(compilation.Files[0].Content)) || !strings.Contains(string(compilation.Files[0].Content), "ProxyPass / http://10.0.0.2:8080/") {
					t.Fatalf("bounded raw Apache config was not compiled for writing: %+v, %v", compilation, err)
				}
				return
			}
			if err == nil {
				t.Fatal("unbounded raw Apache config admitted")
			}
			reason := localPolicyRefusalReason(err)
			for _, want := range tt.want {
				if !strings.Contains(reason, want) {
					t.Fatalf("refusal reason %q does not contain %q", reason, want)
				}
			}
		})
	}
}

// TestManagedApplyKeepsExactLivePolicyForeignApacheConfig checks that a raw
// Apache config outside the policy is still accepted when exactly these bytes
// are already the protected live file, and never written.
func TestManagedApplyKeepsExactLivePolicyForeignApacheConfig(t *testing.T) {
	test := newApacheManagedApplyTest(t)
	action := test.action
	raw := "<IfModule mod_proxy.c>\n" + boundedApacheRaw + "</IfModule>\n"
	test.set(raw)
	available := filepath.Join(action.layout.AvailableDir, managedFileName("apache", "app.example.com"))
	if err := os.WriteFile(available, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(available, filepath.Join(action.layout.EnabledDir, filepath.Base(available))); err != nil {
		t.Fatal(err)
	}
	if err := test.plan(); err != nil {
		t.Fatalf("exact live policy-foreign config refused: %v", err)
	}
	compilation, err := test.compile()
	if err != nil || !compilation.Files[0].Preserve {
		t.Fatalf("policy-foreign config was not preserve-only: %+v, %v", compilation, err)
	}
	if err := os.WriteFile(available, []byte(raw+"# drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := test.plan(); err == nil || !strings.Contains(localPolicyRefusalReason(err), "<IfModule>") {
		t.Fatalf("drifted policy-foreign config = %v, want a refusal naming <IfModule>", err)
	}
}

// TestManagedApplyRefusesApacheHeaderConfigVariable checks the structured
// path: apachegen refuses "${" in a header value and the reason reaches the
// agent.
func TestManagedApplyRefusesApacheHeaderConfigVariable(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	action.target.Kind = "apache"
	intent.Routes[0].Backend = "apache"
	intent.Routes[0].Route.ResponseHeaders = map[string]string{"X-User": "${APACHE_RUN_USER}"}
	_, err := action.Plan(context.Background(), intent)
	if reason := localPolicyRefusalReason(err); !strings.Contains(reason, "X-User") || !strings.Contains(reason, "${") {
		t.Fatalf("Plan() = %v, want a refusal naming the header", err)
	}
}
