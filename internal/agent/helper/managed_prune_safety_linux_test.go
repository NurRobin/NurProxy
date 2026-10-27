//go:build linux

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// Regression for #148: a certificate that is no longer in certificate_keep must
// not be pruned while a config file that survives the apply still references
// it. Pruning it anyway broke native validation after the commit and latched
// the helper breaker permanently.
func TestManagedApplyKeepsCertificatesReferencedBySurvivingConfig(t *testing.T) {
	const leftoverName = "nurproxy-gone.example.com.conf"
	cases := []struct {
		name          string
		orphanVhost   bool // a vhost for gone.example.com stays on disk
		unmarked      bool // that vhost is a preserved raw config without marker
		deleteVhost   bool // the intent tombstones gone.example.com
		setup         func(t *testing.T, action *managedApplyAction, certPath string)
		wantPruned    bool
		wantVhostGone bool
		wantNote      []string // substrings the receipt message must carry
	}{
		{name: "unreferenced certificate is pruned", wantPruned: true},
		{name: "orphaned managed vhost keeps its certificate and is reported", orphanVhost: true,
			wantNote: []string{"kept 1 unretained certificate(s) still referenced by proxy config: gone.example.com", helperprotocol.ManagedLeftoverVhostsNote + leftoverName}},
		{name: "operator config keeps a referenced certificate",
			setup: func(t *testing.T, action *managedApplyAction, certPath string) {
				writeConfigFixture(t, filepath.Join(action.layout.AvailableDir, "operator.conf"), "ssl_certificate "+certPath+";\n")
			},
			wantNote: []string{"kept 1 unretained certificate(s)"}},
		{name: "differently spelled path still counts as a reference",
			setup: func(t *testing.T, action *managedApplyAction, _ string) {
				writeConfigFixture(t, filepath.Join(action.layout.AvailableDir, "operator.conf"), "ssl_certificate /var/lib//nurproxy-agent/certs/gone.example.com.crt;\n")
			},
			wantNote: []string{"kept 1 unretained certificate(s)"}},
		{name: "enabled symlink to a config outside the available dir is followed",
			setup: func(t *testing.T, action *managedApplyAction, certPath string) {
				outside := filepath.Join(t.TempDir(), "elsewhere.conf")
				writeConfigFixture(t, outside, "ssl_certificate "+certPath+";\n")
				if err := os.Symlink(outside, filepath.Join(action.layout.EnabledDir, "elsewhere.conf")); err != nil {
					t.Fatal(err)
				}
				action.agentUID = uint32(os.Getuid()) + 1 // target is not agent-owned
			},
			wantNote: []string{"kept 1 unretained certificate(s)"}},
		{name: "symlink target owned by the agent is not trusted",
			setup: func(t *testing.T, action *managedApplyAction, certPath string) {
				outside := filepath.Join(t.TempDir(), "agent-owned.conf")
				writeConfigFixture(t, outside, "ssl_certificate "+certPath+";\n")
				if err := os.Symlink(outside, filepath.Join(action.layout.EnabledDir, "agent-owned.conf")); err != nil {
					t.Fatal(err)
				}
			},
			wantPruned: true},
		{name: "oversized config skips pruning instead of failing the plan",
			setup: func(t *testing.T, action *managedApplyAction, _ string) {
				writeConfigFixture(t, filepath.Join(action.layout.AvailableDir, "huge.conf"), strings.Repeat("#", int(maxConfigFileBytes)+1))
			},
			wantNote: []string{"prune skipped, 1 config file(s) too large to scan for references: huge.conf"}},
		{name: "tombstoned vhost is removed together with its certificate", orphanVhost: true, deleteVhost: true, wantPruned: true, wantVhostGone: true},
		{name: "tombstoned unmarked raw vhost stays, keeps its certificate and is reported", orphanVhost: true, unmarked: true, deleteVhost: true,
			wantNote: []string{"kept 1 unretained certificate(s)", helperprotocol.ManagedLeftoverVhostsNote + leftoverName}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, intent, _ := newManagedApplyTest(t)
			intent.OperationID = "apply-operation-prune-safety"
			intent.PruneCertificates = true
			certPath := filepath.Join(action.layout.CertificateDir, "gone.example.com.crt")
			keyPath := filepath.Join(action.layout.CertificateDir, "gone.example.com.key.plain")
			writeConfigFixture(t, certPath, "cert")
			writeConfigFixture(t, keyPath, "key")
			vhostPath := filepath.Join(action.layout.AvailableDir, leftoverName)
			if tc.orphanVhost {
				content := "server {\n  listen 443 ssl;\n  server_name gone.example.com;\n  ssl_certificate " + certPath + ";\n  ssl_certificate_key " + keyPath + ";\n}\n"
				if !tc.unmarked {
					content = proxy.StampManagedArtifact(content)
				}
				writeConfigFixture(t, vhostPath, content)
				if err := os.Symlink(vhostPath, filepath.Join(action.layout.EnabledDir, leftoverName)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setup != nil {
				tc.setup(t, action, certPath)
			}
			if tc.deleteVhost {
				intent.DeletionSet = []helperprotocol.ManagedDeletion{{ResourceID: "dom-59", Host: "gone.example.com", Backend: "nginx"}}
			}

			material, err := action.Plan(context.Background(), intent)
			if err != nil {
				t.Fatal(err)
			}
			plan := helperprotocol.ManagedApplyPlan{OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
				ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
			prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
			if err != nil {
				t.Fatal(err)
			}
			result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
			if err != nil || !result.Validated {
				t.Fatalf("apply = %+v, %v", result, err)
			}
			for _, path := range []string{certPath, keyPath} {
				_, statErr := os.Stat(path)
				if pruned := os.IsNotExist(statErr); pruned != tc.wantPruned {
					t.Fatalf("%s pruned = %v, want %v (stat: %v)", filepath.Base(path), pruned, tc.wantPruned, statErr)
				}
			}
			for _, note := range tc.wantNote {
				if !strings.Contains(result.SanitizedResult, note) {
					t.Fatalf("receipt message = %q, want it to contain %q", result.SanitizedResult, note)
				}
			}
			if len(tc.wantNote) == 0 && strings.Contains(result.SanitizedResult, ";") {
				t.Fatalf("receipt message = %q, want no notes", result.SanitizedResult)
			}
			if tc.orphanVhost {
				_, statErr := os.Lstat(vhostPath)
				if removed := os.IsNotExist(statErr); removed != tc.wantVhostGone {
					t.Fatalf("vhost removed = %v, want %v", removed, tc.wantVhostGone)
				}
			}
		})
	}
}

func writeConfigFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestManagedApplyReceiptCarriesNativeValidationOutput(t *testing.T) {
	action, intent, host := newManagedApplyTest(t)
	host.validateErr = newNativeValidationError(errors.New("exit status 1"),
		"nginx: [emerg] cannot load certificate \"/certs/gone.crt\"\x1b[0m\nnginx: configuration file /etc/nginx/nginx.conf test failed\n")
	material, err := action.Plan(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := helperprotocol.ManagedApplyPlan{OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
		ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint, RollbackCoverage: material.RollbackCoverage}
	prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
	if err != nil {
		t.Fatal(err)
	}
	_, executeErr := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
	if executeErr == nil {
		t.Fatal("expected native validation failure")
	}
	message := withNativeDiagnostic("managed apply failed before mutation", executeErr)
	want := `managed apply failed before mutation; native validation: nginx: [emerg] cannot load certificate "/certs/gone.crt"[0m | nginx: configuration file /etc/nginx/nginx.conf test failed`
	if message != want {
		t.Fatalf("receipt message = %q\nwant %q", message, want)
	}
}
