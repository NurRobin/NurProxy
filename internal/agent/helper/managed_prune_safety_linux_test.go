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
	cases := []struct {
		name          string
		orphanVhost   bool // a stamped vhost for gone.example.com stays on disk
		operatorRef   bool // an operator file references the certificate
		unmarked      bool // the orphaned vhost is a preserved raw config without marker
		deleteVhost   bool // the intent tombstones gone.example.com
		wantPruned    bool
		wantRetention bool
		wantVhostGone bool
	}{
		{name: "unreferenced certificate is pruned", wantPruned: true},
		{name: "orphaned managed vhost keeps its certificate", orphanVhost: true, wantRetention: true},
		{name: "operator config keeps a referenced certificate", operatorRef: true, wantRetention: true},
		{name: "tombstoned vhost is removed together with its certificate", orphanVhost: true, deleteVhost: true, wantPruned: true, wantVhostGone: true},
		{name: "tombstoned unmarked raw vhost stays and keeps its certificate", orphanVhost: true, unmarked: true, deleteVhost: true, wantRetention: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, intent, _ := newManagedApplyTest(t)
			intent.OperationID = "apply-operation-prune-safety"
			intent.PruneCertificates = true
			certPath := filepath.Join(action.layout.CertificateDir, "gone.example.com.crt")
			keyPath := filepath.Join(action.layout.CertificateDir, "gone.example.com.key.plain")
			for path, content := range map[string]string{certPath: "cert", keyPath: "key"} {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			vhostPath := filepath.Join(action.layout.AvailableDir, "nurproxy-gone.example.com.conf")
			linkPath := filepath.Join(action.layout.EnabledDir, "nurproxy-gone.example.com.conf")
			if tc.orphanVhost {
				content := "server {\n  listen 443 ssl;\n  server_name gone.example.com;\n  ssl_certificate " + certPath + ";\n  ssl_certificate_key " + keyPath + ";\n}\n"
				if !tc.unmarked {
					content = proxy.StampManagedArtifact(content)
				}
				if err := os.WriteFile(vhostPath, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(vhostPath, linkPath); err != nil {
					t.Fatal(err)
				}
			}
			if tc.operatorRef {
				if err := os.WriteFile(filepath.Join(action.layout.AvailableDir, "operator.conf"), []byte("ssl_certificate "+certPath+";\n"), 0o644); err != nil {
					t.Fatal(err)
				}
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
			if retained := strings.Contains(result.SanitizedResult, "gone.example.com"); retained != tc.wantRetention {
				t.Fatalf("receipt retention note = %q, want mention %v", result.SanitizedResult, tc.wantRetention)
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
