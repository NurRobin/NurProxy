//go:build linux

package helper

import (
	"context"
	"os"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func TestManagedApplyConvergedAgreesWithExecute(t *testing.T) {
	tests := []struct {
		name          string
		fileMode      os.FileMode
		fileContent   func(managedCompilation) []byte
		link          bool
		wantConverged bool
	}{
		{name: "exact bytes, mode and link", fileMode: 0o644, link: true, wantConverged: true},
		{name: "mode drift", fileMode: 0o600, link: true},
		{name: "content drift", fileMode: 0o644, link: true, fileContent: func(managedCompilation) []byte {
			return []byte(proxy.StampManagedArtifact("server { listen 8081; }\n"))
		}},
		{name: "missing activation link", fileMode: 0o644},
		{name: "missing file", link: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, intent, host := newManagedApplyTest(t)
			compilation, err := action.compile(intent)
			if err != nil {
				t.Fatal(err)
			}
			if tt.fileMode != 0 {
				content := compilation.Files[0].Content
				if tt.fileContent != nil {
					content = tt.fileContent(compilation)
				}
				if err := os.WriteFile(compilation.Files[0].Path, content, tt.fileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(compilation.Files[0].Path, tt.fileMode); err != nil {
					t.Fatal(err)
				}
			}
			if tt.link {
				if err := os.Symlink(compilation.Links[0].Target, compilation.Links[0].Path); err != nil {
					t.Fatal(err)
				}
			}
			material, err := action.Plan(context.Background(), intent)
			if err != nil {
				t.Fatal(err)
			}
			plan := helperprotocol.ManagedApplyPlan{
				OperationID: intent.OperationID, CustomPolicyVersion: material.CustomPolicyVersion,
				ExecutionPlanHash: material.ExecutionPlanHash, ResourceFingerprint: material.ResourceFingerprint,
				RollbackCoverage: material.RollbackCoverage,
			}

			checked, converged, err := action.Converged(context.Background(), plan, intent)
			if err != nil || converged != tt.wantConverged {
				t.Fatalf("converged = %t, %v; want %t", converged, err, tt.wantConverged)
			}
			if len(host.mutations) != 0 {
				t.Fatalf("convergence check mutated the proxy: %v", host.mutations)
			}
			snapshots, err := os.ReadDir(action.journal.snapshotsDir)
			if err != nil || len(snapshots) != 0 {
				t.Fatalf("convergence check stored snapshots: %d, %v", len(snapshots), err)
			}

			prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
			if err != nil {
				t.Fatal(err)
			}
			executed, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
			if err != nil || !executed.Validated {
				t.Fatalf("execute = %+v, %v", executed, err)
			}
			if executed.Mutated == converged {
				t.Fatalf("Converged=%t disagrees with Execute Mutated=%t", converged, executed.Mutated)
			}
			if converged {
				left, leftErr := helperprotocol.Digest(checked.ManagedArtifacts)
				right, rightErr := helperprotocol.Digest(executed.ManagedArtifacts)
				if leftErr != nil || rightErr != nil || left != right || len(checked.ManagedArtifacts) != 1 {
					t.Fatalf("converged attestation differs from execute: %+v vs %+v", checked.ManagedArtifacts, executed.ManagedArtifacts)
				}
			}
		})
	}
}
