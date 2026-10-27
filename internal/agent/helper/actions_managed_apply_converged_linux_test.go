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

func writeManagedTarget(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func linkManagedTarget(t *testing.T, compilation managedCompilation) {
	t.Helper()
	if err := os.Symlink(compilation.Links[0].Target, compilation.Links[0].Path); err != nil {
		t.Fatal(err)
	}
}

func installExactRoute(t *testing.T, compilation managedCompilation) {
	t.Helper()
	writeManagedTarget(t, compilation.Files[0].Path, compilation.Files[0].Content, os.FileMode(compilation.Files[0].Mode))
	linkManagedTarget(t, compilation)
}

// installExactAuthRoute turns the route into a basic-auth route whose worker
// group is a supplementary group (when there is one) and applies it once
// under a separate operation, leaving vhost, link, auth dir and auth file exact.
func installExactAuthRoute(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent) {
	t.Helper()
	gid := testWorkerGID()
	action.workerGroup = func() (uint32, error) { return gid, nil }
	intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
	setup := *intent
	setup.OperationID = "apply-operation-auth-setup"
	runManagedApply(t, action, setup)
}

func deleteRouteIntent(intent *helperprotocol.ApplyIntent) {
	intent.DesiredStateRevision = strings.Repeat("2", 64)
	intent.Resources = []string{}
	intent.Routes = []proxymodel.RouteIntent{}
	intent.DeletionSet = []helperprotocol.ManagedDeletion{{ResourceID: "domain-1", Host: "app.example.com", Backend: "nginx"}}
}

// Converged must say "nothing to do" exactly when Execute would neither mutate
// nor refuse; whenever Execute would fail it must not claim convergence.
func TestManagedApplyConvergedAgreesWithExecute(t *testing.T) {
	tests := []struct {
		name            string
		rootOnly        bool
		needsOtherGroup bool
		setup           func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, route managedCompilation)
		wantConverged   bool
		wantExecuteErr  bool
	}{
		{
			name: "exact bytes, mode and link",
			setup: func(t *testing.T, _ *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
			},
			wantConverged: true,
		},
		{
			name: "mode drift",
			setup: func(t *testing.T, _ *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				writeManagedTarget(t, route.Files[0].Path, route.Files[0].Content, 0o600)
				linkManagedTarget(t, route)
			},
		},
		{
			name: "content drift",
			setup: func(t *testing.T, _ *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				writeManagedTarget(t, route.Files[0].Path, []byte(proxy.StampManagedArtifact("server { listen 8081; }\n")), 0o644)
				linkManagedTarget(t, route)
			},
		},
		{
			name: "missing activation link",
			setup: func(t *testing.T, _ *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				writeManagedTarget(t, route.Files[0].Path, route.Files[0].Content, 0o644)
			},
		},
		{
			name: "missing file",
			setup: func(t *testing.T, _ *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				linkManagedTarget(t, route)
			},
		},
		{
			name: "world-writable destination directory",
			setup: func(t *testing.T, action *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
				if err := os.Chmod(action.layout.AvailableDir, 0o777); err != nil {
					t.Fatal(err)
				}
			},
			wantExecuteErr: true,
		},
		{
			name:     "destination directory owned by someone else",
			rootOnly: true,
			setup: func(t *testing.T, action *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
				if err := os.Chown(action.layout.EnabledDir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			},
			wantExecuteErr: true,
		},
		{
			name: "symlinked destination directory",
			setup: func(t *testing.T, action *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				real := action.layout.EnabledDir + "-real"
				if err := os.Rename(action.layout.EnabledDir, real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, action.layout.EnabledDir); err != nil {
					t.Fatal(err)
				}
				installExactRoute(t, route)
			},
			wantExecuteErr: true,
		},
		{
			name: "tombstoned route still on disk",
			setup: func(t *testing.T, _ *managedApplyAction, intent *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
				deleteRouteIntent(intent)
			},
		},
		{
			name: "tombstoned route already gone",
			setup: func(_ *testing.T, _ *managedApplyAction, intent *helperprotocol.ApplyIntent, _ managedCompilation) {
				deleteRouteIntent(intent)
			},
			wantConverged: true,
		},
		{
			name: "stale certificate to prune",
			setup: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
				intent.PruneCertificates = true
				writeManagedTarget(t, filepath.Join(action.layout.CertificateDir, "stale.example.com.crt"), []byte("cert"), 0o600)
			},
		},
		{
			name: "nothing left to prune",
			setup: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
				intent.PruneCertificates = true
				intent.CertificateKeep = []string{"kept.example.com"}
				writeManagedTarget(t, filepath.Join(action.layout.CertificateDir, "kept.example.com.crt"), []byte("cert"), 0o600)
			},
			wantConverged: true,
		},
		{
			name: "preserved legacy file and link",
			setup: func(t *testing.T, action *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				action.agentUID = uint32(os.Getuid()) + 1
				legacy := strings.TrimPrefix(string(route.Files[0].Content), proxy.ManagedArtifactMarker+"\n")
				writeManagedTarget(t, route.Files[0].Path, []byte(legacy), 0o644)
				linkManagedTarget(t, route)
			},
			wantConverged: true,
		},
		{
			name: "basic-auth file and directory exact",
			setup: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, _ managedCompilation) {
				installExactAuthRoute(t, action, intent)
			},
			wantConverged: true,
		},
		{
			name:            "basic-auth file with wrong group",
			needsOtherGroup: true,
			setup: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, _ managedCompilation) {
				installExactAuthRoute(t, action, intent)
				if err := os.Chown(filepath.Join(action.layout.AuthDir(), "auth-app.example.com.htpasswd"), -1, os.Getgid()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:            "basic-auth directory with wrong group",
			needsOtherGroup: true,
			setup: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, _ managedCompilation) {
				installExactAuthRoute(t, action, intent)
				if err := os.Chown(action.layout.AuthDir(), -1, os.Getgid()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "basic-auth directory with wrong mode",
			setup: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent, _ managedCompilation) {
				installExactAuthRoute(t, action, intent)
				if err := os.Chmod(action.layout.AuthDir(), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stale certs/ auth file pending deletion",
			setup: func(t *testing.T, action *managedApplyAction, _ *helperprotocol.ApplyIntent, route managedCompilation) {
				installExactRoute(t, route)
				writeManagedTarget(t, filepath.Join(action.layout.CertificateDir, "auth-app.example.com.htpasswd"), []byte("operator:hash\n"), 0o600)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.rootOnly && os.Getuid() != 0 {
				t.Skip("changing a directory owner needs root")
			}
			if tt.needsOtherGroup && testWorkerGID() == uint32(os.Getgid()) {
				t.Skip("needs a supplementary group to model group drift")
			}
			action, intent, host := newManagedApplyTest(t)
			route, err := action.compile(intent)
			if err != nil {
				t.Fatal(err)
			}
			tt.setup(t, action, &intent, route)
			mutationsBefore := len(host.mutations)
			snapshotsBefore, err := os.ReadDir(action.journal.snapshotsDir)
			if err != nil {
				t.Fatal(err)
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

			checked, converged, checkErr := action.Converged(context.Background(), plan, intent)
			if converged != tt.wantConverged || (tt.wantConverged && checkErr != nil) {
				t.Fatalf("converged = %t, %v; want %t", converged, checkErr, tt.wantConverged)
			}
			if tt.wantExecuteErr && checkErr == nil {
				t.Fatal("convergence check accepted a target Execute refuses")
			}
			if len(host.mutations) != mutationsBefore {
				t.Fatalf("convergence check mutated the proxy: %v", host.mutations)
			}
			snapshots, err := os.ReadDir(action.journal.snapshotsDir)
			if err != nil || len(snapshots) != len(snapshotsBefore) {
				t.Fatalf("convergence check stored snapshots: %d, %v", len(snapshots), err)
			}

			prepared, err := action.Prepare(context.Background(), intent.OperationID, plan, intent)
			if err != nil {
				t.Fatal(err)
			}
			executed, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared)
			if tt.wantExecuteErr {
				if err == nil || executed.Mutated {
					t.Fatalf("execute = %+v, %v; want refusal before mutation", executed, err)
				}
				return
			}
			if err != nil || !executed.Validated {
				t.Fatalf("execute = %+v, %v", executed, err)
			}
			if executed.Mutated == converged {
				t.Fatalf("Converged=%t disagrees with Execute Mutated=%t", converged, executed.Mutated)
			}
			if converged {
				left, leftErr := helperprotocol.Digest(checked.ManagedArtifacts)
				right, rightErr := helperprotocol.Digest(executed.ManagedArtifacts)
				if leftErr != nil || rightErr != nil || left != right {
					t.Fatalf("converged attestation differs from execute: %+v vs %+v", checked.ManagedArtifacts, executed.ManagedArtifacts)
				}
			}
		})
	}
}
