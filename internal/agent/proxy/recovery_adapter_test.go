package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func TestRecoveryPathCaptureAndNoFollowRemoval(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.conf")
	if err := os.WriteFile(regular, []byte(StampManagedArtifact("server {}\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	regularIdentity, err := CaptureRecoveryPath(regular)
	if err != nil || !regularIdentity.Exists || regularIdentity.Inode == 0 || regularIdentity.SHA256 == "" {
		t.Fatalf("regular identity = %+v, err=%v", regularIdentity, err)
	}
	replacementIdentity := regularIdentity
	if err := os.Rename(regular, regular+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte(StampManagedArtifact("server {}\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRecoveryPath(replacementIdentity); err == nil {
		t.Fatal("replacement passed final identity check")
	}
	if _, err := os.Lstat(regular); err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}

	target := filepath.Join(dir, "target.conf")
	link := filepath.Join(dir, "enabled.conf")
	if err := os.WriteFile(target, []byte("operator"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	linkIdentity, err := CaptureRecoveryPath(link)
	if err != nil || linkIdentity.SymlinkTarget != target {
		t.Fatalf("link identity = %+v, err=%v", linkIdentity, err)
	}
	if err := RemoveRecoveryPath(linkIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was followed: %v", err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink entry survived: %v", err)
	}
}

type recordingRecoveryBackend struct {
	*recordingBackend
	candidates []RecoveryCandidate
	desired    RecoveryDesired
	executed   RecoveryCandidate
}

func (r *recordingRecoveryBackend) InspectRecovery(_ context.Context, desired RecoveryDesired) ([]RecoveryCandidate, error) {
	r.desired = desired
	return r.candidates, r.err
}

func (r *recordingRecoveryBackend) ExecuteRecovery(_ context.Context, candidate RecoveryCandidate, _ map[string]CertBundle) error {
	r.executed = candidate
	return r.err
}

func TestHolderRecoveryAdapterIsOptionalAndForwardsTypedValues(t *testing.T) {
	ctx := context.Background()
	unsupported := NewHolder(proxyOnly{}, "existing")
	got, err := unsupported.InspectRecovery(ctx, RecoveryDesired{})
	if err != nil || got != nil {
		t.Fatalf("unsupported inspect = (%v, %v), want nil,nil", got, err)
	}
	if err := unsupported.ExecuteRecovery(ctx, RecoveryCandidate{}, nil); !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatalf("unsupported execute error = %v", err)
	}

	want := RecoveryCandidate{Action: recoverymodel.ActionRemoveManagedTemp, Host: "app.example.com", Paths: []string{"/etc/nginx/sites-available/nurproxy-app.example.com.conf.nurproxy-tmp"}}
	backend := &recordingRecoveryBackend{recordingBackend: newRecordingBackend(), candidates: []RecoveryCandidate{want}}
	holder := NewHolder(backend, "existing")
	desired := RecoveryDesired{KeepTargets: []Target{{Kind: TargetKindFile, Path: "/managed/keep"}}, KeepCertHosts: []string{"app.example.com"}, ActiveOperationPaths: []string{"/managed/active"}}
	got, err = holder.InspectRecovery(ctx, desired)
	if err != nil || !reflect.DeepEqual(got, backend.candidates) || !reflect.DeepEqual(backend.desired, desired) {
		t.Fatalf("forward inspect = (%+v, %v), desired=%+v", got, err, backend.desired)
	}
	if err := holder.ExecuteRecovery(ctx, want, map[string]CertBundle{"app.example.com": {Host: "app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(backend.executed, want) {
		t.Fatalf("executed = %+v", backend.executed)
	}
}

func TestRecoveryCandidateRejectsUntypedOrUnsafeValues(t *testing.T) {
	tests := []RecoveryCandidate{
		{},
		{Action: recoverymodel.Action("run_command"), Host: "app.example.com", Paths: []string{"/safe"}},
		{Action: recoverymodel.ActionRemoveManagedTemp, Host: "", Paths: []string{"/safe"}},
		{Action: recoverymodel.ActionRemoveManagedTemp, Host: "app.example.com", Paths: []string{"relative"}},
		{Action: recoverymodel.ActionRemoveManagedTemp, Host: "app.example.com", Paths: []string{"/safe/../escape"}},
	}
	for _, candidate := range tests {
		if err := candidate.Validate(); err == nil {
			t.Errorf("unsafe candidate accepted: %+v", candidate)
		}
	}
}
