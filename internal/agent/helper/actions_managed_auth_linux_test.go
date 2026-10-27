//go:build linux

package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const testAuthHash = "$2a$10$abcdefghijklmnopqrstuuuuuuuuuuuuuuuuuuuuuuuuuuuu"

// testWorkerGID prefers a supplementary group so the test proves the file is
// chowned to the resolved group, not just left on the creator's primary group.
func testWorkerGID() uint32 {
	groups, _ := os.Getgroups()
	for _, gid := range groups {
		if gid != os.Getgid() {
			return uint32(gid)
		}
	}
	return uint32(os.Getgid())
}

func runManagedApply(t *testing.T, action *managedApplyAction, intent helperprotocol.ApplyIntent) (helperprotocol.ManagedApplyPlan, PreparedAction) {
	t.Helper()
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
	if result, err := action.Execute(context.Background(), intent.OperationID, plan, intent, prepared); err != nil || !result.Validated {
		t.Fatalf("managed apply = %+v, %v", result, err)
	}
	return plan, prepared
}

func statOwnership(t *testing.T, path string) (os.FileMode, uint32, uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	return info.Mode(), stat.Uid, stat.Gid
}

func TestManagedApplyWritesBasicAuthFileReadableByWorkerGroupAndMigratesLegacyFile(t *testing.T) {
	action, intent, _ := newManagedApplyTest(t)
	gid := testWorkerGID()
	action.workerGroup = func() (uint32, error) { return gid, nil }
	intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
	legacy := filepath.Join(action.layout.CertificateDir, "auth-app.example.com.htpasswd")
	if err := os.WriteFile(legacy, []byte("operator:old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authDir := action.layout.AuthDir()
	authFile := filepath.Join(authDir, "auth-app.example.com.htpasswd")
	plan, prepared := runManagedApply(t, action, intent)

	if mode, uid, dirGID := statOwnership(t, authDir); !mode.IsDir() || mode.Perm() != 0o750 || uid != action.ownerUID || dirGID != gid {
		t.Fatalf("auth dir = %v uid=%d gid=%d, want dir 0750 uid=%d gid=%d", mode, uid, dirGID, action.ownerUID, gid)
	}
	if mode, uid, fileGID := statOwnership(t, authFile); !mode.IsRegular() || mode.Perm() != 0o640 || uid != action.ownerUID || fileGID != gid {
		t.Fatalf("auth file = %v uid=%d gid=%d, want 0640 uid=%d gid=%d", mode, uid, fileGID, action.ownerUID, gid)
	}
	if content, err := os.ReadFile(authFile); err != nil || string(content) != "operator:"+testAuthHash+"\n" {
		t.Fatalf("auth file content = %q, %v", content, err)
	}
	if mode, _, _ := statOwnership(t, action.layout.CertificateDir); mode.Perm() != 0o700 {
		t.Fatalf("certificate dir was loosened to %v", mode.Perm())
	}
	vhost, err := os.ReadFile(filepath.Join(action.layout.AvailableDir, managedFileName("nginx", "app.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(vhost), "auth_basic_user_file "+authFile+";") || strings.Contains(string(vhost), action.layout.CertificateDir) {
		t.Fatalf("vhost does not reference the worker-readable auth file:\n%s", vhost)
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy certs/ auth file was not removed: %v", err)
	}

	if err := action.Rollback(context.Background(), intent.OperationID, plan, intent, prepared); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(legacy); err != nil || string(content) != "operator:old\n" {
		t.Fatalf("rollback did not restore legacy auth file: %q, %v", content, err)
	}
	if _, err := os.Lstat(authFile); !os.IsNotExist(err) {
		t.Fatalf("rollback left the new auth file: %v", err)
	}
}

func TestManagedApplyRepairsAuthGroupDriftAndConvergesAfterwards(t *testing.T) {
	action, intent, host := newManagedApplyTest(t)
	gid := testWorkerGID()
	action.workerGroup = func() (uint32, error) { return gid, nil }
	intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
	runManagedApply(t, action, intent)
	authFile := filepath.Join(action.layout.AuthDir(), "auth-app.example.com.htpasswd")
	if err := os.Chown(authFile, -1, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(action.layout.AuthDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	reloads := len(host.mutations)
	intent.OperationID = "apply-operation-repair"
	runManagedApply(t, action, intent)
	if gid != uint32(os.Getgid()) {
		if _, _, fileGID := statOwnership(t, authFile); fileGID != gid {
			t.Fatalf("auth file group drift was not repaired: gid=%d", fileGID)
		}
		if len(host.mutations) == reloads {
			t.Fatal("auth group repair did not reload the proxy")
		}
	}
	if mode, _, _ := statOwnership(t, action.layout.AuthDir()); mode.Perm() != 0o750 {
		t.Fatalf("auth dir mode drift was not repaired: %v", mode.Perm())
	}
	reloads = len(host.mutations)
	intent.OperationID = "apply-operation-converged"
	runManagedApply(t, action, intent)
	if len(host.mutations) != reloads {
		t.Fatal("converged auth file caused another reload")
	}
}

func TestManagedApplyFailsClosedWhenWorkerGroupIsUnknown(t *testing.T) {
	tests := []struct {
		name      string
		basicAuth bool
		wantErr   bool
	}{
		{name: "basic auth route", basicAuth: true, wantErr: true},
		{name: "route without basic auth never asks", basicAuth: false, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, intent, _ := newManagedApplyTest(t)
			action.workerGroup = func() (uint32, error) { return 0, errors.New("no user directive") }
			if tt.basicAuth {
				intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
			}
			_, err := action.Plan(context.Background(), intent)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Plan error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "no user directive") {
				t.Fatalf("error does not explain the cause: %v", err)
			}
			if _, err := os.Lstat(action.layout.AuthDir()); !os.IsNotExist(err) {
				t.Fatalf("auth dir was created during planning: %v", err)
			}
		})
	}
}

func TestManagedApplyRemovesAuthFilesNoLongerReferenced(t *testing.T) {
	tests := []struct {
		name      string
		configure func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent)
		removed   []string
		kept      []string
	}{
		{
			name: "basic auth switched off",
			configure: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent) {
				intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
				runManagedApply(t, action, *intent)
				intent.Routes[0].Route.BasicAuth = nil
			},
			removed: []string{"auth/auth-app.example.com.htpasswd"},
		},
		{
			name: "deleted host",
			configure: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent) {
				intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
				runManagedApply(t, action, *intent)
				writeTestFile(t, filepath.Join(action.layout.CertificateDir, "auth-app.example.com.htpasswd"))
				intent.Resources = []string{}
				intent.Routes = []proxymodel.RouteIntent{}
				intent.DeletionSet = []helperprotocol.ManagedDeletion{{ResourceID: "domain-1", Host: "app.example.com", Backend: "nginx"}}
			},
			removed: []string{"auth/auth-app.example.com.htpasswd", "certs/auth-app.example.com.htpasswd"},
		},
		{
			name: "full push prunes auth files of unrouted hosts",
			configure: func(t *testing.T, action *managedApplyAction, intent *helperprotocol.ApplyIntent) {
				intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
				runManagedApply(t, action, *intent)
				writeTestFile(t, filepath.Join(action.layout.CertificateDir, "auth-gone.example.com.htpasswd"))
				writeTestFile(t, filepath.Join(action.layout.AuthDir(), "auth-gone.example.com.htpasswd"))
				writeTestFile(t, filepath.Join(action.layout.AuthDir(), "operator-note"))
				intent.PruneCertificates = true
			},
			removed: []string{"certs/auth-gone.example.com.htpasswd", "auth/auth-gone.example.com.htpasswd"},
			kept:    []string{"auth/auth-app.example.com.htpasswd", "auth/operator-note"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, intent, _ := newManagedApplyTest(t)
			tt.configure(t, action, &intent)
			intent.OperationID = "apply-operation-cleanup"
			runManagedApply(t, action, intent)
			root := filepath.Dir(action.layout.CertificateDir)
			for _, rel := range tt.removed {
				if _, err := os.Lstat(filepath.Join(root, rel)); !os.IsNotExist(err) {
					t.Errorf("%s was not removed: %v", rel, err)
				}
			}
			for _, rel := range tt.kept {
				if _, err := os.Lstat(filepath.Join(root, rel)); err != nil {
					t.Errorf("%s was removed: %v", rel, err)
				}
			}
		})
	}
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("operator:hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateManagedCompilationTargetsAuthClass(t *testing.T) {
	layout := ManagedApplyTargetConfig{CertificateDir: "/var/lib/nurproxy-agent/certs"}
	valid := compiledFile("/var/lib/nurproxy-agent/auth/auth-app.example.com.htpasswd", []byte("u:h\n"), 0o640, "auth")
	valid.GID = 33
	secret := compiledFile("/var/lib/nurproxy-agent/certs/app.example.com.key.plain", []byte("k"), 0o600, "secret")
	tests := []struct {
		name   string
		mutate func(*managedCompiledFile)
		ok     bool
	}{
		{name: "auth 0640 with worker group", mutate: func(*managedCompiledFile) {}, ok: true},
		{name: "auth world readable", mutate: func(f *managedCompiledFile) { f.Mode = 0o644 }},
		{name: "auth owner only", mutate: func(f *managedCompiledFile) { f.Mode = 0o600 }},
		{name: "auth with foreign name", mutate: func(f *managedCompiledFile) { f.Path = "/var/lib/nurproxy-agent/auth/app.example.com.key.plain" }},
		{name: "auth in certificate dir", mutate: func(f *managedCompiledFile) { f.Path = "/var/lib/nurproxy-agent/certs/auth-app.example.com.htpasswd" }},
		{name: "auth in vhost dir", mutate: func(f *managedCompiledFile) { f.Path = "/etc/nginx/sites-available/auth-app.example.com.htpasswd" }},
		{name: "auth preserved", mutate: func(f *managedCompiledFile) { f.Preserve = true }},
		{name: "secret 0600", mutate: func(f *managedCompiledFile) { *f = secret }, ok: true},
		{name: "secret with group", mutate: func(f *managedCompiledFile) { *f = secret; f.GID = 33 }},
		{name: "secret 0640", mutate: func(f *managedCompiledFile) { *f = secret; f.Mode = 0o640 }},
		{name: "secret in auth dir", mutate: func(f *managedCompiledFile) {
			*f = secret
			f.Path = "/var/lib/nurproxy-agent/auth/app.example.com.key.plain"
		}},
		{name: "legacy auth deletion in certificate dir", mutate: func(f *managedCompiledFile) {
			*f = managedCompiledFile{Path: "/var/lib/nurproxy-agent/certs/auth-app.example.com.htpasswd", Class: "secret", Delete: true}
		}, ok: true},
		{name: "auth deletion", mutate: func(f *managedCompiledFile) {
			*f = managedCompiledFile{Path: f.Path, Class: "auth", Delete: true}
		}, ok: true},
		{name: "auth deletion carrying a group", mutate: func(f *managedCompiledFile) {
			*f = managedCompiledFile{Path: f.Path, Class: "auth", Delete: true, GID: 33}
		}},
		{name: "unknown class", mutate: func(f *managedCompiledFile) { f.Class = "htpasswd" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := valid
			tt.mutate(&file)
			err := validateManagedCompilationTargets(managedCompilation{Files: []managedCompiledFile{file}, Links: []managedCompiledLink{}}, layout)
			if (err == nil) != tt.ok {
				t.Fatalf("validate = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestEnsureManagedAuthDirectoryOnlyManagesTheLayoutAuthDir(t *testing.T) {
	root := t.TempDir()
	layout := ManagedApplyTargetConfig{CertificateDir: filepath.Join(root, "certs")}
	for _, dir := range []string{filepath.Join(root, "certs"), filepath.Join(root, "other")} {
		if err := ensureManagedAuthDirectory(dir, layout, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
			t.Fatalf("ensureManagedAuthDirectory accepted %s", dir)
		}
	}
	if err := ensureManagedAuthDirectory(layout.AuthDir(), layout, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
}

func TestManagedApplyMovesRawNginxRouteOffLegacyAuthPath(t *testing.T) {
	tests := []struct {
		name    string
		stamp   bool
		foreign bool
	}{
		{name: "raw saved from an applied artifact", stamp: true},
		{name: "raw without marker", stamp: false},
		{name: "policy-foreign raw still on legacy path", foreign: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, intent, _ := newManagedApplyTest(t)
			route := &intent.Routes[0].Route
			route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
			legacy := filepath.Join(action.layout.CertificateDir, "auth-app.example.com.htpasswd")
			authFile := filepath.Join(action.layout.AuthDir(), "auth-app.example.com.htpasswd")
			raw, err := action.renderRoute(*route, "", "", legacy)
			if err != nil {
				t.Fatal(err)
			}
			if tt.stamp {
				raw = proxy.StampManagedArtifact(raw)
			}
			if tt.foreign {
				raw = strings.Replace(raw, "listen 80;", "listen 8080;", 1)
			}
			route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: raw}
			writeTestFile(t, legacy)
			if tt.foreign {
				_, err := action.compile(intent)
				if err == nil || !strings.Contains(err.Error(), legacy) || !strings.Contains(err.Error(), authFile) {
					t.Fatalf("compile error = %v, want one naming %s and %s", err, legacy, authFile)
				}
				return
			}
			runManagedApply(t, action, intent)
			vhost, err := os.ReadFile(filepath.Join(action.layout.AvailableDir, managedFileName("nginx", "app.example.com")))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(vhost), "auth_basic_user_file "+authFile+";") || strings.Contains(string(vhost), legacy) {
				t.Fatalf("raw vhost still uses the legacy auth path:\n%s", vhost)
			}
			if _, err := os.Stat(authFile); err != nil {
				t.Fatalf("auth file was not written: %v", err)
			}
			if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
				t.Fatalf("legacy auth file remained: %v", err)
			}
		})
	}
}

// reloadObservingHost records whether a path existed when the proxy reloaded.
type reloadObservingHost struct {
	*fakeProxyServiceHost
	path            string
	existedAtReload []bool
}

func (h *reloadObservingHost) Mutate(ctx context.Context, target ProxyTargetConfig, mutation proxyServiceMutation) error {
	_, err := os.Lstat(h.path)
	h.existedAtReload = append(h.existedAtReload, err == nil)
	return h.fakeProxyServiceHost.Mutate(ctx, target, mutation)
}

func TestManagedApplyRemovesAuthFileOnlyAfterReload(t *testing.T) {
	action, intent, fake := newManagedApplyTest(t)
	intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: testAuthHash}
	runManagedApply(t, action, intent)
	authFile := filepath.Join(action.layout.AuthDir(), "auth-app.example.com.htpasswd")
	host := &reloadObservingHost{fakeProxyServiceHost: fake, path: authFile}
	action.host = host
	intent.Routes[0].Route.BasicAuth = nil
	intent.OperationID = "apply-operation-auth-off"
	runManagedApply(t, action, intent)
	if len(host.existedAtReload) != 1 || !host.existedAtReload[0] {
		t.Fatalf("auth file presence at reload = %v, want it still present during the one reload", host.existedAtReload)
	}
	if _, err := os.Lstat(authFile); !os.IsNotExist(err) {
		t.Fatalf("auth file was not removed after reload: %v", err)
	}
}

func TestManagedApplyRemovesOnlyUnreferencedAuthFileWithoutReload(t *testing.T) {
	action, intent, host := newManagedApplyTest(t)
	runManagedApply(t, action, intent)
	legacy := filepath.Join(action.layout.CertificateDir, "auth-app.example.com.htpasswd")
	writeTestFile(t, legacy)
	reloads := len(host.mutations)
	intent.OperationID = "apply-operation-orphan"
	runManagedApply(t, action, intent)
	if len(host.mutations) != reloads {
		t.Fatal("removing an unreferenced auth file reloaded the proxy")
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("unreferenced legacy auth file remained: %v", err)
	}
}

func TestReadTrustedConfigOwnedBy(t *testing.T) {
	uid := uint32(os.Getuid())
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		owner   uint32
		wantErr bool
	}{
		{name: "owner-only writable file", owner: uid, setup: func(t *testing.T, dir string) string {
			return writeConfigFile(t, dir, 0o644)
		}},
		{name: "symlink", owner: uid, wantErr: true, setup: func(t *testing.T, dir string) string {
			target := writeConfigFile(t, dir, 0o644)
			link := filepath.Join(dir, "link.conf")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{name: "owned by someone else", owner: uid + 1, wantErr: true, setup: func(t *testing.T, dir string) string {
			return writeConfigFile(t, dir, 0o644)
		}},
		{name: "group writable", owner: uid, wantErr: true, setup: func(t *testing.T, dir string) string {
			return writeConfigFile(t, dir, 0o664)
		}},
		{name: "world writable", owner: uid, wantErr: true, setup: func(t *testing.T, dir string) string {
			return writeConfigFile(t, dir, 0o646)
		}},
		{name: "directory", owner: uid, wantErr: true, setup: func(t *testing.T, dir string) string {
			return dir
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t, t.TempDir())
			content, err := readTrustedConfigOwnedBy(path, tt.owner)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readTrustedConfigOwnedBy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && string(content) != "user www-data;\n" {
				t.Fatalf("content = %q", content)
			}
		})
	}
}

func writeConfigFile(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, []byte("user www-data;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
