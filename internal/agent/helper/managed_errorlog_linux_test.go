//go:build linux

package helper

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

type fakeFileInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeFileInfo) Name() string       { return "x" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestErrorLogTargetCheck(t *testing.T) {
	const (
		file = "/var/log/nginx/error.log"
		dir  = "/var/log/nginx"
	)
	regular := fakeFileInfo{mode: 0o640}
	rootDir := fakeFileInfo{mode: fs.ModeDir | 0o755}
	compiledDefault := "nginx version: nginx/1.24.0\nconfigure arguments: --prefix=/usr/share/nginx --error-log-path=/var/log/nginx/error.log --conf-path=/etc/nginx/nginx.conf"
	compiledOther := "configure arguments: --prefix=/usr/local/openresty/nginx --error-log-path=/usr/local/openresty/nginx/logs/error.log"
	tests := []struct {
		name       string
		files      map[string]os.FileInfo
		version    string
		versionErr error
		wantErr    string // "" means allowed
	}{
		{name: "regular file in root-owned dir", files: map[string]os.FileInfo{file: regular, dir: rootDir}, versionErr: errors.New("must not be needed")},
		{name: "symlink, compiled default", files: map[string]os.FileInfo{file: fakeFileInfo{mode: fs.ModeSymlink | 0o777}, dir: rootDir}, version: compiledDefault},
		{name: "missing file, compiled default", files: map[string]os.FileInfo{dir: rootDir}, version: compiledDefault},
		{name: "dir owned by nginx user, compiled default", files: map[string]os.FileInfo{file: regular, dir: fakeFileInfo{mode: fs.ModeDir | 0o770, uid: 990}}, version: compiledDefault},
		{name: "symlink, other compiled path", files: map[string]os.FileInfo{file: fakeFileInfo{mode: fs.ModeSymlink | 0o777}, dir: rootDir}, version: compiledOther, wantErr: "is a symlink, and nginx -V reports --error-log-path=/usr/local/openresty"},
		{name: "missing, other compiled path", files: map[string]os.FileInfo{}, version: compiledOther, wantErr: "does not exist"},
		{name: "dir owned by other user", files: map[string]os.FileInfo{file: regular, dir: fakeFileInfo{mode: fs.ModeDir | 0o755, uid: 1000}}, version: compiledOther, wantErr: "/var/log/nginx is not owned by root"},
		{name: "dir writable by others", files: map[string]os.FileInfo{file: regular, dir: fakeFileInfo{mode: fs.ModeDir | 0o777}}, version: compiledOther, wantErr: "writable by group or others"},
		{name: "dir writable by group", files: map[string]os.FileInfo{file: regular, dir: fakeFileInfo{mode: fs.ModeDir | 0o775}}, version: compiledOther, wantErr: "writable by group or others"},
		{name: "dir is a symlink", files: map[string]os.FileInfo{file: regular, dir: fakeFileInfo{mode: fs.ModeSymlink | 0o777}}, version: compiledOther, wantErr: "not a plain directory"},
		{name: "fifo", files: map[string]os.FileInfo{file: fakeFileInfo{mode: fs.ModeNamedPipe | 0o600}, dir: rootDir}, version: compiledOther, wantErr: "not a regular file"},
		{name: "nginx -V fails", files: map[string]os.FileInfo{}, versionErr: errors.New("exit status 1"), wantErr: "nginx -V failed"},
		{name: "nginx -V names no path", files: map[string]os.FileInfo{}, version: "configure arguments: --prefix=/opt/nginx", wantErr: "reports no --error-log-path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := errorLogTargetCheck{
				lstat: func(path string) (os.FileInfo, error) {
					if info, ok := tt.files[path]; ok {
						return info, nil
					}
					return nil, fs.ErrNotExist
				},
				nginxVersion: func() (string, error) { return tt.version, tt.versionErr },
			}
			err := check.verify()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("verify() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("verify() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestManagedApplyChecksErrorLogTargetBeforeWriting checks that the helper
// itself refuses an error_log directive, rendered or raw, when the error log
// target is not safe, that the refusal carries the reason to the agent, and
// that routes without the directive never run the check.
func TestManagedApplyChecksErrorLogTargetBeforeWriting(t *testing.T) {
	const rawWithErrorLog = `server {
    listen 80;
    server_name app.example.com;
    error_log /var/log/nginx/error.log crit;
    location / {
        proxy_pass http://10.0.0.2:8080;
    }
}`
	tests := []struct {
		name      string
		level     string
		raw       string
		targetErr error
		wantErr   bool
		wantCheck bool
	}{
		{name: "rendered level, safe target", level: "crit", wantCheck: true},
		{name: "rendered level, unsafe target", level: "crit", targetErr: errors.New("/var/log/nginx/error.log is a symlink"), wantErr: true, wantCheck: true},
		{name: "raw error_log, unsafe target", raw: rawWithErrorLog, targetErr: errors.New("/var/log/nginx/error.log is a symlink"), wantErr: true, wantCheck: true},
		{name: "no error log, unsafe target", targetErr: errors.New("must not be checked")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, intent, _ := newManagedApplyTest(t)
			checked := 0
			action.errorLogTarget = func() error { checked++; return tt.targetErr }
			intent.Routes[0].Route.ErrorLogLevel = tt.level
			if tt.raw != "" {
				intent.Routes[0].Route.Raw = proxymodel.RawConfig{Backend: "nginx", Content: tt.raw}
			}
			_, err := action.Plan(context.Background(), intent)
			if (checked > 0) != tt.wantCheck {
				t.Fatalf("error log check ran %d times, want run=%v", checked, tt.wantCheck)
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Plan() = %v", err)
				}
				return
			}
			reason := localPolicyRefusalReason(err)
			if !strings.Contains(reason, "app.example.com") || !strings.Contains(reason, "is a symlink") || !strings.Contains(reason, "default") {
				t.Fatalf("refusal reason %q (error %v) does not name domain, cause and fix", reason, err)
			}
			message := managedPlanRefusedMessage(err)
			if got := helperprotocol.ManagedPlanRefusalReason(helperprotocol.ErrorAmbiguousLocalTarget, message); got != reason {
				t.Fatalf("protocol round trip = %q, want %q", got, reason)
			}
		})
	}
}
