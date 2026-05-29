package proxy

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

func TestDetect_nginxInstalledPortConflict_reportsAll(t *testing.T) {
	restore := stubFS(
		map[string]bool{"/etc/nginx/sites-available": true, "/etc/nginx": true},
		map[string]bool{"/var/log/nginx/error.log": true},
	)
	defer restore()

	d := &Detector{
		lookPath: func(name string) (string, error) {
			if name == "nginx" {
				return "/usr/sbin/nginx", nil
			}
			return "", exec.ErrNotFound
		},
		run: func(ctx context.Context, name string, args ...string) (string, error) {
			if name == "/usr/sbin/nginx" {
				return "nginx version: nginx/1.24.0 (Ubuntu)\n", nil
			}
			return "", errors.New("unexpected command")
		},
		listListeners: func(ctx context.Context) ([]listener, error) {
			return []listener{
				{port: 80, process: "nginx", pid: 1234},
				{port: 443, process: "nginx", pid: 1234},
			}, nil
		},
	}

	got, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	want := Detection{
		Installed:  true,
		Kind:       KindNginx,
		Version:    "1.24.0",
		BinaryPath: "/usr/sbin/nginx",
		ConfigDir:  "/etc/nginx/sites-available",
		LogPaths:   []string{"/var/log/nginx/error.log"},
		PortConflicts: []PortConflict{
			{Port: 80, Process: "nginx", PID: 1234},
			{Port: 443, Process: "nginx", PID: 1234},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDetect_noProxyInstalled_reportsNotInstalled(t *testing.T) {
	d := &Detector{
		lookPath:      func(string) (string, error) { return "", exec.ErrNotFound },
		run:           func(context.Context, string, ...string) (string, error) { return "", nil },
		listListeners: func(context.Context) ([]listener, error) { return nil, nil },
	}
	got, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if got.Installed {
		t.Fatalf("Installed = true, want false")
	}
	if got.Kind != KindUnknown {
		t.Fatalf("Kind = %q, want unknown", got.Kind)
	}
}

func TestDetect_caddyInstalledNoConflict_reportsCaddy(t *testing.T) {
	restore := stubFS(map[string]bool{"/etc/caddy": true}, map[string]bool{})
	defer restore()

	d := &Detector{
		lookPath: func(name string) (string, error) {
			if name == "caddy" {
				return "/usr/bin/caddy", nil
			}
			return "", exec.ErrNotFound
		},
		run: func(ctx context.Context, name string, args ...string) (string, error) {
			return "v2.7.6 h1:abc=\n", nil
		},
		listListeners: func(ctx context.Context) ([]listener, error) {
			// Only an unrelated high port is held; no :80/:443 conflict.
			return []listener{{port: 2019, process: "caddy", pid: 9}}, nil
		},
	}
	got, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if got.Kind != KindCaddy || got.Version != "2.7.6" {
		t.Fatalf("got kind=%q version=%q, want caddy 2.7.6", got.Kind, got.Version)
	}
	if len(got.PortConflicts) != 0 {
		t.Fatalf("PortConflicts = %v, want none", got.PortConflicts)
	}
}

func TestDetect_versionCommandFails_stillReportsInstalled(t *testing.T) {
	restore := stubFS(map[string]bool{"/etc/nginx": true}, map[string]bool{})
	defer restore()

	d := &Detector{
		lookPath: func(name string) (string, error) {
			if name == "nginx" {
				return "/usr/sbin/nginx", nil
			}
			return "", exec.ErrNotFound
		},
		run: func(ctx context.Context, name string, args ...string) (string, error) {
			return "", errors.New("permission denied")
		},
		listListeners: func(ctx context.Context) ([]listener, error) { return nil, nil },
	}
	got, err := d.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if !got.Installed || got.Kind != KindNginx {
		t.Fatalf("got installed=%v kind=%q, want installed nginx", got.Installed, got.Kind)
	}
	if got.Version != "" {
		t.Fatalf("Version = %q, want empty when version cmd fails", got.Version)
	}
}

func TestDetectPortConflicts_onlyReportsHTTPPorts(t *testing.T) {
	d := &Detector{
		listListeners: func(ctx context.Context) ([]listener, error) {
			return []listener{
				{port: 22, process: "sshd", pid: 1},
				{port: 80, process: "nginx", pid: 2},
				{port: 8080, process: "java", pid: 3},
				{port: 443, process: "nginx", pid: 2},
			}, nil
		},
	}
	got := d.detectPortConflicts(context.Background())
	want := []PortConflict{
		{Port: 80, Process: "nginx", PID: 2},
		{Port: 443, Process: "nginx", PID: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectPortConflicts() = %+v, want %+v", got, want)
	}
}

func TestDetection_ToModel_mapsAllFields(t *testing.T) {
	d := Detection{
		Installed:  true,
		Kind:       KindNginx,
		Version:    "1.24.0",
		BinaryPath: "/usr/sbin/nginx",
		ConfigDir:  "/etc/nginx/sites-available",
		LogPaths:   []string{"/var/log/nginx/error.log"},
		PortConflicts: []PortConflict{
			{Port: 443, Process: "nginx", PID: 1234},
		},
	}
	m := d.ToModel()
	if m == nil {
		t.Fatal("ToModel() returned nil")
	}
	if !m.Installed || m.Kind != "nginx" || m.Version != "1.24.0" {
		t.Errorf("scalars: got installed=%t kind=%q version=%q", m.Installed, m.Kind, m.Version)
	}
	if m.BinaryPath != "/usr/sbin/nginx" || m.ConfigDir != "/etc/nginx/sites-available" {
		t.Errorf("paths: got binary=%q config=%q", m.BinaryPath, m.ConfigDir)
	}
	if len(m.LogPaths) != 1 || m.LogPaths[0] != "/var/log/nginx/error.log" {
		t.Errorf("log_paths: got %v", m.LogPaths)
	}
	if len(m.PortConflicts) != 1 {
		t.Fatalf("port_conflicts: got %d, want 1", len(m.PortConflicts))
	}
	if c := m.PortConflicts[0]; c.Port != 443 || c.Process != "nginx" || c.PID != 1234 {
		t.Errorf("port_conflict: got %+v", c)
	}
}
