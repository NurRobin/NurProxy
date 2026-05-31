package proxy

import (
	"reflect"
	"testing"
)

func TestParseVersion_capturedOutputs_extractsVersion(t *testing.T) {
	tests := []struct {
		name string
		kind Kind
		raw  string
		want string
	}{
		{
			name: "nginx debian",
			kind: KindNginx,
			raw:  "nginx version: nginx/1.24.0 (Ubuntu)\n",
			want: "1.24.0",
		},
		{
			name: "nginx rhel two-component build",
			kind: KindNginx,
			raw:  "nginx version: nginx/1.20.1\n",
			want: "1.20.1",
		},
		{
			name: "apachectl debian",
			kind: KindApache,
			raw:  "Server version: Apache/2.4.58 (Ubuntu)\nServer built:   2024-04-04T17:11:50\n",
			want: "2.4.58",
		},
		{
			name: "httpd rhel",
			kind: KindApache,
			raw:  "Server version: Apache/2.4.57 (Red Hat Enterprise Linux)\nServer built:   ...\n",
			want: "2.4.57",
		},
		{
			name: "caddy version",
			kind: KindCaddy,
			raw:  "v2.7.6 h1:w0NymbG2m9PcvKWsrXO6EEkY9Ru4FJK8uQbYcev1p3A=\n",
			want: "2.7.6",
		},
		{
			name: "empty output",
			kind: KindNginx,
			raw:  "",
			want: "",
		},
		{
			name: "no version present",
			kind: KindNginx,
			raw:  "command not found",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseVersion(tt.kind, tt.raw); got != tt.want {
				t.Fatalf("ParseVersion(%q, %q) = %q, want %q", tt.kind, tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseSSOutput_capturedOutputs_extractsListeners(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []listener
	}{
		{
			name: "nginx holds 80 and 443",
			raw: "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
				`LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=1234,fd=6),("nginx",pid=1235,fd=6))` + "\n" +
				`LISTEN 0      511          0.0.0.0:443       0.0.0.0:*    users:(("nginx",pid=1234,fd=7))` + "\n",
			want: []listener{
				{port: 80, process: "nginx", pid: 1234},
				{port: 443, process: "nginx", pid: 1234},
			},
		},
		{
			name: "ipv6 and wildcard addresses",
			raw: `LISTEN 0 128 [::]:443 [::]:* users:(("apache2",pid=42,fd=4))` + "\n" +
				`LISTEN 0 128 *:8080 *:* users:(("caddy",pid=7,fd=3))` + "\n",
			want: []listener{
				{port: 443, process: "apache2", pid: 42},
				{port: 8080, process: "caddy", pid: 7},
			},
		},
		{
			name: "no process column (no permission)",
			raw:  `LISTEN 0 511 0.0.0.0:443 0.0.0.0:*` + "\n",
			want: []listener{{port: 443}},
		},
		{
			name: "header only",
			raw:  "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
			want: nil,
		},
		{
			name: "malformed lines skipped",
			raw:  "garbage\nLISTEN only-three cols\n",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSSOutput(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseSSOutput() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPortFromAddr_variousForms_extractsPort(t *testing.T) {
	tests := []struct {
		addr     string
		wantPort int
		wantOK   bool
	}{
		{"0.0.0.0:443", 443, true},
		{"*:80", 80, true},
		{"[::]:443", 443, true},
		{"127.0.0.1:8080", 8080, true},
		{"0.0.0.0:", 0, false},
		{"noport", 0, false},
		{"[::]:bad", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			port, ok := portFromAddr(tt.addr)
			if port != tt.wantPort || ok != tt.wantOK {
				t.Fatalf("portFromAddr(%q) = (%d, %v), want (%d, %v)", tt.addr, port, ok, tt.wantPort, tt.wantOK)
			}
		})
	}
}

func TestResolvePaths_debianLayout_picksSitesAvailable(t *testing.T) {
	restore := stubFS(
		map[string]bool{
			"/etc/nginx/sites-available": true,
			"/etc/nginx":                 true,
		},
		map[string]bool{
			"/var/log/nginx/error.log":  true,
			"/var/log/nginx/access.log": true,
		},
	)
	defer restore()

	got := ResolvePaths(KindNginx)
	if got.ConfigDir != "/etc/nginx/sites-available" {
		t.Fatalf("ConfigDir = %q, want /etc/nginx/sites-available", got.ConfigDir)
	}
	wantLogs := []string{"/var/log/nginx/error.log", "/var/log/nginx/access.log"}
	if !reflect.DeepEqual(got.LogPaths, wantLogs) {
		t.Fatalf("LogPaths = %v, want %v", got.LogPaths, wantLogs)
	}
}

func TestResolvePaths_rhelLayout_picksConfD(t *testing.T) {
	restore := stubFS(
		map[string]bool{
			// No sites-available on RHEL; conf.d exists.
			"/etc/nginx/conf.d": true,
			"/etc/nginx":        true,
		},
		map[string]bool{
			"/var/log/nginx/error.log": true,
		},
	)
	defer restore()

	got := ResolvePaths(KindNginx)
	if got.ConfigDir != "/etc/nginx/conf.d" {
		t.Fatalf("ConfigDir = %q, want /etc/nginx/conf.d", got.ConfigDir)
	}
	if !reflect.DeepEqual(got.LogPaths, []string{"/var/log/nginx/error.log"}) {
		t.Fatalf("LogPaths = %v, want [error.log]", got.LogPaths)
	}
}

func TestResolvePaths_apacheRHEL_picksHttpd(t *testing.T) {
	restore := stubFS(
		map[string]bool{
			"/etc/httpd/conf.d": true,
			"/etc/httpd":        true,
		},
		map[string]bool{
			"/var/log/httpd/error_log": true,
		},
	)
	defer restore()

	got := ResolvePaths(KindApache)
	if got.ConfigDir != "/etc/httpd/conf.d" {
		t.Fatalf("ConfigDir = %q, want /etc/httpd/conf.d", got.ConfigDir)
	}
	if !reflect.DeepEqual(got.LogPaths, []string{"/var/log/httpd/error_log"}) {
		t.Fatalf("LogPaths = %v, want [error_log]", got.LogPaths)
	}
}

func TestResolvePaths_nothingOnDisk_fallsBackToPrimaryDefault(t *testing.T) {
	restore := stubFS(map[string]bool{}, map[string]bool{})
	defer restore()

	got := ResolvePaths(KindNginx)
	if got.ConfigDir != "/etc/nginx/sites-available" {
		t.Fatalf("ConfigDir = %q, want primary default /etc/nginx/sites-available", got.ConfigDir)
	}
	if got.LogPaths != nil {
		t.Fatalf("LogPaths = %v, want nil when no logs exist", got.LogPaths)
	}
}

// stubFS replaces the package dir/file existence hooks with synthetic layouts
// and returns a restore func.
func stubFS(dirs, files map[string]bool) func() {
	origDir, origFile := dirExists, fileExists
	dirExists = func(p string) bool { return dirs[p] }
	fileExists = func(p string) bool { return files[p] }
	return func() {
		dirExists = origDir
		fileExists = origFile
	}
}
