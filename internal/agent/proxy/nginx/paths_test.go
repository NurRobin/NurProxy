package nginx

import "testing"

func TestResolveLayout_table(t *testing.T) {
	tests := []struct {
		name          string
		configDir     string
		wantAvailable string
		wantEnabled   string
	}{
		{
			name:          "debian sites-available config dir",
			configDir:     "/etc/nginx/sites-available",
			wantAvailable: "/etc/nginx/sites-available",
			wantEnabled:   "/etc/nginx/sites-enabled",
		},
		{
			name:          "sites-enabled config dir derives available sibling",
			configDir:     "/etc/nginx/sites-enabled",
			wantAvailable: "/etc/nginx/sites-available",
			wantEnabled:   "/etc/nginx/sites-enabled",
		},
		{
			name:          "nginx root appends both subdirs",
			configDir:     "/etc/nginx",
			wantAvailable: "/etc/nginx/sites-available",
			wantEnabled:   "/etc/nginx/sites-enabled",
		},
		{
			name:          "trailing slash is cleaned",
			configDir:     "/etc/nginx/sites-available/",
			wantAvailable: "/etc/nginx/sites-available",
			wantEnabled:   "/etc/nginx/sites-enabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveLayout(tt.configDir)
			if got.Available != tt.wantAvailable {
				t.Errorf("Available = %q, want %q", got.Available, tt.wantAvailable)
			}
			if got.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %q, want %q", got.Enabled, tt.wantEnabled)
			}
		})
	}
}

func TestManagedFileName_table(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "plain host", host: "app.example.com", want: "nurproxy-app.example.com.conf"},
		{name: "wildcard host mapped", host: "*.example.com", want: "nurproxy-_wildcard.example.com.conf"},
		{name: "path traversal stripped", host: "../../etc/passwd", want: "nurproxy-____etc_passwd.conf"},
		{name: "whitespace trimmed", host: "  app.example.com  ", want: "nurproxy-app.example.com.conf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ManagedFileName(tt.host); got != tt.want {
				t.Errorf("ManagedFileName(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestLayoutPaths(t *testing.T) {
	l := ResolveLayout("/etc/nginx/sites-available")
	if got, want := l.AvailablePath("app.example.com"), "/etc/nginx/sites-available/nurproxy-app.example.com.conf"; got != want {
		t.Errorf("AvailablePath = %q, want %q", got, want)
	}
	if got, want := l.EnabledPath("app.example.com"), "/etc/nginx/sites-enabled/nurproxy-app.example.com.conf"; got != want {
		t.Errorf("EnabledPath = %q, want %q", got, want)
	}
}

func TestIsManagedFile_table(t *testing.T) {
	tests := []struct {
		name string
		file string
		want bool
	}{
		{name: "our file", file: "nurproxy-app.example.com.conf", want: true},
		{name: "operator's vhost", file: "default", want: false},
		{name: "operator's conf without prefix", file: "mysite.conf", want: false},
		{name: "prefix but not conf", file: "nurproxy-app.example.com.bak", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsManagedFile(tt.file); got != tt.want {
				t.Errorf("IsManagedFile(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}
