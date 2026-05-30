package apache

import "testing"

func TestResolveLayout(t *testing.T) {
	tests := []struct {
		name      string
		configDir string
		wantAvail string
		wantEnab  string
		wantConfD bool
	}{
		{
			name:      "debian_sites_available",
			configDir: "/etc/apache2/sites-available",
			wantAvail: "/etc/apache2/sites-available",
			wantEnab:  "/etc/apache2/sites-enabled",
		},
		{
			name:      "debian_sites_enabled",
			configDir: "/etc/apache2/sites-enabled",
			wantAvail: "/etc/apache2/sites-available",
			wantEnab:  "/etc/apache2/sites-enabled",
		},
		{
			name:      "rhel_confd",
			configDir: "/etc/httpd/conf.d",
			wantAvail: "/etc/httpd/conf.d",
			wantEnab:  "",
			wantConfD: true,
		},
		{
			name:      "rhel_httpd_root",
			configDir: "/etc/httpd",
			wantAvail: "/etc/httpd/conf.d",
			wantEnab:  "",
			wantConfD: true,
		},
		{
			name:      "debian_apache2_root",
			configDir: "/etc/apache2",
			wantAvail: "/etc/apache2/sites-available",
			wantEnab:  "/etc/apache2/sites-enabled",
		},
		{
			name:      "trailing_slash_normalized",
			configDir: "/etc/apache2/sites-available/",
			wantAvail: "/etc/apache2/sites-available",
			wantEnab:  "/etc/apache2/sites-enabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := ResolveLayout(tt.configDir)
			if l.Available != tt.wantAvail {
				t.Errorf("Available = %q, want %q", l.Available, tt.wantAvail)
			}
			if l.Enabled != tt.wantEnab {
				t.Errorf("Enabled = %q, want %q", l.Enabled, tt.wantEnab)
			}
			if l.IsConfD() != tt.wantConfD {
				t.Errorf("IsConfD() = %v, want %v", l.IsConfD(), tt.wantConfD)
			}
		})
	}
}

func TestManagedFileName(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"app.example.com", "nurproxy-app.example.com.conf"},
		{"*.example.com", "nurproxy-_wildcard.example.com.conf"},
		{"a/b", "nurproxy-a_b.conf"},
		{"../etc", "nurproxy-__etc.conf"},
	}
	for _, tt := range tests {
		if got := ManagedFileName(tt.host); got != tt.want {
			t.Errorf("ManagedFileName(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestIsManagedFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"nurproxy-app.example.com.conf", true},
		{"operator.conf", false},
		{"nurproxy-app.example.com.conf.nurproxy-tmp", false},
		{"nurproxy-app", false},
		{"000-default.conf", false},
	}
	for _, tt := range tests {
		if got := IsManagedFile(tt.name); got != tt.want {
			t.Errorf("IsManagedFile(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestEnabledPath_confd_empty(t *testing.T) {
	l := ResolveLayout("/etc/httpd/conf.d")
	if l.EnabledPath("app.example.com") != "" {
		t.Errorf("conf.d layout EnabledPath should be empty")
	}
}
