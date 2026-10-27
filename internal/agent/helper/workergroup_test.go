package helper

import (
	"errors"
	"os"
	"testing"
)

func TestResolveProxyWorkerGroup(t *testing.T) {
	groups := map[string]uint32{"www-data": 33, "nginx": 990, "apache": 48, "nogroup": 65534}
	lookup := func(name string) (uint32, error) {
		if gid, ok := groups[name]; ok {
			return gid, nil
		}
		return 0, errors.New("unknown group")
	}
	tests := []struct {
		name         string
		kind         string
		availableDir string
		files        map[string]string
		want         uint32
		wantErr      bool
	}{
		{
			name: "nginx debian user only", kind: "nginx", availableDir: "/etc/nginx/sites-available",
			files: map[string]string{nginxMainConfigPath: "user www-data;\nworker_processes auto;\nevents {}\n"},
			want:  33,
		},
		{
			name: "nginx rhel user and group", kind: "nginx", availableDir: "/etc/nginx/conf.d",
			files: map[string]string{nginxMainConfigPath: "# comment user root;\nuser  nginx  nginx;\nevents { worker_connections 1024; }\n"},
			want:  990,
		},
		{
			name: "nginx explicit group differs from user", kind: "nginx",
			files: map[string]string{nginxMainConfigPath: "user nobody nogroup;"},
			want:  65534,
		},
		{
			name: "nginx quoted group", kind: "nginx",
			files: map[string]string{nginxMainConfigPath: "user \"www-data\";"},
			want:  33,
		},
		{
			name: "nginx without user directive fails closed", kind: "nginx",
			files:   map[string]string{nginxMainConfigPath: "events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n"},
			wantErr: true,
		},
		{
			name: "nginx user inside a block is not the main context", kind: "nginx",
			files:   map[string]string{nginxMainConfigPath: "http { user www-data; }\n"},
			wantErr: true,
		},
		{
			name: "nginx duplicate user directive", kind: "nginx",
			files:   map[string]string{nginxMainConfigPath: "user www-data;\nuser nginx;\n"},
			wantErr: true,
		},
		{
			name: "nginx unknown group", kind: "nginx",
			files:   map[string]string{nginxMainConfigPath: "user ghost;"},
			wantErr: true,
		},
		{
			name: "nginx unreadable main config", kind: "nginx",
			files: map[string]string{}, wantErr: true,
		},
		{
			name: "apache debian envvars", kind: "apache", availableDir: "/etc/apache2/sites-available",
			files: map[string]string{
				apacheDebianConfigPath:  "User ${APACHE_RUN_USER}\nGroup ${APACHE_RUN_GROUP}\n",
				apacheDebianEnvvarsPath: "unset HOME\nexport APACHE_RUN_USER=www-data\nexport APACHE_RUN_GROUP=www-data\n",
			},
			want: 33,
		},
		{
			name: "apache debian envvar needing shell expansion fails closed", kind: "apache", availableDir: "/etc/apache2/sites-available",
			files: map[string]string{
				apacheDebianConfigPath:  "Group ${APACHE_RUN_GROUP}\n",
				apacheDebianEnvvarsPath: "export APACHE_RUN_GROUP=www-data$SUFFIX\n",
			},
			wantErr: true,
		},
		{
			name: "apache debian envvar missing", kind: "apache", availableDir: "/etc/apache2/sites-available",
			files:   map[string]string{apacheDebianConfigPath: "Group ${APACHE_RUN_GROUP}\n", apacheDebianEnvvarsPath: "export APACHE_RUN_USER=www-data\n"},
			wantErr: true,
		},
		{
			name: "apache rhel literal group", kind: "apache", availableDir: "/etc/httpd/conf.d",
			files: map[string]string{apacheRedHatMainConfigPath: "User apache\n# Group nobody\ngroup apache\n"},
			want:  48,
		},
		{
			name: "apache numeric group", kind: "apache", availableDir: "/etc/httpd/conf.d",
			files: map[string]string{apacheRedHatMainConfigPath: "Group #48\n"},
			want:  48,
		},
		{
			name: "apache numeric root group rejected", kind: "apache", availableDir: "/etc/httpd/conf.d",
			files:   map[string]string{apacheRedHatMainConfigPath: "Group #0\n"},
			wantErr: true,
		},
		{
			name: "apache numeric invalid gid rejected", kind: "apache", availableDir: "/etc/httpd/conf.d",
			files:   map[string]string{apacheRedHatMainConfigPath: "Group #4294967295\n"},
			wantErr: true,
		},
		{
			name: "apache numeric gid out of range", kind: "apache", availableDir: "/etc/httpd/conf.d",
			files:   map[string]string{apacheRedHatMainConfigPath: "Group #4294967296\n"},
			wantErr: true,
		},
		{
			name: "apache without group fails closed", kind: "apache", availableDir: "/etc/httpd/conf.d",
			files:   map[string]string{apacheRedHatMainConfigPath: "User apache\n"},
			wantErr: true,
		},
		{
			name: "caddy has no mapping", kind: "caddy", files: map[string]string{}, wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				content, ok := tt.files[path]
				if !ok {
					return nil, os.ErrNotExist
				}
				return []byte(content), nil
			}
			got, err := resolveProxyWorkerGroup(tt.kind, tt.availableDir, read, lookup)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveProxyWorkerGroup() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("resolveProxyWorkerGroup() = %d, want %d", got, tt.want)
			}
		})
	}
}
