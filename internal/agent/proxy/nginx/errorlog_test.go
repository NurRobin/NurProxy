package nginx

import (
	"io/fs"
	"os"
	"testing"
	"time"
)

type fakeFileInfo struct{ mode fs.FileMode }

func (f fakeFileInfo) Name() string       { return "error.log" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func TestErrorLogTargetIsDefault(t *testing.T) {
	const debianV = "nginx version: nginx/1.22.1\nconfigure arguments: --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --with-http_ssl_module"
	const sourceV = "nginx version: nginx/1.25.3\nconfigure arguments: --prefix=/usr/local/nginx"
	const openrestyV = "nginx version: openresty/1.21.4.1\nconfigure arguments: --prefix=/usr/local/openresty/nginx --conf-path=/usr/local/openresty/nginx/conf/nginx.conf"
	const debianConf = `user www-data;
include /etc/nginx/modules-enabled/*.conf;
error_log /var/log/nginx/error.log;
events { worker_connections 768; }
http {
    # error_log /var/log/nginx/commented.log;
    access_log /var/log/nginx/access.log;
    include /etc/nginx/conf.d/*.conf;
}
`
	regular := fakeFileInfo{mode: 0o640}
	tests := []struct {
		name    string
		version string
		confAt  string
		conf    string
		logFile os.FileInfo // nil: /var/log/nginx/error.log does not exist
		want    bool
	}{
		{"debian package", debianV, "/etc/nginx/nginx.conf", debianConf, regular, true},
		{"compiled default only", debianV, "/etc/nginx/nginx.conf", "events {}\nhttp {}\n", regular, true},
		{"log file missing", debianV, "/etc/nginx/nginx.conf", debianConf, nil, false},
		{"log path is a directory", debianV, "/etc/nginx/nginx.conf", debianConf, fakeFileInfo{mode: fs.ModeDir | 0o755}, false},
		{"main error_log elsewhere", debianV, "/etc/nginx/nginx.conf", "error_log /srv/logs/nginx.log warn;\nhttp {}\n", regular, false},
		{"http error_log elsewhere", debianV, "/etc/nginx/nginx.conf", "error_log /var/log/nginx/error.log;\nhttp {\n    error_log /var/log/nginx/http.log;\n}\n", regular, false},
		{"http error_log default overrides main", debianV, "/etc/nginx/nginx.conf", "error_log /srv/main.log;\nhttp {\n    error_log /var/log/nginx/error.log warn;\n}\n", regular, true},
		{"second main error_log elsewhere", debianV, "/etc/nginx/nginx.conf", "error_log /var/log/nginx/error.log;\nerror_log syslog:server=10.0.0.1;\nhttp {}\n", regular, false},
		{"server-level error_log ignored", debianV, "/etc/nginx/nginx.conf", "http {\n    server {\n        error_log /srv/x.log;\n    }\n}\n", regular, true},
		{"source build without paths", sourceV, "/etc/nginx/nginx.conf", "http {}\n", regular, false},
		{"openresty conf path", openrestyV, "/usr/local/openresty/nginx/conf/nginx.conf", "error_log logs/error.log;\nhttp {}\n", regular, false},
		{"unreadable config", debianV, "/elsewhere/nginx.conf", "", regular, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readFile := func(path string) ([]byte, error) {
				if path != tt.confAt {
					return nil, os.ErrNotExist
				}
				return []byte(tt.conf), nil
			}
			stat := func(path string) (os.FileInfo, error) {
				if path != "/var/log/nginx/error.log" || tt.logFile == nil {
					return nil, os.ErrNotExist
				}
				return tt.logFile, nil
			}
			if got := errorLogTargetIsDefault(tt.version, readFile, stat); got != tt.want {
				t.Fatalf("errorLogTargetIsDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}
