//go:build integration && linux

package helper

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"golang.org/x/crypto/bcrypt"
)

const nginxMainConfigTemplate = `user npworker npworkers;
events {}
http {
    server {
        listen 127.0.0.1:8081;
        location / { return 200 "upstream ok\n"; }
    }
    include %s/*;
}
`

const apacheMainConfigTemplate = `ServerRoot "/usr/local/apache2"
Listen 80
Listen 127.0.0.1:8081
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule headers_module modules/mod_headers.so
LoadModule dir_module modules/mod_dir.so
User npworker
Group npworkers
ServerName localhost
ErrorLog /proc/self/fd/2
<VirtualHost 127.0.0.1:8081>
    DocumentRoot "/usr/local/apache2/htdocs"
    <Directory "/usr/local/apache2/htdocs">
        Require all granted
    </Directory>
    DirectoryIndex index.html
</VirtualHost>
IncludeOptional %s/*
`

// TestManagedBasicAuthIsReadableByRealProxyWorker runs the helper's managed
// apply for a basic-auth route, then serves the result from a real proxy whose
// worker shares only the resolved group with the auth file: it is neither the
// owner nor root. Correct credentials must reach the upstream, wrong ones must
// get 401, and nothing may answer 500 (the #147 symptom).
func TestManagedBasicAuthIsReadableByRealProxyWorker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.SecurityOptions}}").CombinedOutput(); err != nil {
		t.Skipf("docker not usable: %v", err)
	} else if strings.Contains(string(out), "rootless") {
		t.Skip("rootless docker remaps uid/gid; the group-permission check needs identity mapping")
	}
	tests := []struct {
		kind, image, confTemplate, confTarget, start string
	}{
		{kind: "nginx", image: "nginx:1.29-alpine", confTemplate: nginxMainConfigTemplate, confTarget: "/etc/nginx/nginx.conf", start: "nginx -g 'daemon off;'"},
		{kind: "apache", image: "httpd:2.4-alpine", confTemplate: apacheMainConfigTemplate, confTarget: "/usr/local/apache2/conf/httpd.conf", start: "httpd-foreground"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			action, intent, host := newManagedApplyTest(t)
			action.target.Kind = tt.kind
			host.facts.Kind = tt.kind
			intent.Routes[0].Backend = tt.kind
			gid := uint32(os.Getgid())
			action.workerGroup = func() (uint32, error) { return gid, nil }
			hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			intent.Routes[0].Route.Upstream = proxymodel.Upstream{Addr: "127.0.0.1", Port: 8081}
			intent.Routes[0].Route.BasicAuth = &proxymodel.BasicAuth{Username: "operator", PasswordHash: string(hash)}
			runManagedApply(t, action, intent)
			authFile := filepath.Join(action.layout.AuthDir(), "auth-app.example.com.htpasswd")

			mainConf := filepath.Join(filepath.Dir(action.layout.CertificateDir), "main.conf")
			if err := os.WriteFile(mainConf, []byte(fmt.Sprintf(tt.confTemplate, action.layout.EnabledDir)), 0o644); err != nil {
				t.Fatal(err)
			}
			script := fmt.Sprintf("addgroup -g %d npworkers && adduser -D -H -u 4242 -G npworkers npworker && exec %s", gid, tt.start)
			out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "-p", "127.0.0.1::80",
				"-v", mainConf+":"+tt.confTarget+":ro",
				"-v", action.layout.AvailableDir+":"+action.layout.AvailableDir+":ro",
				"-v", action.layout.EnabledDir+":"+action.layout.EnabledDir+":ro",
				"-v", action.layout.AuthDir()+":"+action.layout.AuthDir(),
				"--entrypoint", "sh", tt.image, "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("docker run: %v\n%s", err, out)
			}
			container := strings.TrimSpace(string(out))
			t.Cleanup(func() {
				if t.Failed() {
					logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
					t.Logf("%s logs:\n%s", tt.kind, logs)
				}
				_ = exec.Command("docker", "rm", "-f", container).Run()
			})
			portOut, err := exec.CommandContext(ctx, "docker", "port", container, "80/tcp").CombinedOutput()
			if err != nil {
				t.Fatalf("docker port: %v\n%s", err, portOut)
			}
			address := strings.TrimSpace(strings.Split(string(portOut), "\n")[0])

			get := func(user, password string) int {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = "app.example.com"
				if user != "" {
					request.SetBasicAuth(user, password)
				}
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					return 0
				}
				_ = response.Body.Close()
				return response.StatusCode
			}
			deadline := time.Now().Add(30 * time.Second)
			for get("", "") == 0 {
				if time.Now().After(deadline) {
					t.Fatalf("%s did not start serving", tt.kind)
				}
				time.Sleep(200 * time.Millisecond)
			}

			requests := []struct {
				name           string
				user, password string
				want           int
			}{
				{name: "no credentials", want: http.StatusUnauthorized},
				{name: "correct credentials", user: "operator", password: "s3cret", want: http.StatusOK},
				{name: "wrong password", user: "operator", password: "nope", want: http.StatusUnauthorized},
				{name: "unknown user", user: "intruder", password: "s3cret", want: http.StatusUnauthorized},
			}
			for _, rq := range requests {
				if got := get(rq.user, rq.password); got != rq.want {
					t.Errorf("%s: status = %d, want %d", rq.name, got, rq.want)
				}
			}

			// Control: the pre-fix owner-only mode makes the same request fail
			// with 500, so this test would have caught #147.
			if err := os.Chmod(authFile, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := get("operator", "s3cret"); got != http.StatusInternalServerError {
				t.Errorf("status with owner-only auth file = %d, want 500", got)
			}
		})
	}
}
