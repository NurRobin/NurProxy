package apacheparse

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/apachegen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const (
	testHost = "app.example.com"
	testCert = "/var/lib/nurproxy-agent/certs/app.example.com.crt"
	testKey  = "/var/lib/nurproxy-agent/certs/app.example.com.key.plain"
	testAuth = "/etc/apache2/nurproxy-auth/app.example.com.htpasswd"
)

var testPolicy = ManagedPolicy{Host: testHost, CertPath: testCert, KeyPath: testKey, AuthPath: testAuth}

// TestValidateManagedAdmitsGeneratorOutput renders the route shapes apachegen
// supports and checks that every output passes the policy the helper
// applies to rendered vhosts.
func TestValidateManagedAdmitsGeneratorOutput(t *testing.T) {
	base := func() proxymodel.Route {
		return proxymodel.Route{Host: testHost, Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080}}
	}
	full := func() proxymodel.Route {
		r := base()
		r.ForceHTTPS = true
		r.WebSocket = true
		r.MaxBodySize = "50MB"
		r.RequestHeaders = map[string]string{"X-Team": "edge", "X-Quote": `say "hi" 100%`}
		r.ResponseHeaders = map[string]string{"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; img-src * #x {y}"}
		r.Timeouts = proxymodel.Timeouts{Read: 60, Write: 30}
		r.BasicAuth = &proxymodel.BasicAuth{Username: "u", PasswordHash: "$2a$10$x"}
		r.IPAllowlist = []string{"10.0.0.0/8", "fd00::/8"}
		r.IPBlocklist = []string{"10.6.6.6/32"}
		r.AccessLog = proxymodel.AccessLogOff
		r.ErrorLogLevel = "crit"
		r.TLS = proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral}
		return r
	}
	tests := []struct {
		name  string
		route func() proxymodel.Route
	}{
		{"plain", base},
		{"full tls", full},
		{"blocklist only", func() proxymodel.Route { r := base(); r.IPBlocklist = []string{"192.0.2.1"}; return r }},
		{"basic auth only", func() proxymodel.Route {
			r := base()
			r.BasicAuth = &proxymodel.BasicAuth{Username: "u", PasswordHash: "h"}
			return r
		}},
		{"strip prefix", func() proxymodel.Route { r := base(); r.Path.StripPrefix = "/api.v1+(x)"; return r }},
		{"rewrite", func() proxymodel.Route { r := base(); r.Path.Rewrite = "/v2/index?x=1&y=$z"; return r }},
		{"https upstream websocket", func() proxymodel.Route {
			r := base()
			r.Upstream = proxymodel.Upstream{Addr: "fd00::5", Port: 8443, Scheme: proxymodel.SchemeHTTPS}
			r.WebSocket = true
			return r
		}},
		{"wildcard host", func() proxymodel.Route { r := base(); r.Host = "*.example.com"; return r }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := tt.route()
			res, err := apachegen.Render(apachegen.Input{Route: route, CertPath: testCert, KeyPath: testKey, AuthFile: testAuth})
			if err != nil {
				t.Fatal(err)
			}
			policy := testPolicy
			policy.Host = route.Host
			if err := ValidateManaged(res.VHost, policy); err != nil {
				t.Fatalf("generator output refused: %v\n%s", err, res.VHost)
			}
		})
	}
}

const proxiedVHost = `<VirtualHost *:443>
    ServerName app.example.com
    SSLEngine on
    SSLCertificateFile /var/lib/nurproxy-agent/certs/app.example.com.crt
    SSLCertificateKeyFile /var/lib/nurproxy-agent/certs/app.example.com.key.plain
%s
    ProxyPreserveHost On
    ProxyPass / http://10.0.0.4:8080/
    ProxyPassReverse / http://10.0.0.4:8080/
</VirtualHost>
`

func TestValidateManagedAdmitsBoundedRawConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"minimal", fmt.Sprintf(proxiedVHost, "")},
		{"comments and mixed case", "# operator note\n" + strings.ReplaceAll(fmt.Sprintf(proxiedVHost, "    # inner note\n    header ALWAYS set X-A b"), "ProxyPreserveHost On", "proxypreservehost on")},
		{"redirect companion", "<VirtualHost *:80>\n    ServerName app.example.com\n    Redirect permanent / https://app.example.com/\n</VirtualHost>\n" + fmt.Sprintf(proxiedVHost, "")},
		{"crlf line ends", strings.ReplaceAll(fmt.Sprintf(proxiedVHost, ""), "\n", "\r\n")},
		{"double quoted header", fmt.Sprintf(proxiedVHost, `    RequestHeader set X-A "two 'words'"`)},
		{"unset header", fmt.Sprintf(proxiedVHost, `    Header unset Server`)},
		{"literal percent and backslash", fmt.Sprintf(proxiedVHost, `    Header always set X-A "100%% \\\\ done"`)},
		{"websocket connection cond", fmt.Sprintf(proxiedVHost, "    RewriteEngine On\n    RewriteCond %{HTTP:Connection} upgrade [NC]\n    RewriteRule ^/?(.*)$ ws://10.0.0.4:8080/$1 [P,L]")},
		{"location with auth and ip", fmt.Sprintf(proxiedVHost, "    <Location />\n        AuthType Basic\n        AuthName \"Restricted\"\n        AuthUserFile "+testAuth+"\n        <RequireAll>\n            Require ip 10.0.0.0/8\n            Require valid-user\n        </RequireAll>\n    </Location>")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateManaged(tt.content, testPolicy); err != nil {
				t.Fatalf("bounded raw config refused: %v\n%s", err, tt.content)
			}
		})
	}
}

func TestValidateManagedRefusesUnboundedRawConfig(t *testing.T) {
	inVHost := func(lines string) string { return fmt.Sprintf(proxiedVHost, lines) }
	tests := []struct {
		name    string
		content string
		// want must appear in the error so the operator sees the directive.
		want string
	}{
		{"load module at top", "LoadModule cgi_module modules/mod_cgi.so\n" + inVHost(""), "LoadModule"},
		{"load module lower case", inVHost("    loadmodule cgi_module modules/mod_cgi.so"), "loadmodule"},
		{"include", inVHost("    Include /etc/shadow"), "Include"},
		{"include optional", inVHost("    IncludeOptional /tmp/*.conf"), "IncludeOptional"},
		{"piped error log", inVHost(`    ErrorLog "|/bin/sh -c id"`), "ErrorLog"},
		{"piped custom log", inVHost(`    CustomLog "|/bin/sh -c id" common`), "CustomLog"},
		{"custom log to file", inVHost("    CustomLog /etc/cron.d/x common"), "CustomLog"},
		{"define", inVHost("    Define X y"), "Define"},
		{"setenv", inVHost("    SetEnv LD_PRELOAD /tmp/x.so"), "SetEnv"},
		{"pass env", inVHost("    PassEnv HOME"), "PassEnv"},
		{"directory root", inVHost("    <Directory />\n        Require all granted\n    </Directory>"), "<Directory>"},
		{"document root", inVHost("    DocumentRoot /"), "DocumentRoot"},
		{"rewrite map program", inVHost("    RewriteMap m prg:/bin/sh"), "RewriteMap"},
		{"script alias", inVHost("    ScriptAlias /x /bin/"), "ScriptAlias"},
		{"rewrite handler flag", inVHost("    RewriteRule ^/x$ http://10.0.0.4:8080/ [P,H=cgi-script]"), "RewriteRule"},
		{"rewrite env flag", inVHost("    RewriteRule ^/x$ http://10.0.0.4:8080/ [P,E=X:1]"), "RewriteRule"},
		{"rewrite without proxy", inVHost("    RewriteRule ^/x$ /etc/passwd [L]"), "RewriteRule"},
		{"rewrite server variable", inVHost("    RewriteRule ^/x$ http://10.0.0.4:8080/%{ENV:HOME} [P]"), "RewriteRule"},
		{"proxy to unix socket", strings.Replace(inVHost(""), "ProxyPass / http://10.0.0.4:8080/", "ProxyPass / unix:/run/php.sock|fcgi://localhost/", 1), "ProxyPass"},
		{"proxy to fcgi", strings.Replace(inVHost(""), "ProxyPass / http://10.0.0.4:8080/", "ProxyPass / fcgi://127.0.0.1:9000/var/www/", 1), "ProxyPass"},
		{"header env format", inVHost(`    Header always set X-A "%{HOME}e"`), "Header"},
		{"header expr", inVHost(`    Header always set X-A "expr=%{file:/etc/shadow}"`), "Header"},
		{"header condition", inVHost(`    Header always set X-A b env=HOME`), "Header"},
		{"header config variable", inVHost(`    Header always set X-A "${APACHE_RUN_USER}"`), "${"},
		{"server alias", inVHost("    ServerAlias other.example.com"), "ServerAlias"},
		{"foreign server name", strings.Replace(inVHost(""), "ServerName app.example.com", "ServerName other.example.com", 1), "ServerName"},
		{"foreign certificate", strings.Replace(inVHost(""), testCert, "/etc/ssl/private/other.pem", 1), "SSLCertificateFile"},
		{"foreign auth file", inVHost("    <Location />\n        AuthUserFile /etc/shadow\n    </Location>"), "AuthUserFile"},
		{"location other path", inVHost("    <Location /admin>\n        Require all granted\n    </Location>"), "<Location>"},
		{"require expression", inVHost("    <Location />\n        Require expr true\n    </Location>"), "Require"},
		{"if module wrapper", inVHost("    <IfModule mod_cgi.c>\n    </IfModule>"), "<IfModule>"},
		{"line continuation", inVHost("    Header always set X-A \\\n        b"), "continuation"},
		{"other port", strings.Replace(inVHost(""), "*:443", "*:8443", 1), "*:80 and *:443"},
		{"three vhosts", inVHost("") + inVHost("") + inVHost(""), "more than two"},
		{"two proxied vhosts", inVHost("") + inVHost(""), "exactly one proxied"},
		{"no proxy", "<VirtualHost *:80>\n    ServerName app.example.com\n</VirtualHost>\n", "ProxyPass"},
		{"unclosed section", "<VirtualHost *:443>\n    ServerName app.example.com\n", "never closed"},
		{"quoted directive name", inVHost(`    "LoadModule" x y`), "plain word"},
		{"control character", inVHost("    Header always set X-A b\x00"), "control"},
		{"redirect elsewhere", "<VirtualHost *:80>\n    ServerName app.example.com\n    Redirect permanent / https://evil.example/\n</VirtualHost>\n" + inVHost(""), "Redirect"},
		{"empty", "", "no <VirtualHost>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateManaged(tt.content, testPolicy)
			if err == nil {
				t.Fatalf("unbounded raw config admitted:\n%s", tt.content)
			}
			var policyErr *PolicyError
			if !errors.As(err, &policyErr) {
				t.Fatalf("error %v is not a *PolicyError", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestValidateManagedRefusesWithoutManagedPaths(t *testing.T) {
	content := fmt.Sprintf(proxiedVHost, "")
	if err := ValidateManaged(content, ManagedPolicy{Host: testHost}); err == nil || !strings.Contains(err.Error(), "SSLCertificateFile") {
		t.Fatalf("certificate directive admitted without a managed certificate path: %v", err)
	}
	if err := ValidateManaged(content, ManagedPolicy{}); err == nil {
		t.Fatal("config admitted without a policy host")
	}
}

func TestDangerReasonNamesWhy(t *testing.T) {
	err := ValidateManaged("LoadModule x y\n", testPolicy)
	if err == nil || !strings.Contains(err.Error(), "loads a module") || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("refusal does not explain the directive: %v", err)
	}
}
