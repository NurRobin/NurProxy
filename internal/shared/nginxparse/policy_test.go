package nginxparse

import (
	"fmt"
	"strings"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

const (
	policyTestHost = "app.example.test"
	policyTestCert = "/var/lib/nurproxy-agent/certs/app.example.test.crt"
	policyTestKey  = "/var/lib/nurproxy-agent/certs/app.example.test.key.plain"
	policyTestAuth = "/var/lib/nurproxy-agent/auth/auth-app.example.test.htpasswd"
)

var policyTestPolicy = ManagedPolicy{Host: policyTestHost, CertPath: policyTestCert, KeyPath: policyTestKey, AuthPath: policyTestAuth}

const policyTestValid = `server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name app.example.test;
    ssl_certificate /var/lib/nurproxy-agent/certs/app.example.test.crt;
    ssl_certificate_key /var/lib/nurproxy-agent/certs/app.example.test.key.plain;
    add_header X-Frame-Options DENY always;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}`

const policyTestRedirect = `server {
    listen 80;
    listen [::]:80;
    server_name app.example.test;
    return 301 https://$host$request_uri;
}

`

// policyTestAccepted are hand-written vhosts inside the raw policy.
var policyTestAccepted = map[string]string{
	"proxied only":              policyTestValid,
	"with redirect":             policyTestRedirect + policyTestValid,
	"comment lines":             "# managed\n" + strings.Replace(policyTestValid, "    location / {", "    # proxy\n    location / {", 1),
	"quoted header value":       strings.Replace(policyTestValid, "DENY always", `"default-src 'self'; img-src \"x\"" always`, 1),
	"quoted request value":      strings.Replace(policyTestValid, "Host $host", `Connection "upgrade"`, 1),
	"redirect after proxied":    policyTestValid + "\n" + policyTestRedirect,
	"redirect to literal host":  strings.Replace(policyTestRedirect, "https://$host", "https://app.example.test", 1) + policyTestValid,
	"old nginx http2 listen":    strings.Replace(policyTestValid, "listen 443 ssl;", "listen 443 ssl http2;", 1),
	"long quoted value":         strings.Replace(policyTestValid, "DENY always", "\""+strings.Repeat("a b", 1300)+"\" always", 1),
	"long comment":              "#" + strings.Repeat("a", 3900) + "\n" + policyTestValid,
	"bracketed ipv6 upstream":   strings.Replace(policyTestValid, "http://127.0.0.1:3000", "http://[fd00::5]:3000", 1),
	"fully qualified upstream":  strings.Replace(policyTestValid, "http://127.0.0.1:3000", "http://ai.lan.:3000", 1),
	"compact location":          strings.Replace(policyTestValid, "location / {\n        proxy_pass http://127.0.0.1:3000;\n        proxy_set_header Host $host;\n    }", "location / { proxy_pass http://127.0.0.1:3000; }", 1),
	"escaped rewrite":           strings.Replace(policyTestValid, "proxy_pass", `rewrite ^/api\.v1/?(.*)$ /$1 break;`+"\n        proxy_pass", 1),
	"header without always":     strings.Replace(policyTestValid, "DENY always", "DENY", 1),
	"timeout without unit":      strings.Replace(policyTestValid, "proxy_pass", "proxy_read_timeout 60;\n        proxy_pass", 1),
	"body size and access list": strings.Replace(policyTestValid, "add_header", "client_max_body_size 10m;\n    deny 1.2.3.4/32;\n    allow 10.0.0.0/8;\n    allow ::1;\n    deny all;\n    add_header", 1),
	"access log off":            policyTestInServer("access_log off;"),
	"stock error log level":     policyTestInServer("error_log /var/log/nginx/error.log crit;"),
	"exact path route":          policyTestWithLocation("= /api/world", "proxy_pass http://192.168.178.210:80;"),
	"prefix path route":         strings.Replace(policyTestWithLocation("/media/", "proxy_pass http://10.0.0.7:9000;"), "    location / {", "    location = /media { proxy_pass http://10.0.0.7:9000; }\n    location / {", 1),
	"logging in both servers": strings.Replace(policyTestInRedirect("access_log off;\n    error_log /var/log/nginx/error.log emerg;"),
		"    location / {", "    access_log off;\n    error_log /var/log/nginx/error.log emerg;\n    location / {", 1),
	"issue 149 shape": policyTestInServer("access_log off;\n    client_max_body_size 50m;\n    add_header Strict-Transport-Security \"max-age=31536000\" always;\n    gzip on;\n    gzip_types text/plain application/json;"),
}

// policyTestTuning are the tuning directives (#149) a raw config may carry in
// the server block and in location /. Each one is admitted in both scopes.
var policyTestTuning = []string{
	"client_max_body_size 0;",
	"client_max_body_size 2g;",
	"client_max_body_size 999999999g;",
	"client_body_buffer_size 128k;",
	"client_body_buffer_size 16m;",
	"add_header X-Robots-Tag noindex;",
	`add_header Content-Security-Policy "default-src 'self'" always;`,
	"access_log off;",
	"proxy_set_header X-Forwarded-Host $host;",
	"proxy_hide_header X-Powered-By;",
	"proxy_http_version 1.1;",
	"proxy_connect_timeout 5s;",
	"proxy_send_timeout 2m;",
	"proxy_read_timeout 3600;",
	"proxy_read_timeout 500ms;",
	"proxy_read_timeout 1h;",
	"proxy_read_timeout 999999h;",
	"proxy_connect_timeout 999999ms;",
	"proxy_buffering off;",
	"proxy_request_buffering off;",
	"proxy_buffer_size 16k; proxy_buffers 8 16k; proxy_busy_buffers_size 32k;",
	"proxy_buffer_size 4k; proxy_buffers 2 4k; proxy_busy_buffers_size 4k;",
	"proxy_buffer_size 128k; proxy_buffers 4 256k; proxy_busy_buffers_size 256k;",
	"proxy_buffer_size 16m; proxy_buffers 64 16m; proxy_busy_buffers_size 16m;",
	"proxy_buffer_size 1k; proxy_buffers 64 1k; proxy_busy_buffers_size 63k;",
	"proxy_redirect off;",
	"proxy_ssl_server_name on;",
	"gzip on;",
	"gzip_vary on;",
	"gzip_comp_level 1;",
	"gzip_comp_level 9;",
	"gzip_min_length 1k;",
	"gzip_min_length 1024m;",
	"gzip_types text/css application/javascript image/svg+xml;",
	"gzip_types *;",
	"gzip_proxied expired no-cache no-store private auth;",
	"gzip_proxied any;",
	"gzip_proxied off expired no-cache no-store private no_last_modified no_etag auth any;",
	"gzip_types " + strings.TrimSpace(strings.Repeat("text/x-a ", 32)) + ";",
	"add_header X-A 1; add_header X-A 2;",
	"proxy_set_header X-A 1; proxy_set_header X-B 2;",
	"proxy_hide_header X-A; proxy_hide_header X-B;",
	"access_log off; access_log off;",
	"gzip_types text/css; gzip_types text/xml;",
	"gzip_proxied any; gzip_proxied auth;",
}

// policyTestServerOnly are admitted only directly in the proxied server.
var policyTestServerOnly = []string{
	"server_tokens off;",
	"error_log /var/log/nginx/error.log warn;",
	"allow 10.0.0.0/8;",
	"allow 10.0.0.0/8; deny all;",
	"error_log /var/log/nginx/error.log warn; error_log /var/log/nginx/error.log crit;",
}

func TestValidateManagedAdmitsTuningDirectives(t *testing.T) {
	for _, statement := range policyTestTuning {
		for scope, content := range map[string]string{"server": policyTestInServer(statement), "location": policyTestInLocation(statement)} {
			t.Run(scope+"/"+statement, func(t *testing.T) {
				if err := ValidateManaged(content, policyTestPolicy); err != nil {
					t.Fatalf("allowed directive refused: %v\n%s", err, content)
				}
			})
		}
	}
	for _, statement := range policyTestServerOnly {
		t.Run("server/"+statement, func(t *testing.T) {
			if err := ValidateManaged(policyTestInServer(statement), policyTestPolicy); err != nil {
				t.Fatalf("allowed directive refused: %v", err)
			}
		})
		t.Run("location/"+statement, func(t *testing.T) {
			if err := ValidateManaged(policyTestInLocation(statement), policyTestPolicy); err == nil {
				t.Fatalf("server-only directive admitted in location /")
			}
		})
	}
}

func TestValidateManagedAdmitsBoundedVHost(t *testing.T) {
	for name, content := range policyTestAccepted {
		t.Run(name, func(t *testing.T) {
			if err := ValidateManaged(content, policyTestPolicy); err != nil {
				t.Fatalf("bounded raw vhost refused: %v\n%s", err, content)
			}
		})
	}
}

func policyTestInServer(statement string) string {
	return strings.Replace(policyTestValid, "    location / {", "    "+statement+"\n    location / {", 1)
}

func policyTestInLocation(statement string) string {
	return strings.Replace(policyTestValid, "        proxy_pass", "        "+statement+"\n        proxy_pass", 1)
}

// policyTestWithLocation adds a location block before `location /`.
func policyTestWithLocation(header, body string) string {
	return strings.Replace(policyTestValid, "    location / {", "    location "+header+" {\n        "+body+"\n    }\n    location / {", 1)
}

func policyTestInRedirect(statement string) string {
	return strings.Replace(policyTestRedirect, "    return", "    "+statement+"\n    return", 1) + policyTestValid
}

// policyTestRefused are vhosts outside the raw policy. The groups mirror the
// tokenizer rules nginx applies (quotes and "#" only matter at the start of a
// word; quoted and escaped names are plain names to nginx) and the per-scope
// directive allowlists.
var policyTestRefused = []struct {
	name    string
	content string
}{
	{"host", strings.Replace(policyTestValid, "server_name app.example.test", "server_name victim.example.test", 1)},
	{"cert path", strings.Replace(policyTestValid, policyTestCert, "/etc/shadow", 1)},
	{"key path", strings.Replace(policyTestValid, policyTestKey+";", "/etc/shadow;", 1)},
	{"port", strings.Replace(policyTestValid, "listen 443 ssl", "listen 8443 ssl", 1)},
	{"listen option", strings.Replace(policyTestValid, "listen 443 ssl", "listen 443 ssl default_server", 1)},
	{"include in server", policyTestInServer("include /etc/nginx/nginx.conf;")},
	{"include in location", policyTestInLocation("include /etc/nginx/mime.types;")},
	{"error_log in server", policyTestInServer("error_log /tmp/x.log info;")},
	{"access_log in location", policyTestInLocation("access_log /tmp/x.log;")},

	// Per-domain logging (#150): only `access_log off;` and the stock error
	// log with a level from proxymodel.ErrorLogLevels, only at server scope.
	{"access_log to file", policyTestInServer("access_log /var/log/nginx/app.log;")},
	{"access_log to syslog", policyTestInServer("access_log syslog:server=10.0.0.1;")},
	{"access_log off with format", policyTestInServer("access_log off combined;")},
	{"access_log quoted off", policyTestInServer(`access_log "off";`)},
	{"error_log stock path without level", policyTestInServer("error_log /var/log/nginx/error.log;")},
	{"error_log debug", policyTestInServer("error_log /var/log/nginx/error.log debug;")},
	{"error_log uppercase level", policyTestInServer("error_log /var/log/nginx/error.log CRIT;")},
	{"error_log extra argument", policyTestInServer("error_log /var/log/nginx/error.log crit warn;")},
	{"error_log quoted path", policyTestInServer(`error_log "/var/log/nginx/error.log" crit;`)},
	{"error_log sibling path", policyTestInServer("error_log /var/log/nginx/error.log.1 crit;")},
	{"error_log traversal", policyTestInServer("error_log /var/log/nginx/../../../etc/cron.d/x crit;")},
	{"error_log stderr", policyTestInServer("error_log stderr crit;")},
	{"error_log memory", policyTestInServer("error_log memory:32m debug;")},
	{"error_log in location", policyTestInLocation("error_log /var/log/nginx/error.log crit;")},
	{"redirect error_log debug", policyTestInRedirect("error_log /var/log/nginx/error.log debug;")},
	{"redirect access_log to file", policyTestInRedirect("access_log /var/log/nginx/app.log;")},

	{"quote inside header value", policyTestInServer(`add_header X-A a"; error_log /tmp/x.log info; #";`)},
	{"single quote inside header value", policyTestInServer(`add_header X-A a'; error_log /tmp/x.log info; #';`)},
	{"quote inside request header value", policyTestInLocation(`proxy_set_header X-A a"; error_log /tmp/x.log info; #";`)},
	{"quote inside redirect target", strings.Replace(policyTestRedirect, `return 301 https://$host$request_uri;`, `return 301 https://h/a"; error_log /tmp/x.log info; #";`, 1) + policyTestValid},
	{"quote inside header name", policyTestInServer(`add_header X"; error_log /tmp/x.log info; #" a;`)},

	{"double quoted name", policyTestInServer(`"error_log" /tmp/x.log info;`)},
	{"single quoted name", policyTestInServer(`'error_log' /tmp/x.log info;`)},
	{"escaped name", policyTestInServer(`error\_log /tmp/x.log info;`)},
	{"quoted allowed name", strings.Replace(policyTestValid, "add_header X-Frame-Options", `"add_header" X-Frame-Options`, 1)},
	{"quoted server_name value", strings.Replace(policyTestValid, "server_name app.example.test", `server_name "app.example.test"`, 1)},
	{"quoted cert path", strings.Replace(policyTestValid, "ssl_certificate "+policyTestCert, `ssl_certificate "`+policyTestCert+`"`, 1)},
	{"quoted location", strings.Replace(policyTestValid, "location / {", `location "/" {`, 1)},
	{"quoted block kind", strings.Replace(policyTestValid, "server {", `"server" {`, 1)},
	{"single quoted header value", strings.Replace(policyTestValid, "DENY always", `'DENY' always`, 1)},
	{"escape in quoted header value", strings.Replace(policyTestValid, "DENY always", `"a\nb" always`, 1)},
	{"backslash in header value", strings.Replace(policyTestValid, "DENY always", `a\;b always`, 1)},

	{"comment mid statement", policyTestInServer("add_header X-A a #\n;")},
	{"comment hides terminator", strings.Replace(policyTestValid, "DENY always;", "DENY #;\n always;", 1)},
	{"hash inside word", strings.Replace(policyTestValid, "DENY always", "a#b always", 1)},
	{"variable braces", strings.Replace(policyTestValid, "DENY always", "${host} always", 1)},
	{"brace inside word", strings.Replace(policyTestValid, "DENY always", "a}b always", 1)},

	{"redirect include", policyTestInRedirect("include /etc/nginx/mime.types;")},
	{"redirect error_log", policyTestInRedirect("error_log /tmp/x.log info;")},
	{"redirect access_log", policyTestInRedirect("access_log /tmp/x.log;")},
	{"redirect root", policyTestInRedirect("root /;")},
	{"redirect add_header", policyTestInRedirect("add_header X-A a;")},
	{"redirect quoted name", policyTestInRedirect(`"error_log" /tmp/x.log info;`)},
	{"redirect ssl listen", strings.Replace(policyTestRedirect, "listen 80;", "listen 443 ssl;", 1) + policyTestValid},
	{"redirect second return", strings.Replace(policyTestRedirect, "return 301 https://$host$request_uri;", "return 301 https://$host$request_uri;\n    return 200 x;", 1) + policyTestValid},
	{"redirect to http", strings.Replace(policyTestRedirect, "https://", "http://", 1) + policyTestValid},
	{"redirect for other host", strings.Replace(policyTestRedirect, "server_name app.example.test", "server_name victim.example.test", 1) + policyTestValid},

	{"second location", strings.Replace(policyTestValid, "    location / {", "    location / {\n        root /;\n    }\n    location / {", 1)},
	{"nested location", policyTestInLocation("location / { root /; }")},
	{"other location", strings.Replace(policyTestValid, "location / {", "location /x {", 1)},
	{"http block", "http { " + policyTestValid + " }"},
	{"top-level directive", "error_log /tmp/x.log;\n" + policyTestValid},
	{"three servers", policyTestRedirect + policyTestRedirect + policyTestValid},
	{"unbalanced close", policyTestValid + "\n}"},
	{"unterminated", policyTestValid + "\nerror_log /tmp/x.log"},
	{"unterminated quote", strings.Replace(policyTestValid, "DENY always", `"DENY always`, 1)},
	{"text after closing quote", strings.Replace(policyTestValid, "DENY always", `"DENY"x always`, 1)},
	{"nul byte", strings.Replace(policyTestValid, "DENY", "DE\x00NY", 1)},
	{"proxy_pass to socket", strings.Replace(policyTestValid, "http://127.0.0.1:3000", "http://unix:/run/x.sock:3000", 1)},
	{"limit_req", policyTestInServer("limit_req zone=z burst=1 nodelay;")},
	{"auth_basic", policyTestInServer(`auth_basic "x";`)},

	// nginx merges listen options per port across vhosts.
	{"listen 80 ssl", strings.Replace(policyTestValid, "listen 443 ssl;", "listen 80 ssl;", 1)},
	{"listen 80 http2", strings.Replace(policyTestValid, "listen 443 ssl;", "listen 80 http2;", 1)},
	{"listen 443 without ssl", strings.Replace(policyTestValid, "listen 443 ssl;", "listen 443;", 1)},
	{"listen 443 http2 without ssl", strings.Replace(policyTestValid, "listen 443 ssl;", "listen 443 http2;", 1)},
	{"listen options reordered", strings.Replace(policyTestValid, "listen 443 ssl;", "listen 443 http2 ssl;", 1)},
	{"redirect listen http2", strings.Replace(policyTestRedirect, "listen 80;", "listen 80 http2;", 1) + policyTestValid},

	{"redirect without server_name", strings.Replace(policyTestRedirect, "    server_name app.example.test;\n", "", 1) + policyTestValid},
	{"redirect with two server_names", strings.Replace(policyTestRedirect, "server_name app.example.test;", "server_name app.example.test;\n    server_name app.example.test;", 1) + policyTestValid},
	{"redirect to other target", strings.Replace(policyTestRedirect, "https://$host$request_uri", "https://victim.example.test$request_uri", 1) + policyTestValid},
	{"redirect to fixed path", strings.Replace(policyTestRedirect, "https://$host$request_uri", "https://$host/x", 1) + policyTestValid},

	// Path routes (#89): only `location = <path>` and `location <path>/`
	// with a path proxymodel accepts, the same directives as `location /`,
	// and exactly one `location /`.
	{"regex location", policyTestWithLocation("~ ^/api", "proxy_pass http://10.0.0.5:80;")},
	{"case-insensitive regex location", policyTestWithLocation("~* ^/api", "proxy_pass http://10.0.0.5:80;")},
	{"prefix priority location", policyTestWithLocation("^~ /api/", "proxy_pass http://10.0.0.5:80;")},
	{"named location", policyTestWithLocation("@fallback", "proxy_pass http://10.0.0.5:80;")},
	{"prefix without slash", policyTestWithLocation("/api", "proxy_pass http://10.0.0.5:80;")},
	{"exact without separate word", policyTestWithLocation("=/api", "proxy_pass http://10.0.0.5:80;")},
	{"quoted path location", policyTestWithLocation(`= "/api"`, "proxy_pass http://10.0.0.5:80;")},
	{"encoded path location", policyTestWithLocation("/a%2e/", "proxy_pass http://10.0.0.5:80;")},
	{"dot segment location", policyTestWithLocation("/a/../", "proxy_pass http://10.0.0.5:80;")},
	{"wildcard path location", policyTestWithLocation("/a*/", "proxy_pass http://10.0.0.5:80;")},
	{"path location with root", policyTestWithLocation("/static/", "root /etc;")},
	{"path location with alias", policyTestWithLocation("= /x", "alias /etc/shadow;")},
	{"path location with return", policyTestWithLocation("/api/", "return 200 x;")},
	{"path location with include", policyTestWithLocation("/api/", "include /etc/nginx/x.conf;\n        proxy_pass http://10.0.0.5:80;")},
	{"path location to socket", policyTestWithLocation("/api/", "proxy_pass http://unix:/run/x.sock:80;")},
	{"path location with uri", policyTestWithLocation("/api/", "proxy_pass http://10.0.0.5:80/x/;")},
	{"nested in path location", policyTestWithLocation("/api/", "location /api/x/ { proxy_pass http://10.0.0.5:80; }")},
	{"duplicate path location", strings.Replace(policyTestWithLocation("/api/", "proxy_pass http://10.0.0.5:80;"), "    location / {", "    location /api/ { proxy_pass http://10.0.0.6:80; }\n    location / {", 1)},
	{"no root location", strings.Replace(policyTestValid, "location / {", "location /x/ {", 1)},
	// Tuning directives (#149): only the documented argument forms.
	{"gzip variable", policyTestInServer("gzip $x;")},
	{"gzip_types quoted", policyTestInServer(`gzip_types "text/plain";`)},
	{"gzip_types variable", policyTestInServer("gzip_types $x;")},
	{"gzip_types bad mime", policyTestInServer("gzip_types text;")},
	{"gzip_proxied unknown flag", policyTestInServer("gzip_proxied all;")},
	{"gzip_comp_level 10", policyTestInServer("gzip_comp_level 10;")},
	{"gzip_disable regex", policyTestInServer(`gzip_disable "msie6";`)},
	{"gzip_static", policyTestInServer("gzip_static on;")},
	{"proxy_buffering variable", policyTestInLocation("proxy_buffering $x;")},
	{"proxy_buffers one arg", policyTestInLocation("proxy_buffers 16k;")},
	{"proxy_buffers zero", policyTestInLocation("proxy_buffers 0 16k;")},
	{"proxy_buffer_size gigabytes", policyTestInLocation("proxy_buffer_size 1g;")},
	{"proxy_redirect mapping", policyTestInLocation("proxy_redirect http://a/ http://b/;")},
	{"proxy_redirect default", policyTestInLocation("proxy_redirect default;")},
	{"proxy_ssl_verify", policyTestInLocation("proxy_ssl_verify on;")},
	{"proxy_ssl_trusted_certificate", policyTestInLocation("proxy_ssl_trusted_certificate /etc/shadow;")},
	{"proxy_ssl_certificate", policyTestInLocation("proxy_ssl_certificate /etc/shadow;")},
	{"proxy_temp_path", policyTestInLocation("proxy_temp_path /etc/cron.d;")},
	{"proxy_cache_path", policyTestInServer("proxy_cache_path /tmp/c keys_zone=c:1m;")},
	{"proxy_store", policyTestInLocation("proxy_store /etc/x;")},
	{"proxy_timeout variable", policyTestInLocation("proxy_read_timeout $x;")},
	{"proxy_timeout days", policyTestInLocation("proxy_read_timeout 1d;")},
	{"proxy_hide_header value", policyTestInLocation("proxy_hide_header X-A b;")},
	{"proxy_http_version 2", policyTestInLocation("proxy_http_version 2.0;")},
	{"client_body_temp_path", policyTestInServer("client_body_temp_path /etc;")},
	{"client_max_body_size variable", policyTestInLocation("client_max_body_size $x;")},
	{"server_tokens build", policyTestInServer("server_tokens build;")},
	{"server_tokens in location", policyTestInLocation("server_tokens off;")},
	{"proxy_pass in server", policyTestInServer("proxy_pass http://127.0.0.1:3000;")},
	{"rewrite in server", policyTestInServer(`rewrite ^/a$ /b break;`)},
	{"allow in location", policyTestInLocation("allow 10.0.0.0/8;")},
	{"error_log in location stock path", policyTestInLocation("error_log /var/log/nginx/error.log warn;")},

	// Forms nginx -t rejects: duplicates, buffer sets that break nginx's
	// merge checks, out-of-range values.
	{"duplicate gzip", policyTestInServer("gzip on;\n    gzip on;")},
	{"duplicate gzip in location", policyTestInLocation("gzip on; gzip off;")},
	{"duplicate server_tokens", policyTestInServer("server_tokens off; server_tokens on;")},
	{"duplicate client_max_body_size", policyTestInServer("client_max_body_size 1m; client_max_body_size 2m;")},
	{"duplicate proxy_buffering", policyTestInLocation("proxy_buffering off; proxy_buffering off;")},
	{"duplicate http2", strings.Replace(policyTestValid, "listen 443 ssl;", "listen 443 ssl;\n    http2 on;\n    http2 on;", 1)},
	{"duplicate proxy_read_timeout", policyTestInLocation("proxy_read_timeout 1s; proxy_read_timeout 2s;")},
	{"proxy_buffer_size alone", policyTestInLocation("proxy_buffer_size 1m;")},
	{"proxy_busy_buffers_size alone", policyTestInLocation("proxy_busy_buffers_size 1m;")},
	{"proxy_buffers alone", policyTestInLocation("proxy_buffers 8 16k;")},
	{"proxy_buffers one buffer", policyTestInLocation("proxy_buffer_size 4k; proxy_buffers 1 4k; proxy_busy_buffers_size 4k;")},
	{"proxy_buffers 65", policyTestInLocation("proxy_buffer_size 4k; proxy_buffers 65 4k; proxy_busy_buffers_size 8k;")},
	{"busy above buffers minus one", policyTestInLocation("proxy_buffer_size 4k; proxy_buffers 2 4k; proxy_busy_buffers_size 8k;")},
	{"busy below buffer size", policyTestInLocation("proxy_buffer_size 8k; proxy_buffers 4 4k; proxy_busy_buffers_size 4k;")},
	{"busy below one buffer", policyTestInLocation("proxy_buffer_size 4k; proxy_buffers 4 8k; proxy_busy_buffers_size 4k;")},
	{"location overrides into bad set", strings.Replace(policyTestInServer("proxy_buffer_size 4k; proxy_buffers 8 4k; proxy_busy_buffers_size 8k;"), "        proxy_pass", "        proxy_buffers 2 4k;\n        proxy_pass", 1)},
	{"buffer size above cap", policyTestInLocation("proxy_buffer_size 17m; proxy_buffers 64 17m; proxy_busy_buffers_size 17m;")},
	{"client_body_buffer_size above cap", policyTestInServer("client_body_buffer_size 17m;")},
	{"gzip_min_length above cap", policyTestInServer("gzip_min_length 1025m;")},
	{"client_max_body_size ten digits", policyTestInServer("client_max_body_size 9999999999g;")},
	{"timeout seven digits", policyTestInLocation("proxy_read_timeout 9999999h;")},
	{"gzip_types 33", policyTestInServer("gzip_types " + strings.TrimSpace(strings.Repeat("text/x-a ", 33)) + ";")},

	// Only the two rewrite forms nginxgen renders.
	{"rewrite nested quantifier", policyTestInLocation("rewrite (a+)+$ /x break;")},
	{"rewrite to absolute URL", policyTestInLocation("rewrite ^ http://evil.example/ break;")},
	{"rewrite unescaped dot prefix", policyTestInLocation("rewrite ^/a.b/?(.*)$ /$1 break;")},
	{"rewrite strip with other replacement", policyTestInLocation("rewrite ^/a/?(.*)$ /x$1 break;")},
	{"rewrite strip relative prefix", policyTestInLocation("rewrite ^a/?(.*)$ /$1 break;")},
	{"rewrite last", policyTestInLocation("rewrite ^.*$ /x last;")},

	// Files, code and other scopes stay out.
	{"access_log to managed-looking path", policyTestInLocation("access_log /var/log/nginx/app.example.test.access.log;")},
	{"access_log with variable path", policyTestInServer("access_log /var/log/nginx/$host.log;")},
	{"access_log with condition", policyTestInServer("access_log off if=$x;")},
	{"lua block", policyTestInLocation("content_by_lua_block { ngx.say(1); }")},
	{"lua directive", policyTestInLocation(`access_by_lua 'os.execute("id")';`)},
	{"lua file", policyTestInServer("rewrite_by_lua_file /tmp/x.lua;")},
	{"perl", policyTestInLocation("perl Module::handler;")},
	{"js_content", policyTestInLocation("js_content x.y;")},
	{"load_module", "load_module /tmp/x.so;\n" + policyTestValid},
	{"root", policyTestInServer("root /;")},
	{"alias", policyTestInLocation("alias /etc/;")},
	{"if block", policyTestInLocation("if ($x) { return 403; }")},
	{"set variable", policyTestInLocation("set $x 1;")},
	{"map block", "map $a $b { default 1; }\n" + policyTestValid},
	{"upstream block", "upstream u { server 127.0.0.1:3000; }\n" + policyTestValid},
	{"proxy_pass to upstream name", strings.Replace(policyTestValid, "http://127.0.0.1:3000", "http://u", 1)},
	{"proxy_pass with variable", strings.Replace(policyTestValid, "http://127.0.0.1:3000", "http://$host:3000", 1)},
	{"proxy_pass port zero", strings.Replace(policyTestValid, "127.0.0.1:3000", "127.0.0.1:0", 1)},
	{"proxy_pass port too high", strings.Replace(policyTestValid, "127.0.0.1:3000", "127.0.0.1:70000", 1)},
	{"two proxy_pass", policyTestInLocation("proxy_pass http://127.0.0.1:4000;")},
	{"no proxy_pass", strings.Replace(policyTestValid, "        proxy_pass http://127.0.0.1:3000;\n", "", 1)},
	{"no server_name", strings.Replace(policyTestValid, "    server_name app.example.test;\n", "", 1)},
	{"two server_names", policyTestInServer("server_name app.example.test;")},
	{"auth_basic_user_file raw", policyTestInServer("auth_basic_user_file " + policyTestAuth + ";")},

	{"long line", strings.Replace(policyTestValid, "DENY always", "\""+strings.Repeat("a", 4096)+"\" always", 1)},
	{"long comment", "#" + strings.Repeat("a", 4096) + "\n" + policyTestValid},
}

// TestValidateManagedNamesDirectiveAndLine checks that a refusal tells the
// operator which directive on which line broke the policy, without quoting
// argument values.
func TestValidateManagedNamesDirectiveAndLine(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"unknown directive in server", policyTestInServer("include /etc/nginx/secret.conf;"), `line 8: nginx directive "include" is not allowed in the server block`},
		{"unknown directive in location", policyTestInLocation("proxy_cache_path /etc/x keys_zone=a:1m;"), `line 9: nginx directive "proxy_cache_path" is not allowed in location /`},
		{"bad arguments", policyTestInLocation("access_log /etc/cron.d/x;"), `line 9: nginx directive "access_log" has unsupported arguments in location /`},
		{"lua block", policyTestInLocation("content_by_lua_block { ngx.say(1); }"), `line 9: nginx block "content_by_lua_block" is not allowed inside location /`},
		{"second location", strings.Replace(policyTestValid, "    location / {", "    location /x {\n    }\n    location / {", 1), `line 8: nginx block "location" is not allowed in the server block`},
		{"top-level directive", "\n\nerror_log /tmp/x.log;\n" + policyTestValid, `line 3: top-level directives are not allowed`},
		{"redirect server", policyTestInRedirect("root /;"), `line 5: nginx directive "root" is not allowed in the redirect server block`},
		{"quoted name", policyTestInServer(`"include" /etc/x;`), `line 8: nginx directive is not in plain form`},
		{"no proxy_pass", strings.Replace(policyTestValid, "        proxy_pass http://127.0.0.1:3000;\n", "", 1), `line 8: location / needs exactly one proxy_pass, found 0`},
		{"duplicate", policyTestInServer("gzip on;\n    gzip on;"), `line 9: nginx directive "gzip" appears more than once in the server block`},
		{"buffer set", policyTestInLocation("proxy_buffer_size 1m;"), `line 8: the proxy buffer settings of location / must set proxy_buffer_size, proxy_buffers and proxy_busy_buffers_size together`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateManaged(tt.content, policyTestPolicy)
			if err == nil {
				t.Fatalf("refused config admitted:\n%s", tt.content)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.want)
			}
			for _, secret := range []string{"/etc/nginx/secret.conf", "/etc/cron.d/x", "ngx.say", "keys_zone"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error quotes an argument value %q: %q", secret, err)
				}
			}
		})
	}
}

// policyTestNginxRejects names refused cases that nginx -t itself rejects.
// The Docker agreement test checks that, so these cases keep exercising the
// nginx checks the policy mirrors.
var policyTestNginxRejects = map[string]bool{
	"duplicate gzip": true, "duplicate gzip in location": true, "duplicate server_tokens": true,
	"duplicate client_max_body_size": true, "duplicate proxy_buffering": true,
	"duplicate http2": true, "duplicate proxy_read_timeout": true,
	"proxy_buffer_size alone": true, "proxy_busy_buffers_size alone": true, "proxy_buffers one buffer": true,
	"busy above buffers minus one": true, "busy below buffer size": true, "busy below one buffer": true,
	"location overrides into bad set": true,
}

func TestPolicyTestNginxRejectsNamesRefusedCases(t *testing.T) {
	refused := map[string]bool{}
	for _, tt := range policyTestRefused {
		refused[tt.name] = true
	}
	for name := range policyTestNginxRejects {
		if !refused[name] {
			t.Errorf("policyTestNginxRejects names %q, which is not a refused case", name)
		}
	}
}

func TestValidateManagedRefusesUnboundedVHost(t *testing.T) {
	for _, tt := range policyTestRefused {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateManaged(tt.content, policyTestPolicy); err == nil {
				t.Fatalf("unbounded raw vhost was admitted:\n%s", tt.content)
			}
		})
	}
}

// policyTestGenerated is one nginxgen rendering.
type policyTestGenerated struct {
	// server is Result.Server, what a raw config copied from the form holds.
	server string
	// full is the file the helper writes: the http preamble, then the server.
	full string
	// raw reports whether the server passes as a raw config. Basic auth and
	// rate limits are generator-only.
	raw bool
}

// policyTestGeneratedConfigs renders routes across nginxgen's options.
func policyTestGeneratedConfigs(t *testing.T) map[string]policyTestGenerated {
	t.Helper()
	base := proxymodel.Route{Host: policyTestHost, Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080}}
	variants := map[string]func(*proxymodel.Route){
		"plain": func(*proxymodel.Route) {},
		"https upstream": func(r *proxymodel.Route) {
			r.Upstream = proxymodel.Upstream{Addr: "backend.internal", Port: 8443, Scheme: proxymodel.SchemeHTTPS}
		},
		"ipv6 upstream":            func(r *proxymodel.Route) { r.Upstream.Addr = "[::1]" },
		"unbracketed ipv6":         func(r *proxymodel.Route) { r.Upstream.Addr = "fd00::5" },
		"fully qualified upstream": func(r *proxymodel.Route) { r.Upstream.Addr = "ai.lan." },
		"long header value": func(r *proxymodel.Route) {
			r.ResponseHeaders = map[string]string{"Content-Security-Policy": "default-src 'self'; " + strings.Repeat("img-src https://a.example.test; ", 100)}
		},
		"percent header value": func(r *proxymodel.Route) { r.ResponseHeaders = map[string]string{"X-P": "100%{HOME}e"} },
		"websocket":            func(r *proxymodel.Route) { r.WebSocket = true },
		"body size":            func(r *proxymodel.Route) { r.MaxBodySize = "10MB" },
		"unlimited":            func(r *proxymodel.Route) { r.MaxBodySize = "unlimited" },
		"access list": func(r *proxymodel.Route) {
			r.IPAllowlist = []string{"10.0.0.0/8", "2001:db8::/32"}
			r.IPBlocklist = []string{"1.2.3.4/32"}
		},
		"block list": func(r *proxymodel.Route) { r.IPBlocklist = []string{"1.2.3.4"} },
		"headers": func(r *proxymodel.Route) {
			r.RequestHeaders = map[string]string{"X-Custom": "abc", "X-Spaced": "a b", "X-Empty": "", "X-Quote": `say "hi"`}
			r.ResponseHeaders = map[string]string{"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; img-src *", "X-Var": "$host", "X-Hash": "a#b", "X-Apostrophe": "it's", "X-Brace": "{x}"}
		},
		"strip prefix":        func(r *proxymodel.Route) { r.Path.StripPrefix = "/api" },
		"strip dotted prefix": func(r *proxymodel.Route) { r.Path.StripPrefix = "/api.v1/" },
		"rewrite":             func(r *proxymodel.Route) { r.Path.Rewrite = "/new/path" },
		"timeouts":            func(r *proxymodel.Route) { r.Timeouts = proxymodel.Timeouts{Read: 60, Write: 30} },
		"basic auth": func(r *proxymodel.Route) {
			r.BasicAuth = &proxymodel.BasicAuth{Username: "admin", PasswordHash: "$2y$10$abc"}
		},
		"access log off": func(r *proxymodel.Route) { r.AccessLog = proxymodel.AccessLogOff },
		"error log crit": func(r *proxymodel.Route) { r.ErrorLogLevel = "crit" },
		"logging every level": func(r *proxymodel.Route) {
			r.AccessLog = proxymodel.AccessLogOff
			r.ErrorLogLevel = "emerg"
		},
		"path routes": func(r *proxymodel.Route) { r.PathRoutes = policyTestPathRoutes() },
		"path routes with options": func(r *proxymodel.Route) {
			r.PathRoutes = policyTestPathRoutes()
			r.WebSocket = true
			r.RequestHeaders = map[string]string{"X-A": "1 2"}
			r.Timeouts = proxymodel.Timeouts{Read: 5, Write: 5}
			r.Path.StripPrefix = "/app"
			r.IPAllowlist = []string{"192.168.0.0/16"}
		},
		"rate limit":    func(r *proxymodel.Route) { r.RateLimit.RequestsPerSecond = 10 },
		"slow rate":     func(r *proxymodel.Route) { r.RateLimit.RequestsPerSecond = 0.5 },
		"wildcard host": func(r *proxymodel.Route) { r.Host = "*.example.test" },
		"everything supported": func(r *proxymodel.Route) {
			r.WebSocket = true
			r.MaxBodySize = "1g"
			r.IPAllowlist = []string{"192.168.0.0/16"}
			r.RequestHeaders = map[string]string{"X-A": "1"}
			r.ResponseHeaders = map[string]string{"X-B": "2 3"}
			r.Path.StripPrefix = "/app"
			r.Timeouts = proxymodel.Timeouts{Read: 5, Write: 5}
			r.BasicAuth = &proxymodel.BasicAuth{Username: "admin", PasswordHash: "$2y$10$abc"}
			r.RateLimit.RequestsPerSecond = 3
			r.AccessLog = proxymodel.AccessLogOff
			r.ErrorLogLevel = "error"
		},
	}
	for _, level := range proxymodel.ErrorLogLevels {
		variants["error log "+level+" with access off"] = func(r *proxymodel.Route) {
			r.AccessLog = proxymodel.AccessLogOff
			r.ErrorLogLevel = level
		}
	}
	tlsModes := []struct {
		name       string
		policy     proxymodel.TLSPolicy
		forceHTTPS bool
		version    string
	}{
		{name: "plaintext", policy: proxymodel.TLSPolicyOff},
		{name: "tls", policy: proxymodel.TLSPolicyCentral},
		{name: "tls force-https", policy: proxymodel.TLSPolicyCentral, forceHTTPS: true},
		{name: "tls force-https old nginx", policy: proxymodel.TLSPolicyCentral, forceHTTPS: true, version: "1.18.0"},
	}
	configs := make(map[string]policyTestGenerated)
	for variantName, mutate := range variants {
		for _, mode := range tlsModes {
			route := base
			route.TLS.Policy = mode.policy
			route.ForceHTTPS = mode.forceHTTPS
			mutate(&route)
			rendered, err := nginxgen.Render(nginxgen.Input{Route: route, CertPath: policyTestCert, KeyPath: policyTestKey, AuthFile: policyTestAuth, NginxVersion: mode.version})
			if err != nil {
				t.Fatal(err)
			}
			if len(rendered.Warnings) != 0 {
				t.Fatalf("%s/%s: unexpected render warnings %v", variantName, mode.name, rendered.Warnings)
			}
			full := rendered.Server
			if rendered.HTTPPreamble != "" {
				full = strings.TrimSuffix(rendered.HTTPPreamble, "\n") + "\n\n" + rendered.Server
			}
			configs[fmt.Sprintf("%s/%s", variantName, mode.name)] = policyTestGenerated{
				server: rendered.Server,
				full:   full,
				raw:    route.BasicAuth == nil && route.RateLimit.RequestsPerSecond == 0,
			}
		}
	}
	return configs
}

// policyTestPathRoutes covers each path route form nginxgen renders.
func policyTestPathRoutes() []proxymodel.PathRoute {
	return []proxymodel.PathRoute{
		{Match: proxymodel.PathMatchExact, Path: "/api/world", Upstream: proxymodel.Upstream{Addr: "192.168.178.210", Port: 80}},
		{Match: proxymodel.PathMatchPrefix, Path: "/media", Upstream: proxymodel.Upstream{Addr: "10.0.0.7", Port: 9000}},
		{Match: proxymodel.PathMatchPrefix, Path: "/ws.v1", StripPrefix: true, WebSocket: true, Upstream: proxymodel.Upstream{Addr: "fd00::5", Port: 8443, Scheme: proxymodel.SchemeHTTPS}},
		{Match: proxymodel.PathMatchPrefix, Path: "/admin", Upstream: proxymodel.Upstream{Addr: "10.0.0.8", Port: 8081}},
		{Match: proxymodel.PathMatchExact, Path: "/admin", Upstream: proxymodel.Upstream{Addr: "10.0.0.9", Port: 8082}},
		{Match: proxymodel.PathMatchExact, Path: "/", Upstream: proxymodel.Upstream{Addr: "10.0.0.10", Port: 8083}},
	}
}

// policyTestPolicyFor returns the policy for a generated config's host.
func policyTestPolicyFor(content string) ManagedPolicy {
	policy := policyTestPolicy
	if strings.Contains(content, "server_name *.example.test;") {
		policy.Host = "*.example.test"
	}
	return policy
}

// TestValidateManagedAdmitsGeneratorOutput requires every vhost nginxgen
// renders for the supported options to pass the raw policy, so a config copied
// from the form view into the raw editor stays writable. Basic auth and rate
// limits are refused as raw configs; the helper only writes them rendered.
func TestValidateManagedAdmitsGeneratorOutput(t *testing.T) {
	for name, generated := range policyTestGeneratedConfigs(t) {
		t.Run(name, func(t *testing.T) {
			err := ValidateManaged(generated.server, policyTestPolicyFor(generated.server))
			if generated.raw && err != nil {
				t.Fatalf("generated vhost refused as raw: %v\n%s", err, generated.server)
			}
			if !generated.raw && err == nil {
				t.Fatalf("generator-only vhost admitted as raw:\n%s", generated.server)
			}
		})
	}
}

// TestValidateRenderedAdmitsGeneratorOutput requires every file the helper
// renders, including basic auth and rate limits, to pass ValidateRendered.
func TestValidateRenderedAdmitsGeneratorOutput(t *testing.T) {
	for name, generated := range policyTestGeneratedConfigs(t) {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRendered(generated.full, policyTestPolicyFor(generated.full)); err != nil {
				t.Fatalf("rendered vhost refused: %v\n%s", err, generated.full)
			}
		})
	}
}

const policyTestRendered = `limit_req_zone $binary_remote_addr zone=nurproxy_app_example_test:10m rate=10r/s;

server {
    listen 443 ssl;
    server_name app.example.test;
    ssl_certificate /var/lib/nurproxy-agent/certs/app.example.test.crt;
    ssl_certificate_key /var/lib/nurproxy-agent/certs/app.example.test.key.plain;

    auth_basic "Restricted: app.example.test";
    auth_basic_user_file /var/lib/nurproxy-agent/auth/auth-app.example.test.htpasswd;

    limit_req zone=nurproxy_app_example_test burst=10 nodelay;

    add_header X-A "\\\";include /etc/x;#" always;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}`

// policyTestRenderedRefused are rendered-file shapes outside the generator's
// forms.
var policyTestRenderedRefused = map[string]string{
	"other top-level directive": "error_log /tmp/x.log;\n" + policyTestRendered,
	"two zones":                 "limit_req_zone $binary_remote_addr zone=nurproxy_b:10m rate=1r/s;\n" + policyTestRendered,
	"zone with other key":       strings.Replace(policyTestRendered, "$binary_remote_addr", "$remote_addr", 1),
	"zone with other size":      strings.Replace(policyTestRendered, ":10m", ":100m", 1),
	"limit_req other zone":      strings.Replace(policyTestRendered, "limit_req zone=nurproxy_app_example_test", "limit_req zone=other", 1),
	"limit_req without zone":    strings.Replace(policyTestRendered, "limit_req_zone $binary_remote_addr zone=nurproxy_app_example_test:10m rate=10r/s;\n", "", 1),
	"other auth file":           strings.Replace(policyTestRendered, policyTestAuth, "/etc/shadow", 1),
	"escaped newline in value":  strings.Replace(policyTestRendered, `"\\\";include /etc/x;#"`, `"a\nb"`, 1),
	"unescaped quote in value":  strings.Replace(policyTestRendered, `"\\\";include /etc/x;#"`, `"\\";include /etc/x;#"`, 1),
	"listen 80 ssl":             strings.Replace(policyTestRendered, "listen 443 ssl", "listen 80 ssl", 1),
}

func TestValidateRenderedRefusesOtherForms(t *testing.T) {
	if err := ValidateRendered(policyTestRendered, policyTestPolicy); err != nil {
		t.Fatalf("rendered sample refused: %v", err)
	}
	for name, content := range policyTestRenderedRefused {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRendered(content, policyTestPolicy); err == nil {
				t.Fatalf("rendered vhost admitted:\n%s", content)
			}
		})
	}
}

// TestRenderedHeaderValueReadsBack checks that the escaped header forms
// nginxgen renders are read by nginx's tokenizer as exactly one value.
func TestRenderedHeaderValueReadsBack(t *testing.T) {
	blocks, _, err := parseConfig(policyTestRendered)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range blocks[0].directives {
		if d.tokens[0].value == "add_header" {
			if len(d.tokens) != 4 || d.tokens[2].value != `\";include /etc/x;#` {
				t.Fatalf("add_header tokens = %+v", d.tokens)
			}
			return
		}
	}
	t.Fatal("no add_header")
}
