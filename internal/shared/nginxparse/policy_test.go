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
	"compact location":          strings.Replace(policyTestValid, "location / {\n        proxy_pass http://127.0.0.1:3000;\n        proxy_set_header Host $host;\n    }", "location / { proxy_pass http://127.0.0.1:3000; }", 1),
	"escaped rewrite":           strings.Replace(policyTestValid, "proxy_pass", `rewrite ^/api\.v1/?(.*)$ /$1 break;`+"\n        proxy_pass", 1),
	"header without always":     strings.Replace(policyTestValid, "DENY always", "DENY", 1),
	"timeout without unit":      strings.Replace(policyTestValid, "proxy_pass", "proxy_read_timeout 60;\n        proxy_pass", 1),
	"body size and access list": strings.Replace(policyTestValid, "add_header", "client_max_body_size 10m;\n    deny 1.2.3.4/32;\n    allow 10.0.0.0/8;\n    allow ::1;\n    deny all;\n    add_header", 1),
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

// policyTestGeneratedConfigs renders routes across nginxgen's options.
func policyTestGeneratedConfigs(t *testing.T) map[string]string {
	t.Helper()
	base := proxymodel.Route{Host: policyTestHost, Upstream: proxymodel.Upstream{Addr: "10.0.0.4", Port: 8080}}
	variants := map[string]func(*proxymodel.Route){
		"plain": func(*proxymodel.Route) {},
		"https upstream": func(r *proxymodel.Route) {
			r.Upstream = proxymodel.Upstream{Addr: "backend.internal", Port: 8443, Scheme: proxymodel.SchemeHTTPS}
		},
		"websocket": func(r *proxymodel.Route) { r.WebSocket = true },
		"body size": func(r *proxymodel.Route) { r.MaxBodySize = "10MB" },
		"unlimited": func(r *proxymodel.Route) { r.MaxBodySize = "unlimited" },
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
		"everything supported": func(r *proxymodel.Route) {
			r.WebSocket = true
			r.MaxBodySize = "1g"
			r.IPAllowlist = []string{"192.168.0.0/16"}
			r.RequestHeaders = map[string]string{"X-A": "1"}
			r.ResponseHeaders = map[string]string{"X-B": "2 3"}
			r.Path.StripPrefix = "/app"
			r.Timeouts = proxymodel.Timeouts{Read: 5, Write: 5}
		},
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
	configs := make(map[string]string)
	for variantName, mutate := range variants {
		for _, mode := range tlsModes {
			route := base
			route.TLS.Policy = mode.policy
			route.ForceHTTPS = mode.forceHTTPS
			mutate(&route)
			rendered, err := nginxgen.Render(nginxgen.Input{Route: route, CertPath: policyTestCert, KeyPath: policyTestKey, NginxVersion: mode.version})
			if err != nil {
				t.Fatal(err)
			}
			if len(rendered.Warnings) != 0 {
				t.Fatalf("%s/%s: unexpected render warnings %v", variantName, mode.name, rendered.Warnings)
			}
			configs[fmt.Sprintf("%s/%s", variantName, mode.name)] = rendered.Server
		}
	}
	return configs
}

// TestValidateManagedAdmitsGeneratorOutput requires every vhost nginxgen
// renders for the supported options to pass the raw policy, so a config copied
// from the form view into the raw editor stays writable.
func TestValidateManagedAdmitsGeneratorOutput(t *testing.T) {
	for name, content := range policyTestGeneratedConfigs(t) {
		t.Run(name, func(t *testing.T) {
			if err := ValidateManaged(content, policyTestPolicy); err != nil {
				t.Fatalf("generated vhost refused: %v\n%s", err, content)
			}
		})
	}
}
