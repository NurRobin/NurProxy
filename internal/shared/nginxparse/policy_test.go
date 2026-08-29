package nginxparse

import "testing"

func TestValidateManagedRawPolicyAdmitsBoundedVHostAndRejectsHostPathsPortsAndIncludes(t *testing.T) {
	valid := `server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name app.example.test;
    ssl_certificate /var/lib/nurproxy-agent/certs/app.example.test.crt;
    ssl_certificate_key /var/lib/nurproxy-agent/certs/app.example.test.key.plain;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}`
	if err := ValidateManaged(valid, ManagedPolicy{
		Host: "app.example.test", CertPath: "/var/lib/nurproxy-agent/certs/app.example.test.crt",
		KeyPath: "/var/lib/nurproxy-agent/certs/app.example.test.key.plain",
	}); err != nil {
		t.Fatalf("valid bounded raw vhost: %v", err)
	}
	tests := map[string]string{
		"host":    replacePolicyTest(valid, "server_name app.example.test", "server_name victim.example.test"),
		"cert":    replacePolicyTest(valid, "/var/lib/nurproxy-agent/certs/app.example.test.crt", "/etc/shadow"),
		"port":    replacePolicyTest(valid, "listen 443 ssl", "listen 8443 ssl"),
		"include": replacePolicyTest(valid, "location / {", "include /etc/nginx/nginx.conf;\n    location / {"),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateManaged(content, ManagedPolicy{Host: "app.example.test", CertPath: "/var/lib/nurproxy-agent/certs/app.example.test.crt", KeyPath: "/var/lib/nurproxy-agent/certs/app.example.test.key.plain"}); err == nil {
				t.Fatal("unsafe raw vhost was admitted")
			}
		})
	}
}

func replacePolicyTest(source, old, replacement string) string {
	for index := 0; index+len(old) <= len(source); index++ {
		if source[index:index+len(old)] == old {
			return source[:index] + replacement + source[index+len(old):]
		}
	}
	return source
}
