package nginx

import "testing"

func TestAttributeNginxTestError_table(t *testing.T) {
	const ourFile = "/etc/nginx/sites-available/nurproxy-app.example.com.conf"

	tests := []struct {
		name        string
		out         string
		ourFile     string
		wantLocated bool
		wantOurs    bool
		wantFile    string
		wantLine    int
	}{
		{
			name:        "error in our file by full path",
			out:         `nginx: [emerg] unknown directive "proxy_pas" in /etc/nginx/sites-available/nurproxy-app.example.com.conf:7`,
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    true,
			wantFile:    "/etc/nginx/sites-available/nurproxy-app.example.com.conf",
			wantLine:    7,
		},
		{
			name:        "error in our file via sites-enabled symlink matches by base name",
			out:         `nginx: [emerg] invalid number of arguments in "listen" directive in /etc/nginx/sites-enabled/nurproxy-app.example.com.conf:3`,
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    true,
			wantFile:    "/etc/nginx/sites-enabled/nurproxy-app.example.com.conf",
			wantLine:    3,
		},
		{
			name:        "error in operator's pre-existing config elsewhere",
			out:         `nginx: [emerg] unexpected "}" in /etc/nginx/sites-enabled/legacy-site:42`,
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    false,
			wantFile:    "/etc/nginx/sites-enabled/legacy-site",
			wantLine:    42,
		},
		{
			name:        "error in main nginx.conf not ours",
			out:         `nginx: [emerg] "worker_connections" directive is duplicate in /etc/nginx/nginx.conf:15`,
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    false,
			wantFile:    "/etc/nginx/nginx.conf",
			wantLine:    15,
		},
		{
			name: "chained context lines attribute to the innermost (last) frame",
			out: `nginx: [emerg] invalid parameter in /etc/nginx/nginx.conf:9
nginx: configuration file test failed in /etc/nginx/sites-enabled/nurproxy-app.example.com.conf:5`,
			ourFile:     ourFile,
			wantLocated: true,
			wantOurs:    true,
			wantFile:    "/etc/nginx/sites-enabled/nurproxy-app.example.com.conf",
			wantLine:    5,
		},
		{
			name:        "no parseable location surfaces unattributed",
			out:         "nginx: [emerg] open() \"/etc/nginx/nginx.conf\" failed (13: Permission denied)",
			ourFile:     ourFile,
			wantLocated: false,
			wantOurs:    false,
			wantFile:    "",
			wantLine:    0,
		},
		{
			// Real unprivileged-agent failure: the only "in file:line" clause is on a
			// benign [warn] about the user directive at nginx.conf:1; the actual fault
			// is an [emerg] cert-key permission error with no location. We must NOT
			// attribute the failure to nginx.conf:1.
			name: "warn-only location is not attributed (cert-key permission failure)",
			out: `nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" failed (13: Permission denied)
2026/05/30 20:55:43 [warn] 474022#474022: the "user" directive makes sense only if the master process runs with super-user privileges, ignored in /etc/nginx/nginx.conf:1
2026/05/30 20:55:43 [emerg] 474022#474022: cannot load certificate key "/etc/nginx/ssl/llm_P256/private.key": BIO_new_file() failed (SSL: error:8000000D Permission denied)
nginx: configuration file /etc/nginx/nginx.conf test failed`,
			ourFile:     ourFile,
			wantLocated: false,
			wantOurs:    false,
			wantFile:    "",
			wantLine:    0,
		},
		{
			name:        "empty ourFile (Validate) never attributes ours",
			out:         `nginx: [emerg] unknown directive "foo" in /etc/nginx/sites-enabled/nurproxy-app.example.com.conf:2`,
			ourFile:     "",
			wantLocated: true,
			wantOurs:    false,
			wantFile:    "/etc/nginx/sites-enabled/nurproxy-app.example.com.conf",
			wantLine:    2,
		},
		{
			name:        "empty output",
			out:         "",
			ourFile:     ourFile,
			wantLocated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AttributeNginxTestError(tt.out, tt.ourFile)
			if got.Located != tt.wantLocated {
				t.Errorf("Located = %v, want %v", got.Located, tt.wantLocated)
			}
			if got.Ours != tt.wantOurs {
				t.Errorf("Ours = %v, want %v", got.Ours, tt.wantOurs)
			}
			if got.File != tt.wantFile {
				t.Errorf("File = %q, want %q", got.File, tt.wantFile)
			}
			if got.Line != tt.wantLine {
				t.Errorf("Line = %d, want %d", got.Line, tt.wantLine)
			}
			if got.Raw != tt.out {
				t.Errorf("Raw = %q, want verbatim output %q", got.Raw, tt.out)
			}
		})
	}
}

func TestCommandError_message(t *testing.T) {
	tests := []struct {
		name string
		attr ErrAttribution
		want string
	}{
		{
			name: "ours names the generated config",
			attr: ErrAttribution{Located: true, Ours: true, File: "/x/nurproxy-a.conf", Line: 4},
			want: "nginx -t failed in the generated config at /x/nurproxy-a.conf:4",
		},
		{
			name: "theirs names the existing config with jump location",
			attr: ErrAttribution{Located: true, Ours: false, File: "/etc/nginx/sites-enabled/legacy", Line: 9},
			want: "nginx -t failed: error in your existing config at /etc/nginx/sites-enabled/legacy:9",
		},
		{
			name: "unlocated surfaces raw output",
			attr: ErrAttribution{Located: false, Raw: "nginx: [emerg] permission denied"},
			want: "nginx -t failed: nginx: [emerg] permission denied",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (&commandError{Attribution: tt.attr}).Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
