package permcheck

import (
	"strings"
	"testing"
)

func TestBuildRemediation_table(t *testing.T) {
	tests := []struct {
		name string
		opts RemediationOptions

		wantSteps       int    // number of steps expected
		wantNoWriteStep bool   // step 1 (group/ownership) omitted
		wantNoSudoers   bool   // SudoersLine empty + step 2 omitted
		wantSudoersLine string // exact expected sudoers line (when not empty)
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "nginx absolute commands with dirs",
			opts: RemediationOptions{
				Backend:   "nginx",
				User:      "nurproxy",
				Dirs:      []string{"/etc/nginx/sites-available", "/etc/nginx/sites-enabled"},
				TestCmd:   "/usr/sbin/nginx -t",
				ReloadCmd: "/usr/sbin/nginx -s reload",
			},
			wantSteps:       2,
			wantSudoersLine: "nurproxy ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -s reload",
			wantContains: []string{
				"sudo groupadd -f nurproxy",
				"sudo usermod -aG nurproxy nurproxy",
				"sudo chgrp -R nurproxy /etc/nginx/sites-available",
				"sudo chmod -R g+w /etc/nginx/sites-available",
				"sudo chmod g+s /etc/nginx/sites-available",
				"sudo chgrp -R nurproxy /etc/nginx/sites-enabled",
				"sudo chmod g+s /etc/nginx/sites-enabled",
				"echo 'nurproxy ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -s reload' | sudo tee /etc/sudoers.d/nurproxy-agent",
				"sudo chmod 0440 /etc/sudoers.d/nurproxy-agent",
				"sudo visudo -c",
			},
			wantNotContains: []string{"# note:"},
		},
		{
			name: "apache custom group conf.d single dir",
			opts: RemediationOptions{
				Backend:   "apache",
				User:      "www-data",
				Group:     "webadmins",
				Dirs:      []string{"/etc/httpd/conf.d"},
				TestCmd:   "/usr/sbin/apachectl configtest",
				ReloadCmd: "/usr/sbin/apachectl graceful",
			},
			wantSteps:       2,
			wantSudoersLine: "www-data ALL=(root) NOPASSWD: /usr/sbin/apachectl configtest, /usr/sbin/apachectl graceful",
			wantContains: []string{
				"sudo groupadd -f webadmins",
				"sudo usermod -aG webadmins www-data",
				"sudo chgrp -R webadmins /etc/httpd/conf.d",
				"sudo chmod g+s /etc/httpd/conf.d",
			},
			// The default "nurproxy" group must not leak in when a custom group is set
			// (the sudoers drop-in path legitimately contains "nurproxy", so we assert
			// on the group-grant commands specifically).
			wantNotContains: []string{"groupadd -f nurproxy", "-aG nurproxy"},
		},
		{
			name: "no dirs omits the write step",
			opts: RemediationOptions{
				Backend:   "nginx",
				User:      "nurproxy",
				TestCmd:   "/usr/sbin/nginx -t",
				ReloadCmd: "/usr/sbin/nginx -s reload",
			},
			wantSteps:       1,
			wantNoWriteStep: true,
			wantSudoersLine: "nurproxy ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -s reload",
		},
		{
			name: "no commands omits the sudoers step",
			opts: RemediationOptions{
				Backend: "nginx",
				User:    "nurproxy",
				Dirs:    []string{"/etc/nginx/sites-available"},
			},
			wantSteps:     1,
			wantNoSudoers: true,
		},
		{
			name:          "empty opts yields nothing",
			opts:          RemediationOptions{},
			wantSteps:     0,
			wantNoSudoers: true,
		},
		{
			name: "bare command path emits a note",
			opts: RemediationOptions{
				Backend:   "nginx",
				User:      "nurproxy",
				Dirs:      []string{"/etc/nginx/sites-available"},
				TestCmd:   "nginx -t",
				ReloadCmd: "nginx -s reload",
			},
			wantSteps:       2,
			wantSudoersLine: "nurproxy ALL=(root) NOPASSWD: nginx -t, nginx -s reload",
			wantContains: []string{
				`# note: use absolute paths in the sudoers line for: nginx`,
			},
		},
		{
			name: "only reload command still builds sudoers line",
			opts: RemediationOptions{
				Backend:   "nginx",
				User:      "nurproxy",
				ReloadCmd: "/usr/sbin/nginx -s reload",
			},
			wantSteps:       1,
			wantNoWriteStep: true,
			wantSudoersLine: "nurproxy ALL=(root) NOPASSWD: /usr/sbin/nginx -s reload",
		},
		{
			name: "empty group defaults to nurproxy",
			opts: RemediationOptions{
				Backend: "nginx",
				User:    "agent",
				Dirs:    []string{"/etc/nginx/sites-available"},
			},
			wantSteps:     1,
			wantNoSudoers: true,
			wantContains:  []string{"sudo groupadd -f nurproxy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rem := BuildRemediation(tt.opts)

			if len(rem.Steps) != tt.wantSteps {
				t.Fatalf("steps = %d, want %d (%+v)", len(rem.Steps), tt.wantSteps, rem.Steps)
			}

			if tt.wantNoSudoers {
				if rem.SudoersLine != "" {
					t.Fatalf("expected empty SudoersLine, got %q", rem.SudoersLine)
				}
			} else if rem.SudoersLine != tt.wantSudoersLine {
				t.Fatalf("SudoersLine = %q, want %q", rem.SudoersLine, tt.wantSudoersLine)
			}

			joined := allCommands(rem)
			for _, want := range tt.wantContains {
				if !strings.Contains(joined, want) {
					t.Fatalf("commands missing %q\n--- got ---\n%s", want, joined)
				}
			}
			for _, notWant := range tt.wantNotContains {
				if strings.Contains(joined, notWant) {
					t.Fatalf("commands unexpectedly contain %q\n--- got ---\n%s", notWant, joined)
				}
			}

			// Write step, when present, must be ordered before the sudoers step.
			if !tt.wantNoWriteStep && tt.wantSteps == 2 {
				if !strings.Contains(rem.Steps[0].Title, "writable") {
					t.Fatalf("step 0 should be the writable/group step, got %q", rem.Steps[0].Title)
				}
				if !strings.Contains(rem.Steps[1].Title, "scoped sudoers") {
					t.Fatalf("step 1 should be the scoped sudoers step, got %q", rem.Steps[1].Title)
				}
			}
		})
	}
}

func TestBuildRemediation_sudoersInstallIsScopedAndValidated(t *testing.T) {
	rem := BuildRemediation(RemediationOptions{
		User:      "nurproxy",
		TestCmd:   "/usr/sbin/nginx -t",
		ReloadCmd: "/usr/sbin/nginx -s reload",
	})
	cmds := allCommands(rem)
	// Never blanket sudo: the line must scope to exactly the two commands.
	if strings.Contains(rem.SudoersLine, "ALL=(ALL)") || strings.Contains(rem.SudoersLine, "NOPASSWD: ALL") {
		t.Fatalf("sudoers line must be scoped, not blanket: %q", rem.SudoersLine)
	}
	if !strings.Contains(cmds, "visudo -c") {
		t.Fatalf("install must validate with visudo -c: %s", cmds)
	}
	if !strings.Contains(cmds, "chmod 0440 /etc/sudoers.d/nurproxy-agent") {
		t.Fatalf("install must lock down the drop-in file mode: %s", cmds)
	}
}

func TestBuildRemediation_deterministic(t *testing.T) {
	opts := RemediationOptions{
		User:      "nurproxy",
		Dirs:      []string{"/etc/nginx/sites-available", "/etc/nginx/sites-enabled"},
		TestCmd:   "/usr/sbin/nginx -t",
		ReloadCmd: "/usr/sbin/nginx -s reload",
	}
	a := BuildRemediation(opts)
	b := BuildRemediation(opts)
	if allCommands(a) != allCommands(b) || a.SudoersLine != b.SudoersLine {
		t.Fatalf("BuildRemediation is not deterministic")
	}
}

func TestBuildRemediation_emptyDirEntriesIgnored(t *testing.T) {
	rem := BuildRemediation(RemediationOptions{
		User: "nurproxy",
		Dirs: []string{"", "  ", ""},
	})
	if len(rem.Steps) != 0 {
		t.Fatalf("all-empty dirs should omit the write step, got %+v", rem.Steps)
	}
}

func allCommands(rem Remediation) string {
	var sb strings.Builder
	for _, s := range rem.Steps {
		sb.WriteString(s.Title)
		sb.WriteString("\n")
		for _, c := range s.Commands {
			sb.WriteString(c)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
