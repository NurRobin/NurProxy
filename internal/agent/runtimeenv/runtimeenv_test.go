package runtimeenv

import (
	"reflect"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantID   string
		wantLike []string
	}{
		{
			name:     "debian",
			content:  "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			wantID:   "debian",
			wantLike: nil,
		},
		{
			name:     "ubuntu has ID_LIKE",
			content:  "ID=ubuntu\nID_LIKE=debian\n",
			wantID:   "ubuntu",
			wantLike: []string{"debian"},
		},
		{
			name:     "rhel-like multiple tokens, quoted",
			content:  "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
			wantID:   "rocky",
			wantLike: []string{"rhel", "centos", "fedora"},
		},
		{
			name:    "empty",
			content: "",
			wantID:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, like := parseOSRelease(tt.content)
			if id != tt.wantID {
				t.Errorf("ID = %q, want %q", id, tt.wantID)
			}
			if !reflect.DeepEqual(like, tt.wantLike) {
				t.Errorf("ID_LIKE = %v, want %v", like, tt.wantLike)
			}
		})
	}
}

func TestDetectInitFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	tests := []struct {
		name        string
		goos        string
		vars        map[string]string
		wantInit    string
		wantManaged bool
		wantUnit    string
	}{
		{
			name:        "systemd via INVOCATION_ID",
			goos:        "linux",
			vars:        map[string]string{"INVOCATION_ID": "abc123"},
			wantInit:    InitSystemd,
			wantManaged: true,
		},
		{
			name:        "systemd via JOURNAL_STREAM",
			goos:        "linux",
			vars:        map[string]string{"JOURNAL_STREAM": "8:12345"},
			wantInit:    InitSystemd,
			wantManaged: true,
		},
		{
			name:        "openrc carries the unit name",
			goos:        "linux",
			vars:        map[string]string{"RC_SVCNAME": "nurproxy-agent"},
			wantInit:    InitOpenRC,
			wantManaged: true,
			wantUnit:    "nurproxy-agent",
		},
		{
			name:        "launchd on darwin",
			goos:        "darwin",
			vars:        map[string]string{"XPC_SERVICE_NAME": "com.nurproxy.agent"},
			wantInit:    InitLaunchd,
			wantManaged: true,
			wantUnit:    "com.nurproxy.agent",
		},
		{
			name: "launchd sentinel 0 is not a service",
			goos: "darwin",
			vars: map[string]string{"XPC_SERVICE_NAME": "0"},
		},
		{
			name: "foreground / unmanaged",
			goos: "linux",
			vars: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			init, managed, unit := detectInitFromEnv(tt.goos, env(tt.vars))
			if init != tt.wantInit || managed != tt.wantManaged || unit != tt.wantUnit {
				t.Errorf("got (%q,%v,%q), want (%q,%v,%q)", init, managed, unit, tt.wantInit, tt.wantManaged, tt.wantUnit)
			}
		})
	}
}

func TestParseUnitFromCgroup(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "cgroup v2 systemd service",
			content: "0::/system.slice/nurproxy-agent.service\n",
			want:    "nurproxy-agent.service",
		},
		{
			name:    "cgroup v1 multi-line picks the service segment",
			content: "12:pids:/system.slice/nginx.service\n11:memory:/system.slice/nginx.service\n",
			want:    "nginx.service",
		},
		{
			name:    "user scope",
			content: "0::/user.slice/user-1000.slice/session-3.scope\n",
			want:    "session-3.scope",
		},
		{
			name:    "no unit",
			content: "0::/\n",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseUnitFromCgroup(tt.content); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseMountinfoReadOnly(t *testing.T) {
	// A ProtectSystem=strict sandbox remounts / read-only; /var/lib/nurproxy-agent
	// is the only ReadWritePaths entry. /etc is therefore under the read-only root.
	sandbox := "" +
		"1 1 0:1 / / ro,relatime shared:1 - overlay overlay rw\n" +
		"2 1 0:2 / /var/lib/nurproxy-agent rw,relatime shared:2 - ext4 /dev/sda1 rw\n" +
		"3 1 0:3 / /proc rw,nosuid - proc proc rw\n"
	if !parseMountinfoReadOnly(sandbox, "/etc") {
		t.Error("/etc should be read-only under a ro root mount")
	}
	if parseMountinfoReadOnly(sandbox, "/var/lib/nurproxy-agent/x") {
		t.Error("a ReadWritePaths subtree should be writable (longest-prefix match wins)")
	}

	// A normal host: root is rw.
	normal := "1 1 0:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
	if parseMountinfoReadOnly(normal, "/etc") {
		t.Error("/etc should be writable on a normal rw root")
	}

	// Garbage / short lines must not panic and default to writable.
	if parseMountinfoReadOnly("garbage\n\nshort line here\n", "/etc") {
		t.Error("unparseable mountinfo should not report read-only")
	}
}

func TestDetectNeverPanics(t *testing.T) {
	// Detect reads real host files; it must always return without panicking,
	// whatever this CI host looks like.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Detect panicked: %v", r)
		}
	}()
	e := Detect()
	if e.OS == "" {
		t.Error("OS should always be set")
	}
}
