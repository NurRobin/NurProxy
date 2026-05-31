package install

import (
	"strings"
	"testing"
)

func TestRenderUnitHardening(t *testing.T) {
	s := Service{
		Name:         "nurproxy-agent",
		Description:  "NurProxy agent",
		BinaryPath:   "/usr/local/bin/nurproxy-agent",
		Args:         []string{"--data-dir", "/var/lib/nurproxy-agent"},
		User:         "root",
		DataDir:      "/var/lib/nurproxy-agent",
		Capabilities: []string{"CAP_NET_BIND_SERVICE"},
	}
	unit := RenderUnit(s)

	must := []string{
		"Description=NurProxy agent",
		"After=network-online.target",
		"ExecStart=/usr/local/bin/nurproxy-agent --data-dir /var/lib/nurproxy-agent",
		"Restart=on-failure",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
		"ReadWritePaths=/var/lib/nurproxy-agent",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"WantedBy=multi-user.target",
	}
	for _, m := range must {
		if !strings.Contains(unit, m) {
			t.Errorf("unit missing %q\n---\n%s", m, unit)
		}
	}
}

func TestRenderUnitWritePaths(t *testing.T) {
	s := Service{
		Name:       "nurproxy-agent",
		BinaryPath: "/usr/local/bin/nurproxy-agent",
		DataDir:    "/var/lib/nurproxy-agent",
		WritePaths: []string{"-/etc/nginx", "-/var/log/nginx"},
	}
	unit := RenderUnit(s)
	// DataDir keeps its own line; the extra proxy trees join one further line so
	// ProtectSystem=strict no longer makes /etc/nginx a read-only mount.
	for _, m := range []string{
		"ReadWritePaths=/var/lib/nurproxy-agent\n",
		"ReadWritePaths=-/etc/nginx -/var/log/nginx\n",
	} {
		if !strings.Contains(unit, m) {
			t.Errorf("unit missing %q\n---\n%s", m, unit)
		}
	}
}

func TestRenderUnitOptionalsOmitted(t *testing.T) {
	// No caps, no env file, no data dir → those lines must be absent.
	s := Service{Name: "nurproxy", Description: "NurProxy", BinaryPath: "/usr/local/bin/nurproxy", User: "root"}
	unit := RenderUnit(s)
	for _, absent := range []string{"AmbientCapabilities", "EnvironmentFile", "ReadWritePaths"} {
		if strings.Contains(unit, absent) {
			t.Errorf("unit should not contain %q when unset\n%s", absent, unit)
		}
	}
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/nurproxy\n") {
		t.Errorf("ExecStart should have no args\n%s", unit)
	}
}

func TestRenderUnitWithEnvFile(t *testing.T) {
	s := Service{Name: "nurproxy", BinaryPath: "/usr/local/bin/nurproxy", EnvFile: "/etc/nurproxy/nurproxy.env"}
	if !strings.Contains(RenderUnit(s), "EnvironmentFile=/etc/nurproxy/nurproxy.env") {
		t.Error("expected EnvironmentFile line")
	}
}

func TestRenderEnvSortedAndFormatted(t *testing.T) {
	got := RenderEnv(map[string]string{"NP_PORT": "8080", "NP_DATA_DIR": "/var/lib/nurproxy"})
	want := "NP_DATA_DIR=/var/lib/nurproxy\nNP_PORT=8080\n"
	if got != want {
		t.Errorf("RenderEnv = %q, want %q", got, want)
	}
}

func TestUnitPath(t *testing.T) {
	if p := (Service{Name: "nurproxy"}).UnitPath(); p != "/etc/systemd/system/nurproxy.service" {
		t.Errorf("UnitPath = %q", p)
	}
}
