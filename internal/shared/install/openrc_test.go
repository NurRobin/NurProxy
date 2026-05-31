package install

import (
	"strings"
	"testing"
)

func TestRenderOpenRC(t *testing.T) {
	s := Service{
		Name:        "nurproxy-agent",
		Description: "NurProxy agent",
		BinaryPath:  "/usr/bin/nurproxy-agent",
		Args:        []string{"--data-dir", "/var/lib/nurproxy-agent"},
		User:        "root",
		DataDir:     "/var/lib/nurproxy-agent",
		Env:         map[string]string{"NP_FQDN": "edge1.example.com", "NP_ORCHESTRATOR": "https://np.example.com"},
	}
	script := RenderOpenRC(s)

	must := []string{
		"#!/sbin/openrc-run",
		`name="nurproxy-agent"`,
		`command="/usr/bin/nurproxy-agent"`,
		`command_args="--data-dir /var/lib/nurproxy-agent"`,
		`command_user="root"`,
		`supervisor="supervise-daemon"`,
		`output_log="/var/lib/nurproxy-agent/nurproxy-agent.log"`,
		`export NP_FQDN="edge1.example.com"`,
		"depend() {",
	}
	for _, m := range must {
		if !strings.Contains(script, m) {
			t.Errorf("openrc script missing %q\n---\n%s", m, script)
		}
	}
	// Env exports sorted.
	if i, j := strings.Index(script, "NP_FQDN"), strings.Index(script, "NP_ORCHESTRATOR"); i < 0 || j < 0 || i > j {
		t.Errorf("env exports not sorted\n%s", script)
	}
}

func TestRenderOpenRCMinimal(t *testing.T) {
	s := Service{Name: "nurproxy", BinaryPath: "/usr/bin/nurproxy"}
	script := RenderOpenRC(s)
	for _, absent := range []string{"command_args=", "command_user=", "output_log=", "export "} {
		if strings.Contains(script, absent) {
			t.Errorf("script should not contain %q when unset\n%s", absent, script)
		}
	}
}
