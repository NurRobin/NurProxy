package install

import (
	"strings"
	"testing"
)

func TestRenderRCd(t *testing.T) {
	s := Service{
		Name:       "nurproxy-agent",
		BinaryPath: "/usr/local/bin/nurproxy-agent",
		Args:       []string{"--data-dir", "/var/db/nurproxy-agent"},
		User:       "root",
		Env:        map[string]string{"NP_FQDN": "edge1.example.com", "NP_ORCHESTRATOR": "https://np"},
	}
	script := RenderRCd(s)

	must := []string{
		"#!/bin/sh",
		"# PROVIDE: nurproxy_agent",
		". /etc/rc.subr",
		`name="nurproxy_agent"`,
		`rcvar="nurproxy_agent_enable"`,
		`pidfile="/var/run/nurproxy_agent.pid"`,
		`command="/usr/sbin/daemon"`,
		"run_rc_command",
		`nurproxy_agent_user="root"`,
	}
	for _, m := range must {
		if !strings.Contains(script, m) {
			t.Errorf("rc.d script missing %q\n---\n%s", m, script)
		}
	}
	// daemon command_args carries the env prefix, binary and args, in sorted env order.
	if !strings.Contains(script, "/usr/bin/env NP_FQDN=edge1.example.com NP_ORCHESTRATOR=https://np /usr/local/bin/nurproxy-agent --data-dir /var/db/nurproxy-agent") {
		t.Errorf("command_args wrong\n%s", script)
	}
}

func TestRcdName(t *testing.T) {
	if got := rcdName("nurproxy-agent"); got != "nurproxy_agent" {
		t.Errorf("rcdName = %q", got)
	}
}
