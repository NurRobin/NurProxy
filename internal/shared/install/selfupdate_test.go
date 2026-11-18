package install

import (
	"strings"
	"testing"
)

func TestRenderSelfUpdateUnits(t *testing.T) {
	pathUnit, serviceUnit, err := RenderSelfUpdateUnits("/usr/local/bin/nurproxy-agent", "/var/lib/nurproxy-agent", "nurproxy-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PathExists=/var/lib/nurproxy-agent/self-update/request.json", "Unit=nurproxy-agent-update.service", "WantedBy=paths.target"} {
		if !strings.Contains(pathUnit, want) {
			t.Errorf("path unit lacks %q:\n%s", want, pathUnit)
		}
	}
	for _, want := range []string{
		"Type=oneshot",
		"ExecStart=/usr/local/bin/nurproxy-agent self-update-apply --data-dir /var/lib/nurproxy-agent --service-manager systemd --unit nurproxy-agent.service",
		"User=root",
		"TimeoutStartSec=15min",
	} {
		if !strings.Contains(serviceUnit, want) {
			t.Errorf("service unit lacks %q:\n%s", want, serviceUnit)
		}
	}
	for _, bad := range [][3]string{
		{"relative/nurproxy-agent", "/var/lib/x", "a.service"},
		{"/usr/local/bin/nurproxy agent", "/var/lib/x", "a.service"},
		{"/usr/local/bin/nurproxy-agent", "/var/lib/x;rm", "a.service"},
		{"/usr/local/bin/nurproxy-agent", "/var/lib/x", "a service"},
	} {
		if _, _, err := RenderSelfUpdateUnits(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestRenderSelfUpdatePlist(t *testing.T) {
	plist, err := RenderSelfUpdatePlist("/usr/local/bin/nurproxy-agent", "/var/lib/nurproxy-agent", AgentLaunchdLabel())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>de.nurrobin.nurproxy-agent-update</string>",
		"<string>self-update-apply</string>",
		"<string>de.nurrobin.nurproxy-agent</string>",
		"<key>WatchPaths</key>",
		"<string>/var/lib/nurproxy-agent/self-update</string>",
		"<string>root</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	if SelfUpdateLaunchdPlistPath() != "/Library/LaunchDaemons/de.nurrobin.nurproxy-agent-update.plist" {
		t.Fatal(SelfUpdateLaunchdPlistPath())
	}
}
