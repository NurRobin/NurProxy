package install

import (
	"strings"
	"testing"
)

func TestRenderPlist(t *testing.T) {
	s := Service{
		Name:        "nurproxy",
		Description: "NurProxy orchestrator",
		BinaryPath:  "/usr/local/bin/nurproxy",
		Args:        []string{"--data-dir", "/var/lib/nurproxy"},
		User:        "root",
		DataDir:     "/var/lib/nurproxy",
		Env:         map[string]string{"NP_PORT": "8080", "NP_DATA_DIR": "/var/lib/nurproxy"},
	}
	plist := RenderPlist(s)

	must := []string{
		"<key>Label</key>\n  <string>de.nurrobin.nurproxy</string>",
		"<key>ProgramArguments</key>",
		"<string>/usr/local/bin/nurproxy</string>",
		"<string>--data-dir</string>",
		"<key>RunAtLoad</key>\n  <true/>",
		"<key>KeepAlive</key>\n  <true/>",
		"<key>StandardOutPath</key>\n  <string>/var/lib/nurproxy/nurproxy.log</string>",
		"<key>UserName</key>\n  <string>root</string>",
	}
	for _, m := range must {
		if !strings.Contains(plist, m) {
			t.Errorf("plist missing %q\n---\n%s", m, plist)
		}
	}

	// Env keys are emitted in sorted order.
	if i, j := strings.Index(plist, "NP_DATA_DIR"), strings.Index(plist, "NP_PORT"); i < 0 || j < 0 || i > j {
		t.Errorf("env vars not in sorted order\n%s", plist)
	}
}

func TestRenderPlistNoEnvNoDataDir(t *testing.T) {
	s := Service{Name: "nurproxy-agent", BinaryPath: "/usr/local/bin/nurproxy-agent"}
	plist := RenderPlist(s)
	for _, absent := range []string{"EnvironmentVariables", "StandardOutPath", "UserName"} {
		if strings.Contains(plist, absent) {
			t.Errorf("plist should not contain %q when unset\n%s", absent, plist)
		}
	}
	if !strings.Contains(plist, "de.nurrobin.nurproxy-agent") {
		t.Errorf("wrong label\n%s", plist)
	}
}

func TestXMLEscape(t *testing.T) {
	if got := xmlEscape("a&b<c>"); got != "a&amp;b&lt;c&gt;" {
		t.Errorf("xmlEscape = %q", got)
	}
}
