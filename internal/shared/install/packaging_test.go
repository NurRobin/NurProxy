package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The .deb/.rpm packages ship a static systemd unit (deploy/packaging/*.service)
// because nfpm can't run the binary's install subcommand at package-build time.
// These tests pin those files to RenderUnit's output so they can never drift.

func TestPackagedOrchestratorUnitMatchesRenderUnit(t *testing.T) {
	svc := Service{
		Name: "nurproxy", Description: "NurProxy orchestrator",
		BinaryPath: "/usr/bin/nurproxy", User: "root",
		DataDir: "/var/lib/nurproxy", EnvFile: "/etc/nurproxy/nurproxy.env", PrivateData: true,
	}
	assertPackagedUnit(t, "nurproxy.service", svc)
}

func TestOrchestratorPostinstallHardensBeforeStarting(t *testing.T) {
	path := filepath.Join("..", "..", "..", "deploy", "packaging", "postinstall-orchestrator.sh")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(got)
	command := "/usr/bin/nurproxy permissions --data-dir \"$data_dir\" --systemd-drop-in /etc/systemd/system/nurproxy.service.d/data-dir.conf"
	harden := strings.Index(script, command)
	start := strings.Index(script, "systemctl enable --now nurproxy.service")
	if harden < 0 || start < 0 || harden > start {
		t.Fatalf("postinstall must harden data before service start/restart:\n%s", script)
	}
	lineEnd := strings.IndexByte(script[harden:], '\n')
	if lineEnd < 0 {
		lineEnd = len(script) - harden
	}
	if strings.Contains(script[harden:harden+lineEnd], "|| true") {
		t.Fatal("permission migration failure must propagate")
	}
	if !strings.Contains(script, "/etc/nurproxy/nurproxy.env") || !strings.Contains(script, "NP_DATA_DIR=") {
		t.Fatal("postinstall must resolve the configured NP_DATA_DIR")
	}
	for _, command := range []string{"systemctl daemon-reload || true", "systemctl enable --now nurproxy.service || true", "systemctl try-restart nurproxy.service || true"} {
		if strings.Contains(script, command) {
			t.Errorf("postinstall swallows failure: %s", command)
		}
	}
}

func TestPackagedAgentUnitMatchesRenderUnit(t *testing.T) {
	svc := Service{
		Name: "nurproxy-agent", Description: "NurProxy agent",
		BinaryPath: "/usr/bin/nurproxy-agent", Args: []string{"--data-dir", "/var/lib/nurproxy-agent"},
		User: "root", DataDir: "/var/lib/nurproxy-agent", EnvFile: "/etc/nurproxy-agent/agent.env",
		WritePaths:   AgentProxyWritePaths,
		Capabilities: AgentCapabilities,
	}
	assertPackagedUnit(t, "nurproxy-agent.service", svc)
}

func assertPackagedUnit(t *testing.T, file string, svc Service) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "deploy", "packaging", file)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading packaged unit %s: %v", path, err)
	}
	if want := RenderUnit(svc); string(got) != want {
		t.Errorf("packaged %s drifted from RenderUnit — regenerate it.\n--- packaged ---\n%s\n--- RenderUnit ---\n%s", file, got, want)
	}
}
