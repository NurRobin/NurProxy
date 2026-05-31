package install

import (
	"os"
	"path/filepath"
	"testing"
)

// The .deb/.rpm packages ship a static systemd unit (deploy/packaging/*.service)
// because nfpm can't run the binary's install subcommand at package-build time.
// These tests pin those files to RenderUnit's output so they can never drift.

func TestPackagedOrchestratorUnitMatchesRenderUnit(t *testing.T) {
	svc := Service{
		Name: "nurproxy", Description: "NurProxy orchestrator",
		BinaryPath: "/usr/bin/nurproxy", User: "root",
		DataDir: "/var/lib/nurproxy", EnvFile: "/etc/nurproxy/nurproxy.env",
	}
	assertPackagedUnit(t, "nurproxy.service", svc)
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
