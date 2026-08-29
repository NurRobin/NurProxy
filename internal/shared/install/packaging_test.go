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
	command := "/usr/bin/nurproxy permissions --data-dir /var/lib/nurproxy --environment-file /etc/nurproxy/nurproxy.env --systemd-drop-in /etc/systemd/system/nurproxy.service.d/data-dir.conf"
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
	if !strings.Contains(script, "--environment-file /etc/nurproxy/nurproxy.env") {
		t.Fatal("postinstall must delegate configured NP_DATA_DIR parsing")
	}
	for _, unsafe := range []string{"sed ", "source ", ". /etc/nurproxy", "eval "} {
		if strings.Contains(script, unsafe) {
			t.Errorf("postinstall parses EnvironmentFile unsafely with %q", unsafe)
		}
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
		BinaryPath: "/usr/bin/nurproxy-agent", Args: []string{"--data-dir", "/var/lib/nurproxy-agent/state"},
		User: "nurproxy", Group: "nurproxy", DataDir: "/var/lib/nurproxy-agent/state", EnvFile: "/etc/nurproxy-agent/agent.env",
		AfterUnits:   []string{"nurproxy-agent-helper.socket"},
		WantsUnits:   []string{"nurproxy-agent-helper.socket"},
		WritePaths:   []string{"/var/lib/nurproxy-agent/helper-staging"},
		Capabilities: AgentCapabilities,
	}
	assertPackagedUnit(t, "nurproxy-agent.service", svc)
}

func TestPackagedRootHelperUnitsMatchTrustedRenderers(t *testing.T) {
	root := filepath.Join("..", "..", "..", "deploy", "packaging")
	checks := map[string]string{
		"nurproxy-agent-helper.service": RenderRootHelperUnit("/usr/bin/nurproxy-agent"),
		"nurproxy-agent-helper.socket":  RenderRootHelperSocket(),
	}
	for name, want := range checks {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("reading packaged %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("packaged %s drifted from its renderer\n--- packaged ---\n%s\n--- rendered ---\n%s", name, got, want)
		}
	}
}

func TestAgentPostinstallCreatesUnprivilegedBoundaryBeforeRestart(t *testing.T) {
	path := filepath.Join("..", "..", "..", "deploy", "packaging", "postinstall-agent.sh")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(payload)
	ordered := []string{
		"useradd --system",
		"install -d -o root -g nurproxy -m 0770 /var/lib/nurproxy-agent/helper-staging",
		"install -d -o root -g root -m 0700 /var/lib/nurproxy-agent/helper",
		"systemctl enable --now nurproxy-agent-helper.socket",
		"systemctl start nurproxy-agent.service",
	}
	last := -1
	for _, needle := range ordered {
		index := strings.Index(script, needle)
		if index < 0 || index <= last {
			t.Fatalf("postinstall missing ordered boundary step %q:\n%s", needle, script)
		}
		last = index
	}
	for _, forbidden := range []string{"chown -R", "chmod -R", "systemctl enable --now nurproxy-agent-helper.socket || true"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("postinstall contains unsafe or swallowed boundary step %q", forbidden)
		}
	}
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
