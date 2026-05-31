package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	agentconfig "github.com/NurRobin/NurProxy/internal/agent/config"
	"github.com/NurRobin/NurProxy/internal/shared/install"
	"gopkg.in/yaml.v3"
)

// agentService builds the agent's install.Service. Agent config is written as
// agent.yaml in the data dir (not env) to sidestep the data-dir flag/env
// precedence and to use the agent's native config file. install.AgentCapabilities
// keeps the unit narrow: CAP_NET_BIND_SERVICE for the bundled Caddy's ports and
// CAP_DAC_OVERRIDE so existing-mode `nginx -t` can read TLS keys and write logs.
func agentService(bin, dataDir string, cfg agentconfig.Config, user string) (install.Service, error) {
	cfg.DataDir = dataDir
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return install.Service{}, fmt.Errorf("rendering agent.yaml: %w", err)
	}
	return install.Service{
		Name:         "nurproxy-agent",
		Description:  "NurProxy agent",
		BinaryPath:   bin,
		Args:         []string{"--data-dir", dataDir},
		User:         user,
		DataDir:      dataDir,
		WritePaths:   install.AgentProxyWritePaths,
		ConfigFile:   filepath.Join(dataDir, "agent.yaml"),
		ConfigData:   string(data),
		Capabilities: install.AgentCapabilities,
	}, nil
}

// cmdInstall handles `nurproxy-agent install`.
func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	orchestrator := fs.String("orchestrator", "", "Orchestrator URL (required)")
	fqdnFlag := fs.String("fqdn", "", "Agent anchor FQDN (required)")
	dataDir := fs.String("data-dir", "/var/lib/nurproxy-agent", "Data directory")
	apiPort := fs.Int("api-port", 8780, "Agent API port")
	caddyPort := fs.Int("caddy-admin-port", 2019, "Caddy admin API port (localhost)")
	user := fs.String("user", "root", "System user to run the service as")
	bin := fs.String("bin", selfPath(), "Path to the nurproxy-agent binary the service runs")
	_ = fs.Parse(args)

	if *orchestrator == "" || *fqdnFlag == "" {
		log.Fatalf("install requires --orchestrator and --fqdn")
	}

	cfg := agentconfig.Config{
		OrchestratorURL: *orchestrator,
		FQDN:            *fqdnFlag,
		APIPort:         *apiPort,
		CaddyAdminPort:  *caddyPort,
	}
	svc, err := agentService(*bin, *dataDir, cfg, *user)
	if err != nil {
		log.Fatalf("install failed: %v", err)
	}
	if err := install.Install(svc, os.Stdout); err != nil {
		log.Fatalf("install failed: %v", err)
	}
}

// cmdUninstall handles `nurproxy-agent uninstall`.
func cmdUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/var/lib/nurproxy-agent", "Data directory (only removed with --purge)")
	purge := fs.Bool("purge", false, "Also remove the data dir (token, agent id, config)")
	yes := fs.Bool("yes", false, "Skip the confirmation prompt")
	_ = fs.Parse(args)

	if *purge && !*yes && !confirm(fmt.Sprintf("Remove the nurproxy-agent service AND its data at %s? [y/N] ", *dataDir)) {
		fmt.Println("aborted")
		return
	}
	svc := install.Service{Name: "nurproxy-agent", DataDir: *dataDir, ConfigFile: filepath.Join(*dataDir, "agent.yaml")}
	if err := install.Uninstall(svc, *purge, os.Stdout); err != nil {
		log.Fatalf("uninstall failed: %v", err)
	}
}

func selfPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "/usr/local/bin/nurproxy-agent"
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	var resp string
	_, _ = fmt.Scanln(&resp)
	return resp == "y" || resp == "Y" || resp == "yes"
}
