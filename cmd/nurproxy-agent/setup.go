package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/install"
)

// agentEnvFile is the EnvironmentFile the packaged unit reads (NP_ORCHESTRATOR,
// NP_FQDN). `setup` writes it and starts the service.
const agentEnvFile = "/etc/nurproxy-agent/agent.env"

// cmdSetup handles `nurproxy-agent setup`: a guided, one-shot configure for the
// two values the agent needs (orchestrator URL + FQDN), then it starts the
// service. Flags skip the prompts for non-interactive use.
func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	orchestrator := fs.String("orchestrator", "", "Orchestrator URL (skips the prompt)")
	fqdnFlag := fs.String("fqdn", "", "Agent anchor FQDN (skips the prompt)")
	dataDir := fs.String("data-dir", "/var/lib/nurproxy-agent", "Data directory")
	user := fs.String("user", "root", "System user to run the service as")
	bin := fs.String("bin", selfPath(), "Path to the nurproxy-agent binary the service runs")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		log.Fatalf("setup must run as root (try: sudo %s setup)", filepath.Base(os.Args[0]))
	}

	in := bufio.NewReader(os.Stdin)
	orch := strings.TrimSpace(*orchestrator)
	if orch == "" {
		orch = prompt(in, "Orchestrator URL (must be reachable FROM this server)")
	}
	fq := strings.TrimSpace(*fqdnFlag)
	if fq == "" {
		fq = prompt(in, "This agent's FQDN (a hostname inside an assigned DNS zone, e.g. edge1.example.com)")
	}
	if orch == "" || fq == "" {
		log.Fatalf("setup needs both an orchestrator URL and an FQDN")
	}

	checkReachable(orch)

	env := map[string]string{"NP_ORCHESTRATOR": orch, "NP_FQDN": fq}

	if unitInstalled() {
		// A package already laid down the EnvironmentFile-based unit — just fill
		// in the config and start it (don't write a second unit).
		if err := install.WriteEnvFile(agentEnvFile, env, os.Stdout); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
		if err := install.EnableService("nurproxy-agent", os.Stdout); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
	} else {
		// No unit yet (manual binary install) — lay one down that reads the env file.
		svc := install.Service{
			Name:         "nurproxy-agent",
			Description:  "NurProxy agent",
			BinaryPath:   *bin,
			Args:         []string{"--data-dir", *dataDir},
			User:         *user,
			DataDir:      *dataDir,
			WritePaths:   install.AgentProxyWritePaths,
			EnvFile:      agentEnvFile,
			Env:          env,
			Capabilities: []string{"CAP_NET_BIND_SERVICE"},
		}
		if err := install.Install(svc, os.Stdout); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
	}

	fmt.Println()
	fmt.Println("The agent is starting and will register with the orchestrator.")
	fmt.Println("Open the dashboard and approve (adopt) it to finish.")
}

// prompt reads a trimmed line from in after printing label.
func prompt(in *bufio.Reader, label string) string {
	fmt.Printf("%s: ", label)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

// checkReachable does a best-effort HTTP probe of the orchestrator FROM THIS
// host — the single most common setup mistake is an address only reachable from
// the browser. Any HTTP response counts as reachable; failure only warns.
func checkReachable(rawURL string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		fmt.Printf("! could not reach %s from this server (%v)\n", rawURL, err)
		fmt.Println("  The orchestrator URL must be reachable FROM THIS machine, not just your browser.")
		fmt.Println("  Continuing anyway; if the agent never appears in the dashboard, this is why.")
		return
	}
	_ = resp.Body.Close()
	fmt.Printf("✓ reached %s (HTTP %d)\n", rawURL, resp.StatusCode)
}

// unitInstalled reports whether a nurproxy-agent service unit already exists
// (e.g. from the .deb/.rpm), so setup can configure it instead of writing one.
func unitInstalled() bool {
	for _, p := range []string{
		"/usr/lib/systemd/system/nurproxy-agent.service",
		"/lib/systemd/system/nurproxy-agent.service",
		"/etc/systemd/system/nurproxy-agent.service",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
