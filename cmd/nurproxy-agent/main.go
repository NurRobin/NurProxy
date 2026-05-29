package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/adoption"
	"github.com/NurRobin/NurProxy/internal/agent/api"
	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	agentconfig "github.com/NurRobin/NurProxy/internal/agent/config"
	"github.com/NurRobin/NurProxy/internal/agent/ddns"
	"github.com/NurRobin/NurProxy/internal/agent/health"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/stream"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

var version = "dev"

// heartbeatInterval is how often the agent dials home. It is kept comfortably
// below the orchestrator's agent_offline_timeout (default 90s) so a single
// missed beat never flaps the agent offline.
const heartbeatInterval = 30 * time.Second

var (
	orchestratorURL = flag.String("orchestrator", "", "Orchestrator URL (required)")
	fqdn            = flag.String("fqdn", "", "Agent FQDN (required)")
	dataDir         = flag.String("data-dir", "/var/lib/nurproxy-agent", "Data directory")
	apiPort         = flag.Int("api-port", 8780, "Agent API port")
	caddyAdminPort  = flag.Int("caddy-admin-port", 2019, "Caddy admin API port (localhost)")
	showVersion     = flag.Bool("version", false, "Print version and exit")
)

func main() {
	// Subcommands are dispatched before flag parsing so they can own their flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			cmdInstall(os.Args[2:])
			return
		case "uninstall":
			cmdUninstall(os.Args[2:])
			return
		}
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("nurproxy-agent %s\n", version)
		os.Exit(0)
	}

	// Load config with priority: flags > env > config file > defaults.
	cfg, err := agentconfig.Load(*orchestratorURL, *fqdn, *dataDir, *apiPort, *caddyAdminPort)
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	log.Printf("nurproxy-agent %s starting", version)
	log.Printf("  Orchestrator: %s", cfg.OrchestratorURL)
	log.Printf("  FQDN:         %s", cfg.FQDN)
	log.Printf("  Data dir:     %s", cfg.DataDir)
	log.Printf("  API port:     %d", cfg.APIPort)
	log.Printf("  Caddy admin:  %d", cfg.CaddyAdminPort)

	// Set up context with graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Step 1: Adoption flow.
	mgr, err := adoption.New(cfg.OrchestratorURL, cfg.FQDN, cfg.DataDir, cfg.APIPort)
	if err != nil {
		cancel()
		log.Fatalf("Failed to initialize adoption manager: %v", err)
	}

	mgr.SetVersion(version)

	// Phase 0 (§13.0, §2.1, §9): read-only proxy detection. This manages nothing,
	// writes no files, and does not touch the running Caddy path; it only reports
	// which proxy is installed (+ version/paths) and which process holds :80/:443.
	// The result rides the agent-initiated adoption + heartbeat payloads (the
	// agent always dials out; the orchestrator never probes it inbound).
	detection := detectProxy(ctx)
	if detection != nil {
		log.Printf("Proxy detection: installed=%t kind=%q version=%q config_dir=%q",
			detection.Installed, detection.Kind, detection.Version, detection.ConfigDir)
		for _, c := range detection.PortConflicts {
			log.Printf("Proxy detection: :%d held by %q (pid %d)", c.Port, c.Process, c.PID)
		}
	}
	mgr.SetDetection(detection)

	log.Printf("Agent ID: %s", mgr.AgentID())
	log.Printf("Agent Token: %s...%s", mgr.Token()[:10], mgr.Token()[len(mgr.Token())-4:])

	if err := mgr.Register(ctx); err != nil {
		log.Printf("Registration failed (orchestrator may be unavailable): %v", err)
		log.Printf("Continuing anyway — will retry via heartbeat")
	}

	if err := mgr.WaitForAdoption(ctx); err != nil {
		if ctx.Err() != nil {
			log.Printf("Shutdown requested during adoption wait")
			os.Exit(0)
		}
		log.Fatalf("Adoption failed: %v", err)
	}

	// Shared health state: the agent reports problems to the dashboard instead of
	// dying on them. A failure to run the local proxy (e.g. ports 80/443 already
	// taken by nginx) must NOT stop the agent from connecting and explaining why.
	hs := health.New()

	// Step 2: Start Caddy subprocess. Failures here are reported, not fatal.
	caddyProc := caddy.NewProcess(cfg.CaddyAdminPort)
	if err := caddyProc.Start(ctx); err != nil {
		log.Printf("WARNING: failed to start Caddy: %v (continuing — agent stays connected)", err)
		hs.SetCaddyRunning(false)
		hs.SetError(fmt.Sprintf("failed to start Caddy: %v", err))
	}

	// Create Caddy client. Fall back to the in-memory mock whenever there is no
	// live Caddy process to talk to (binary missing, or Start failed above).
	var caddyClient *caddy.Client
	if caddyProc.IsMock() || !caddyProc.Running() {
		caddyClient = caddy.NewMockClient()
		if caddyProc.IsMock() {
			hs.SetCaddyRunning(false)
			hs.SetError("Caddy binary not found — no local reverse proxy (install caddy on this host)")
		}
	} else {
		caddyClient = caddy.NewClient(cfg.CaddyAdminPort)
	}

	// Ensure the HTTP server exists in Caddy. A bind failure here is the classic
	// "ports 80/443 already in use" case — report it clearly and keep running.
	if err := caddyClient.EnsureServer(ctx); err != nil {
		log.Printf("WARNING: Caddy could not start its HTTP server: %v", err)
		hs.SetCaddyRunning(false)
		hs.SetError(fmt.Sprintf("Caddy could not bind :80/:443 — are the ports already in use (nginx/apache)? %v", err))
	} else if !caddyProc.IsMock() && caddyProc.Running() {
		// Real Caddy is serving — healthy.
		hs.SetCaddyRunning(true)
		hs.SetError("")
	}

	// Step 3: Start Agent API server (non-fatal: a bind failure is reported via
	// health and the agent keeps heartbeating).
	api.SetVersion(version)
	apiServer := api.New(cfg.APIPort, caddyClient, mgr.Token())
	apiServer.SetHealth(hs)
	if err := apiServer.Start(ctx); err != nil {
		log.Printf("WARNING: failed to start agent API server: %v", err)
		hs.SetError(fmt.Sprintf("failed to start agent API server: %v", err))
	}

	// Step 4: Start heartbeat loop. It carries the health snapshot so the
	// dashboard always sees the agent and any problems it's reporting.
	hb := ddns.New(cfg.OrchestratorURL, mgr.AgentID(), mgr.Token(), version, heartbeatInterval, hs.Snapshot)
	// Re-report detection on every beat so the orchestrator's stored copy tracks
	// host changes (e.g. a previously-conflicting proxy releasing :443).
	hb.SetDetectionFn(func() *models.ProxyDetection { return detectProxy(ctx) })
	hb.Start(ctx)

	// Step 5: Open the push stream. The agent dials out and holds it open; the
	// orchestrator pushes the desired route set down it the instant it changes —
	// no inbound reachability required. Runs until shutdown, reconnecting as needed.
	streamClient := stream.New(cfg.OrchestratorURL, mgr.AgentID(), mgr.Token(), caddyClient, hs)
	go streamClient.Run(ctx)

	log.Printf("Agent is running. Press Ctrl+C to stop.")

	// Wait for shutdown signal.
	<-sigCh
	log.Printf("Shutting down...")
	cancel()

	// Graceful shutdown with timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	hb.Stop()

	if err := apiServer.Stop(shutdownCtx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}

	if err := caddyProc.Stop(); err != nil {
		log.Printf("Caddy shutdown error: %v", err)
	}

	log.Printf("Agent stopped.")
}

// detectProxy runs read-only proxy detection and converts it to the shared wire
// model. It never mutates host state; a detection error is logged and reported
// as nil (the orchestrator keeps any prior value), never fatal.
func detectProxy(ctx context.Context) *models.ProxyDetection {
	det, err := proxy.NewDetector().Detect(ctx)
	if err != nil {
		log.Printf("Proxy detection failed: %v", err)
		return nil
	}
	return det.ToModel()
}
