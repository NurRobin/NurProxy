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
)

var version = "dev"

var (
	orchestratorURL = flag.String("orchestrator", "", "Orchestrator URL (required)")
	fqdn            = flag.String("fqdn", "", "Agent FQDN (required)")
	dataDir         = flag.String("data-dir", "/var/lib/nurproxy-agent", "Data directory")
	apiPort         = flag.Int("api-port", 8780, "Agent API port")
	caddyAdminPort  = flag.Int("caddy-admin-port", 2019, "Caddy admin API port (localhost)")
	showVersion     = flag.Bool("version", false, "Print version and exit")
)

func main() {
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
		log.Fatalf("Failed to initialize adoption manager: %v", err)
	}

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

	// Step 2: Start Caddy subprocess.
	caddyProc := caddy.NewProcess(cfg.CaddyAdminPort)
	if err := caddyProc.Start(ctx); err != nil {
		log.Fatalf("Failed to start Caddy: %v", err)
	}

	// Create Caddy client (mock if no real Caddy).
	var caddyClient *caddy.Client
	if caddyProc.IsMock() {
		caddyClient = caddy.NewMockClient()
	} else {
		caddyClient = caddy.NewClient(cfg.CaddyAdminPort)
	}

	// Ensure the HTTP server exists in Caddy.
	if err := caddyClient.EnsureServer(ctx); err != nil {
		log.Printf("Warning: failed to ensure Caddy server: %v", err)
	}

	// Step 3: Start Agent API server.
	api.SetVersion(version)
	apiServer := api.New(cfg.APIPort, caddyClient, mgr.Token())
	if err := apiServer.Start(ctx); err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}

	// Step 4: Start heartbeat loop.
	hb := ddns.New(cfg.OrchestratorURL, mgr.AgentID(), mgr.Token(), 60*time.Second)
	hb.Start(ctx)

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
