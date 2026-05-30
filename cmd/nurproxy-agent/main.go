package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/adoption"
	"github.com/NurRobin/NurProxy/internal/agent/api"
	"github.com/NurRobin/NurProxy/internal/agent/caddy"
	agentconfig "github.com/NurRobin/NurProxy/internal/agent/config"
	"github.com/NurRobin/NurProxy/internal/agent/ddns"
	"github.com/NurRobin/NurProxy/internal/agent/health"
	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	apachebackend "github.com/NurRobin/NurProxy/internal/agent/proxy/apache" // also registers the apache backend in the proxy registry
	caddybackend "github.com/NurRobin/NurProxy/internal/agent/proxy/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	nginxbackend "github.com/NurRobin/NurProxy/internal/agent/proxy/nginx" // also registers the nginx backend in the proxy registry
	"github.com/NurRobin/NurProxy/internal/agent/proxy/permcheck"

	"github.com/NurRobin/NurProxy/internal/agent/stream"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
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

	// Proxy backend config (§9). Empty = autodetect / OS default; proxy-mode
	// defaults to built-in (bundled Caddy). These are also settable via env
	// (NP_PROXY_*) and the agent.yaml config file.
	proxyMode      = flag.String("proxy-mode", "", "Proxy mode: built-in (default) | existing")
	proxyType      = flag.String("proxy-type", "", "Existing proxy type: caddy | nginx | apache")
	proxyBinary    = flag.String("proxy-binary", "", "Override detected proxy binary path")
	proxyConfigDir = flag.String("proxy-config-dir", "", "Override detected proxy config directory")
	proxyReloadCmd = flag.String("proxy-reload-cmd", "", "Override proxy reload command")
	proxyTestCmd   = flag.String("proxy-test-cmd", "", "Override proxy config-test command")
	proxyLogPaths  = flag.String("proxy-log-paths", "", "Comma-separated proxy log paths to surface")
	proxyService   = flag.String("proxy-service", "", "Service unit (systemd/openrc/launchd) for reloads")
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
	cfg, err := agentconfig.Load(agentconfig.Flags{
		Orchestrator:   *orchestratorURL,
		FQDN:           *fqdn,
		DataDir:        *dataDir,
		APIPort:        *apiPort,
		CaddyPort:      *caddyAdminPort,
		ProxyMode:      *proxyMode,
		ProxyType:      *proxyType,
		ProxyBinary:    *proxyBinary,
		ProxyConfigDir: *proxyConfigDir,
		ProxyReloadCmd: *proxyReloadCmd,
		ProxyTestCmd:   *proxyTestCmd,
		ProxyLogPaths:  *proxyLogPaths,
		ProxyService:   *proxyService,
	})
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	log.Printf("nurproxy-agent %s starting", version)
	log.Printf("  Orchestrator: %s", cfg.OrchestratorURL)
	log.Printf("  FQDN:         %s", cfg.FQDN)
	log.Printf("  Data dir:     %s", cfg.DataDir)
	log.Printf("  API port:     %d", cfg.APIPort)
	log.Printf("  Caddy admin:  %d", cfg.CaddyAdminPort)
	log.Printf("  Proxy mode:   %s", cfg.ProxyMode)

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

	// Report the backend capability matrix (§8) at registration. For the built-in
	// Caddy this includes module probing (is caddy-ratelimit compiled in?); the
	// probe reads the caddy binary's module list, so it works before the Caddy
	// subprocess is started. Capabilities are refreshed on every heartbeat too.
	capabilities := detectCapabilities()
	if capabilities != nil {
		log.Printf("Proxy capabilities: rate_limit=%t central_tls=%t",
			capabilities.RateLimit, capabilities.CentralTLS)
	}
	mgr.SetCapabilities(capabilities)

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

	// Drive the bundled Caddy through the proxy.Proxy interface: the agent
	// reconciles routes via the admin-API caddy backend (§5) instead of the raw
	// admin client. Behavior is byte-for-byte unchanged — the backend wraps the
	// same client (real or mock) and issues the same admin-API calls.
	caddyBackend := caddybackend.New(caddyClient)

	// Central TLS (§7): attach a cert store so InstallCerts can write
	// orchestrator-issued bundles to disk, encrypting private keys at rest with an
	// agent-local AES-256 key. Certs ride the agent-initiated stream (no inbound,
	// invariant #2) and are installed BEFORE the referencing config is applied
	// (preflight ordering). A failure to provision the at-rest key is non-fatal: the
	// agent stays connected and the built-in Caddy can self-ACME as the fallback.
	certStore := newCertStore(cfg.DataDir)
	if certStore != nil {
		caddyBackend.WithCertStore(certStore)
	}

	// Wrap the bundled caddy backend in the mutable, mutex-guarded Holder (§19).
	// The stream, the local agent API, and the heartbeat all consult the Holder
	// instead of the fixed caddy backend, so the agent can hot-switch built-in ↔
	// existing with no process restart. While nobody calls Reconfigure the Holder
	// forwards every call to this same caddy backend, so the built-in path stays
	// byte-for-byte identical (invariant #1).
	holder := proxy.NewHolder(caddyBackend)
	// Guard the invariant: the bundled caddy backend must satisfy the admin-API
	// primitives the Holder forwards, so wrapping it in the Holder is a transparent
	// pass-through (not a silent no-op). This is a compile-time check via the
	// concrete type; if a future caddy refactor drops one of these methods the build
	// fails here rather than the route path silently going dead.
	var _ interface {
		EnsureServer(context.Context) error
		ClearRoutes(context.Context) error
		RemoveRoute(context.Context, string) error
	} = caddyBackend

	// Ensure the HTTP server exists in Caddy. A bind failure here is the classic
	// "ports 80/443 already in use" case — report it clearly and keep running.
	if err := caddyBackend.EnsureServer(ctx); err != nil {
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
	apiServer := api.New(cfg.APIPort, holder, mgr.Token())
	apiServer.SetHealth(hs)

	// Wire the hot-switch endpoint (§19): POST /admin/reconfigure drives the Holder.
	// The deps let the Holder act without importing concrete agent packages — a
	// health setter, a closure to stop the bundled Caddy subprocess when leaving
	// built-in, the agent's OS user for the least-privilege remediation, and a
	// factory to rebuild the bundled caddy backend on a switch back to built-in.
	apiServer.SetReconfigurer(holder, proxy.ReconfigureDeps{
		Health:    hs,
		StopCaddy: caddyProc.Stop,
		OSUser:    currentOSUser(),
		CaddyFactory: func() proxy.Proxy {
			b := caddybackend.New(caddy.NewClient(cfg.CaddyAdminPort))
			if certStore != nil {
				b.WithCertStore(certStore)
			}
			return b
		},
	})
	if err := apiServer.Start(ctx); err != nil {
		log.Printf("WARNING: failed to start agent API server: %v", err)
		hs.SetError(fmt.Sprintf("failed to start agent API server: %v", err))
	}

	// Step 3b: Existing-mode permission probe (§12). A file-based backend needs to
	// WRITE config (group/ownership) and RELOAD the service (scoped sudoers) — two
	// privileges the built-in Caddy admin-API path never needed. Probe both at
	// startup and, on a denial, report a clear, actionable health error WITHOUT
	// crashing — exactly like the bind-failure handling above. The agent stays
	// connected so the operator can fix the grant from the dashboard. Built-in mode
	// skips this entirely (no file writes / reloads in the zero-config case).
	if cfg.ProxyMode == agentconfig.ProxyModeExisting {
		probeExistingPermissions(ctx, cfg, hs)
	}

	// Step 4: Create the push stream client. The agent dials out and holds it
	// open; the orchestrator pushes the desired route set down it the instant it
	// changes — no inbound reachability required. The client also tracks the
	// artifacts it has applied so the heartbeat can report their checksums for
	// drift detection (§11).
	streamClient := stream.New(cfg.OrchestratorURL, mgr.AgentID(), mgr.Token(), holder, hs).
		WithLogPaths(cfg.ProxyLogPaths)

	// Step 5: Start heartbeat loop. It carries the health snapshot so the
	// dashboard always sees the agent and any problems it's reporting.
	hb := ddns.New(cfg.OrchestratorURL, mgr.AgentID(), mgr.Token(), version, heartbeatInterval, hs.Snapshot)
	// Re-report detection on every beat so the orchestrator's stored copy tracks
	// host changes (e.g. a previously-conflicting proxy releasing :443).
	hb.SetDetectionFn(func() *models.ProxyDetection { return detectProxy(ctx) })
	// Re-report the capability matrix on each beat so module changes (e.g.
	// caddy-ratelimit installed later) propagate. The probe reuses the same caddy
	// backend the agent reconciles through, so the report matches what Render emits.
	hb.SetCapabilitiesFn(func() *models.ProxyCapabilities { return holder.Current().Capabilities().ToModel() })
	// Report each managed artifact's checksum so the orchestrator detects drift
	// (on-disk/live != accepted state, §11) without ever probing the agent inbound.
	hb.SetArtifactChecksumsFn(streamClient.ManagedChecksums)
	hb.Start(ctx)

	// Open the stream. Runs until shutdown, reconnecting as needed.
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

// currentOSUser returns the OS user the agent runs as, for the §19 hot-switch
// remediation (the user added to the config-dir's owning group and named in the
// scoped sudoers line). A lookup failure yields "" — BuildRemediation tolerates an
// empty user (it omits the user-specific commands) so this never fails the switch.
func currentOSUser() string {
	u, err := user.Current()
	if err != nil {
		log.Printf("WARNING: could not resolve current OS user for reconfigure remediation: %v", err)
		return ""
	}
	return u.Username
}

// newCertStore builds the agent's cert store under <dataDir>/certs, loading or
// generating an agent-local AES-256 key (<dataDir>/cert.key) to encrypt cert
// private keys at rest (§7). A failure to provision the at-rest key is non-fatal:
// it logs and returns a store with no key (plaintext PEM) so central TLS still
// works while the operator fixes permissions, rather than crashing the agent
// (mirrors the never-die-on-host-problems posture). Returns nil only if dataDir is
// empty.
func newCertStore(dataDir string) *certstore.Store {
	if dataDir == "" {
		return nil
	}
	certDir := filepath.Join(dataDir, "certs")
	key, err := crypto.LoadOrGenerateKey(filepath.Join(dataDir, "cert.key"))
	if err != nil {
		log.Printf("WARNING: could not provision at-rest cert key: %v (cert keys will be stored unencrypted)", err)
		return certstore.New(certDir, nil)
	}
	return certstore.New(certDir, key)
}

// fileBackend is the subset of a file-based proxy backend (nginx/apache) the
// permission probe needs (§12): the dirs that must be writable, the
// validate-command runner, and the reload command the operator must allow via
// scoped sudoers. Both nginx.Backend and apache.Backend satisfy it. Defining the
// interface here keeps the backends from depending on the probe package.
type fileBackend interface {
	ProbeDirs() []string
	ReloadHint() string
}

// probeExistingPermissions builds the configured Existing-mode backend and runs
// the startup permission probe (§12), reporting a clear, actionable health error
// on a denial. It never crashes: a backend that cannot be built, or that does not
// expose probe hooks, is logged and skipped rather than fatal — the agent stays
// connected and explains why, mirroring the bind-failure posture. A passing probe
// clears any prior probe error.
func probeExistingPermissions(ctx context.Context, cfg *agentconfig.Config, hs *health.State) {
	if cfg.ProxyType == "" {
		log.Printf("WARNING: proxy-mode=existing but proxy-type is unset — cannot probe permissions")
		hs.SetError("Existing proxy mode selected but no proxy_type set (nginx/apache/caddy) — set proxy_type so the agent can manage and reload it.")
		return
	}
	be, err := proxy.Get(cfg.ProxyType, proxy.Config{
		Type:      cfg.ProxyType,
		Binary:    cfg.ProxyBinary,
		ConfigDir: cfg.ProxyConfigDir,
		ReloadCmd: cfg.ProxyReloadCmd,
		TestCmd:   cfg.ProxyTestCmd,
		Service:   cfg.ProxyService,
		LogPaths:  cfg.ProxyLogPaths,
	})
	if err != nil {
		log.Printf("WARNING: could not build %q backend for permission probe: %v", cfg.ProxyType, err)
		hs.SetError(fmt.Sprintf("Existing proxy %q is not a known backend — cannot manage or reload it.", cfg.ProxyType))
		return
	}
	fb, ok := be.(fileBackend)
	if !ok {
		// An admin-API backend (e.g. external caddy) needs no file/reload probe.
		log.Printf("Permission probe skipped: %q backend needs no file-write/reload privilege", cfg.ProxyType)
		return
	}
	// The backend's validate-command runner satisfies permcheck.TestRunner (it has
	// Test(ctx)). Resolve it per concrete backend so the backends stay decoupled
	// from the probe package.
	var runner permcheck.TestRunner
	switch b := be.(type) {
	case *nginxbackend.Backend:
		runner = b.Runner()
	case *apachebackend.Backend:
		runner = b.Runner()
	}
	res := permcheck.Probe(ctx, permcheck.Options{
		Backend:    cfg.ProxyType,
		Dirs:       fb.ProbeDirs(),
		Runner:     runner,
		ReloadHint: fb.ReloadHint(),
	})
	if res.OK() {
		log.Printf("Permission probe OK: %q config is writable and reloadable", cfg.ProxyType)
		hs.SetError("")
		return
	}
	msg := res.HealthError()
	log.Printf("WARNING: permission probe failed: %s", msg)
	hs.SetError(msg)
}

// detectCapabilities probes the bundled Caddy backend's capability matrix (§8),
// including module probing (e.g. caddy-ratelimit). It builds a probe-only caddy
// backend over a mock client — Capabilities never touches the admin API, only the
// binary's module list — so it works before the Caddy subprocess starts. The
// result rides the agent-initiated register/heartbeat payloads.
func detectCapabilities() *models.ProxyCapabilities {
	b := caddybackend.New(caddy.NewMockClient())
	return b.Capabilities().ToModel()
}
