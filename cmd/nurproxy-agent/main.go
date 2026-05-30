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
	_ "github.com/NurRobin/NurProxy/internal/agent/proxy/apache" // registers the apache backend in the proxy registry
	caddybackend "github.com/NurRobin/NurProxy/internal/agent/proxy/caddy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	_ "github.com/NurRobin/NurProxy/internal/agent/proxy/nginx" // registers the nginx backend in the proxy registry
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
		case "apply":
			cmdApply(os.Args[2:])
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

	// Record runtime facts so `nurproxy-agent apply <code>` works zero-arg on this
	// host (§19): the CLI resolves orchestrator/api-port/agent-id from here without
	// re-deriving identity. Non-destructive and non-fatal — a write failure just
	// means the operator passes the flags explicitly.
	if err := agentconfig.SaveRuntimeInfo(cfg.DataDir, agentconfig.RuntimeInfo{
		OrchestratorURL: cfg.OrchestratorURL,
		FQDN:            cfg.FQDN,
		APIPort:         cfg.APIPort,
		AgentID:         mgr.AgentID(),
	}); err != nil {
		log.Printf("WARNING: could not write runtime.json: %v (the apply CLI will need explicit flags)", err)
	}

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
	holder := proxy.NewHolder(caddyBackend, string(cfg.ProxyMode))
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
	reconfigureDeps := proxy.ReconfigureDeps{
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
	}
	apiServer.SetReconfigurer(holder, reconfigureDeps)
	if err := apiServer.Start(ctx); err != nil {
		log.Printf("WARNING: failed to start agent API server: %v", err)
		hs.SetError(fmt.Sprintf("failed to start agent API server: %v", err))
	}

	// Step 3b: honor a persisted Existing mode at startup (§19). agent.yaml may say
	// the agent manages a host-installed nginx/apache (e.g. after a prior hot-switch
	// or a fresh existing-mode install). The bundled Caddy was wrapped above purely
	// as the Holder's seed; here we drive the SAME hot-switch path the live
	// reconfigure uses to swap the Holder onto the existing backend, stop the bundled
	// Caddy so the host proxy owns :80/:443, and run the §12 permission probe. Doing
	// it through Reconfigure (not a standalone probe) means a restart lands in the
	// exact same live state as a §19 apply — the Holder reports mode "existing" on
	// the next beat instead of silently reverting to built-in. Fail-soft: a missing
	// grant is reported via health, never crashes. Built-in mode skips this entirely.
	if cfg.ProxyMode == agentconfig.ProxyModeExisting {
		res := holder.Reconfigure(ctx, proxy.ReconfigureRequest{
			Mode:      "existing",
			Type:      cfg.ProxyType,
			ConfigDir: cfg.ProxyConfigDir,
			Binary:    cfg.ProxyBinary,
			ReloadCmd: cfg.ProxyReloadCmd,
			TestCmd:   cfg.ProxyTestCmd,
			Service:   cfg.ProxyService,
			LogPaths:  cfg.ProxyLogPaths,
		}, reconfigureDeps)
		log.Printf("Existing mode honored at startup: %s", res.Message)
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
	// Report the agent's current live proxy mode each beat (§19) so the dashboard
	// reflects a hot-switch (or this persisted-existing startup) instead of
	// assuming built-in.
	hb.SetModeFn(holder.Mode)
	// Re-run the §12 permission self-test each beat (existing mode only) and report
	// it structured: which grant is missing (config-dir write / service reload) and
	// the targeted remediation. Because it re-probes every beat, granting the right
	// clears the dashboard warning on its own — no restart. osUser names the grant
	// commands. Built-in mode reports nothing (checked=false → nil).
	osUser := currentOSUser()
	hb.SetPermissionsFn(func() *models.ProxyPermissions {
		res, rem, dirs, checked := holder.ProbePermissions(ctx, osUser)
		if checked {
			// Keep health/last_error in sync with the live probe so the stale startup
			// blob clears the moment the operator grants the right — the structured
			// report below is the dashboard's primary surface, this just stops the
			// generic error channel from lagging behind it.
			hs.SetError(res.HealthError())
		}
		return toProxyPermissions(res, rem, dirs, checked)
	})
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

// toProxyPermissions maps the agent-side permcheck result + remediation into the
// shared model the heartbeat carries (§12). checked=false (built-in / admin-API
// backend) yields nil so the dashboard shows no permission block. It keeps the
// proxy package decoupled from shared/models: the conversion lives here, at the
// agent boundary that already speaks both.
func toProxyPermissions(res permcheck.Result, rem *permcheck.Remediation, dirs []string, checked bool) *models.ProxyPermissions {
	if !checked {
		return nil
	}
	pp := &models.ProxyPermissions{
		Checked:     true,
		OK:          res.OK(),
		CanWrite:    res.CanWrite,
		CanReload:   res.CanReload,
		WriteError:  res.WriteError,
		ReloadError: res.ReloadError,
		Dirs:        dirs,
	}
	if rem != nil {
		mr := &models.Remediation{SudoersLine: rem.SudoersLine}
		for _, s := range rem.Steps {
			mr.Steps = append(mr.Steps, models.RemediationStep{Title: s.Title, Commands: s.Commands})
		}
		pp.Remediation = mr
	}
	return pp
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

// detectCapabilities probes the bundled Caddy backend's capability matrix (§8),
// including module probing (e.g. caddy-ratelimit). It builds a probe-only caddy
// backend over a mock client — Capabilities never touches the admin API, only the
// binary's module list — so it works before the Caddy subprocess starts. The
// result rides the agent-initiated register/heartbeat payloads.
func detectCapabilities() *models.ProxyCapabilities {
	b := caddybackend.New(caddy.NewMockClient())
	return b.Capabilities().ToModel()
}
