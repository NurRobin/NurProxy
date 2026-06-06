package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"io/fs"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/orchestrator/agentclient"
	"github.com/NurRobin/NurProxy/internal/orchestrator/agenthub"
	"github.com/NurRobin/NurProxy/internal/orchestrator/api"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/orchestrator/mcp"
	"github.com/NurRobin/NurProxy/internal/orchestrator/reconciler"
	orchtls "github.com/NurRobin/NurProxy/internal/orchestrator/tls"
	_ "github.com/NurRobin/NurProxy/internal/provider/cloudflare"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/internal/shared/logging"
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/web"
)

var version = "dev"

func main() {
	// Configure structured logging first so every log line (including the legacy
	// log.Printf calls, which slog.SetDefault bridges) honors NP_LOG_LEVEL /
	// NP_LOG_FORMAT.
	logging.Setup("orchestrator")

	// Subcommands are dispatched before flag parsing so they can own their flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			cmdInstall(os.Args[2:])
			return
		case "uninstall":
			cmdUninstall(os.Args[2:])
			return
		case "version":
			fmt.Printf("nurproxy %s\n", version)
			return
		case "backup":
			cmdBackup(os.Args[2:])
			return
		case "restore":
			cmdRestore(os.Args[2:])
			return
		default:
			// Management CLI subcommands (provider/zone/agent/server/domain/...).
			// If handled, we're done; otherwise fall through to running the server.
			if runCLI(os.Args[1], os.Args[2:]) {
				return
			}
		}
	}

	port := flag.Int("port", 8080, "HTTP port")
	dataDir := flag.String("data-dir", "./data", "Data directory")
	dryRunFlag := flag.Bool("dry-run", false, "Sandbox mode: simulate all DNS and ACME calls (no external requests)")
	flag.Parse()

	// Check env vars
	if envPort := os.Getenv("NP_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
	}
	if envDataDir := os.Getenv("NP_DATA_DIR"); envDataDir != "" {
		*dataDir = envDataDir
	}

	// Dry-run / sandbox mode (#93). NP_DRY_RUN (or -dry-run) turns on both the DNS
	// and ACME sandboxes; the per-subsystem vars override it for partial testing
	// (e.g. mock DNS but real ACME, or vice versa). NP_DRY_RUN_FAIL injects an ACME
	// failure mode (ratelimit|challenge|propagation) so error paths can be exercised.
	dryRunAll := *dryRunFlag || envBool("NP_DRY_RUN")
	dnsDryRun := envBoolDefault("NP_DNS_DRY_RUN", dryRunAll)
	acmeDryRun := envBoolDefault("NP_ACME_DRY_RUN", dryRunAll)
	acmeFailMode := os.Getenv("NP_DRY_RUN_FAIL")
	if dnsDryRun || acmeDryRun {
		log.Printf("DRY-RUN MODE: dns=%v acme=%v fail=%q — no external DNS/ACME calls will be made", dnsDryRun, acmeDryRun, acmeFailMode)
	}

	// Ensure data dir exists
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}

	// Load or generate encryption key
	cryptoKey, err := crypto.LoadOrGenerateKey(filepath.Join(*dataDir, "encryption.key"))
	if err != nil {
		log.Fatalf("failed to load encryption key: %v", err)
	}

	// Open database
	database, err := db.Open(filepath.Join(*dataDir, "nurproxy.db"), cryptoKey)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	// Root context canceled on shutdown signal.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// Live agent connection hub: agents dial out and hold a stream open, and the
	// orchestrator pushes config down it the instant it changes (works behind NAT).
	hub := agenthub.New()

	// Start the reconciliation engine: it syncs desired state (DB) with the
	// actual state on agents (routes) and at DNS providers (records).
	rec := reconciler.New(database, agentclient.New(), reconcilerInterval(database))
	rec.SetHub(hub)
	rec.SetDryRunDNS(dnsDryRun)
	rec.Start(rootCtx)
	defer rec.Stop()

	// Central TLS renewal: a background loop re-issues certificates entering the
	// 30-day window, re-encrypts them at rest, and re-pushes the bundle to the
	// serving agent over its stream (the agent reloads). The agent is never probed
	// inbound; certs ride the agent-initiated stream (§7). Started only when an
	// ACME account can be constructed; failures here are non-fatal (the built-in
	// Caddy self-ACME fallback keeps hosts served).
	renewer := startRenewer(rootCtx, database, rec, *dataDir, dryRunConfig{dns: dnsDryRun, acme: acmeDryRun, failMode: acmeFailMode})

	// Create API server, wiring in the hub + reconciler so the stream endpoint
	// works and domain changes push to connected agents immediately.
	srv := api.NewServer(database, version)
	srv.SetAgentHub(hub, rec)
	// Surface sandbox state so the dashboard can show a "dry-run" banner (#93).
	srv.SetDryRun(dnsDryRun, acmeDryRun)
	// Wire the on-demand cert issuer so creating a central-TLS domain kicks
	// first-issuance immediately (§7). Nil when ACME could not be set up; the
	// periodic renewal scan remains the backstop.
	if renewer != nil {
		srv.SetCertIssuer(renewer)
	}
	// Sweep abandoned on-demand log tails (§15): a dashboard view that vanished
	// without a clean close is reaped and its agent told to stop tailing.
	srv.StartLogReaper(rootCtx)

	// Serve embedded dashboard + API
	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Handler())

	// Opt-in MCP endpoint (off by default; 404s unless mcp_enabled=true). Mounted
	// at the root so it lives outside the dashboard's /api/ surface.
	mcpHandler := mcp.New(database, version)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)

	if web.HasUI {
		// Serve the embedded SPA dashboard.
		distFS, err := fs.Sub(web.Assets, "dist")
		if err != nil {
			_ = database.Close()
			log.Fatalf("failed to load embedded assets: %v", err)
		}
		fileServer := http.FileServer(http.FS(distFS))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Try to serve the file directly
			if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/api/") {
				f, err := distFS.Open(strings.TrimPrefix(r.URL.Path, "/"))
				if err == nil {
					f.Close()
					fileServer.ServeHTTP(w, r)
					return
				}
			}
			// SPA fallback: serve index.html for all non-file routes
			if r.URL.Path == "/" || !strings.Contains(r.URL.Path, ".") {
				r.URL.Path = "/"
				fileServer.ServeHTTP(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	} else {
		// Headless build: no embedded dashboard. The API (/api/v1) and MCP (/mcp)
		// endpoints above are the entire surface.
		log.Printf("headless build: dashboard disabled — API at /api/v1, MCP at /mcp")
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "NurProxy headless build: no dashboard. Use the API at /api/v1.", http.StatusNotFound)
		})
	}

	// Start HTTP server
	httpSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: mux,
	}

	// Graceful shutdown
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("shutting down...")
		rootCancel()
		httpSrv.Shutdown(context.Background())
	}()

	log.Printf("NurProxy %s listening on :%d", version, *port)
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}

// startRenewer constructs the central TLS Renewer and launches its loop in a
// background goroutine. It loads (or generates) the persistent ACME account key
// from the data dir and reads the operator-set acme_email / acme_directory
// settings. Any setup failure is logged and renewal is simply skipped — it must
// never block orchestrator startup, and hosts still serve via stored certs or
// the Caddy self-ACME fallback.
// dryRunConfig carries the sandbox flags resolved from env/CLI into the renewer
// wiring (#93): dns mocks the DNS provider, acme mocks the CA (self-signed
// issuance), and failMode optionally injects an ACME failure path.
type dryRunConfig struct {
	dns      bool
	acme     bool
	failMode string
}

func startRenewer(ctx context.Context, database *db.DB, rec *reconciler.Reconciler, dataDir string, dry dryRunConfig) *orchtls.Renewer {
	accountKey, err := orchtls.LoadOrGenerateAccountKey(filepath.Join(dataDir, "acme-account.key"))
	if err != nil {
		log.Printf("tls: renewal disabled: %v", err)
		return nil
	}

	// In ACME sandbox mode the CA is never contacted: a dry-run client mints a
	// self-signed bundle (and can inject failures) so the full issuance/renewal
	// loop runs with no LE rate-limit risk and no contact email required. Otherwise
	// the real lego-backed client reads the contact email + directory from settings
	// at issuance time, so configuring them post-boot takes effect without a restart.
	var acmeClient orchtls.ACMEClient
	if dry.acme {
		acmeClient = orchtls.NewDryRunACMEClient(nil, dry.failMode)
	} else {
		acmeClient = &settingsACMEClient{db: database, accountKey: accountKey}
	}
	issuer := orchtls.NewIssuer(acmeClient, nil)
	store := reconciler.NewCertRenewalStore(database)
	store.SetDryRunDNS(dry.dns)
	// A sandbox issuance is audited as "dryrun" so its events are never mistaken
	// for real certificate changes.
	auditSource := models.AuditSourceSystem
	if dry.acme {
		auditSource = models.AuditSourceDryRun
	}
	renewer := orchtls.NewRenewer(store, issuer, orchtls.RenewerConfig{
		Reloader: rec,
		Audit:    &dbAuditSink{db: database, source: auditSource},
	})

	go renewer.Start(ctx)
	log.Printf("tls: central renewal + first-issuance loop started (window %s)", orchtls.DefaultRenewWindow)
	return renewer
}

// settingsACMEClient is an orchtls.ACMEClient that resolves the ACME contact
// email + directory URL from settings on each issuance, then delegates to a lego
// client built with the persistent account key. Reading settings lazily means an
// email set after boot (setup wizard or Settings) enables issuance immediately,
// with no restart. An unset email returns orchtls.ErrACMENotConfigured, which the
// renewer treats as a quiet skip.
type settingsACMEClient struct {
	db *db.DB
	// accountKey is the persistent ACME account key (crypto.PrivateKey, which is
	// an alias for any; typed as any here to avoid shadowing the project's crypto
	// package imported in this file).
	accountKey any
}

func (c *settingsACMEClient) ObtainViaDNS01(ctx context.Context, names []string, solver orchtls.DNSSolver) (*orchtls.CertResult, error) {
	email, _ := c.db.GetSetting("acme_email")
	if strings.TrimSpace(email) == "" {
		return nil, orchtls.ErrACMENotConfigured
	}
	caDir, _ := c.db.GetSetting("acme_directory")
	client, err := orchtls.NewLegoClient(orchtls.LegoConfig{
		Email:      email,
		CADirURL:   caDir,
		AccountKey: c.accountKey,
	})
	if err != nil {
		return nil, err
	}
	return client.ObtainViaDNS01(ctx, names, solver)
}

// dbAuditSink writes renewal audit events to the orchestrator audit log,
// satisfying tls.AuditSink (invariant #5: every config change — including cert
// renewal — is audited with source + actor). source is "system" for real
// issuance and "dryrun" in ACME sandbox mode. A zero source falls back to system.
type dbAuditSink struct {
	db     *db.DB
	source models.AuditSource
}

func (s *dbAuditSink) Audit(entityType, entityID, action, details string) {
	source := s.source
	if source == "" {
		source = models.AuditSourceSystem
	}
	entry := &models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      "renewer",
		Source:     source,
		Details:    details,
	}
	if err := s.db.InsertAuditLog(entry); err != nil {
		log.Printf("tls: failed to insert renewal audit log: %v", err)
	}
}

// envBool reports whether an env var is set to a truthy value (1/true/yes/on).
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// envBoolDefault returns the env var's boolean value, or def when it is unset.
// Used for the per-subsystem dry-run overrides, which default to the global flag.
func envBoolDefault(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// reconcilerInterval reads the reconciler_interval setting (in seconds) from the
// database, falling back to 60s when unset or invalid.
func reconcilerInterval(database *db.DB) time.Duration {
	const def = 60 * time.Second
	v, err := database.GetSetting("reconciler_interval")
	if err != nil || v == "" {
		return def
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 5 {
		return def
	}
	return time.Duration(secs) * time.Second
}
