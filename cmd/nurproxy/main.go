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
	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/web"
)

var version = "dev"

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
		case "version":
			fmt.Printf("nurproxy %s\n", version)
			return
		}
	}

	port := flag.Int("port", 8080, "HTTP port")
	dataDir := flag.String("data-dir", "./data", "Data directory")
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
	rec.Start(rootCtx)
	defer rec.Stop()

	// Central TLS renewal: a background loop re-issues certificates entering the
	// 30-day window, re-encrypts them at rest, and re-pushes the bundle to the
	// serving agent over its stream (the agent reloads). The agent is never probed
	// inbound; certs ride the agent-initiated stream (§7). Started only when an
	// ACME account can be constructed; failures here are non-fatal (the built-in
	// Caddy self-ACME fallback keeps hosts served).
	renewer := startRenewer(rootCtx, database, rec, *dataDir)

	// Create API server, wiring in the hub + reconciler so the stream endpoint
	// works and domain changes push to connected agents immediately.
	srv := api.NewServer(database, version)
	srv.SetAgentHub(hub, rec)
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
func startRenewer(ctx context.Context, database *db.DB, rec *reconciler.Reconciler, dataDir string) *orchtls.Renewer {
	accountKey, err := orchtls.LoadOrGenerateAccountKey(filepath.Join(dataDir, "acme-account.key"))
	if err != nil {
		log.Printf("tls: renewal disabled: %v", err)
		return nil
	}

	email, _ := database.GetSetting("acme_email")
	caDir, _ := database.GetSetting("acme_directory")

	acmeClient, err := orchtls.NewLegoClient(orchtls.LegoConfig{
		Email:      email,
		CADirURL:   caDir,
		AccountKey: accountKey,
	})
	if err != nil {
		log.Printf("tls: renewal disabled: %v", err)
		return nil
	}

	issuer := orchtls.NewIssuer(acmeClient, nil)
	store := reconciler.NewCertRenewalStore(database)
	renewer := orchtls.NewRenewer(store, issuer, orchtls.RenewerConfig{
		Reloader: rec,
		Audit:    &dbAuditSink{db: database},
	})

	go renewer.Start(ctx)
	log.Printf("tls: central renewal + first-issuance loop started (window %s)", orchtls.DefaultRenewWindow)
	return renewer
}

// dbAuditSink writes renewal audit events to the orchestrator audit log with
// the system source, satisfying tls.AuditSink (invariant #5: every config change
// — including cert renewal — is audited with source + actor).
type dbAuditSink struct{ db *db.DB }

func (s *dbAuditSink) Audit(entityType, entityID, action, details string) {
	entry := &models.AuditLogEntry{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      "renewer",
		Source:     models.AuditSourceSystem,
		Details:    details,
	}
	if err := s.db.InsertAuditLog(entry); err != nil {
		log.Printf("tls: failed to insert renewal audit log: %v", err)
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
