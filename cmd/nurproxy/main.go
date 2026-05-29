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
	_ "github.com/NurRobin/NurProxy/internal/provider/cloudflare"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	"github.com/NurRobin/NurProxy/web"
)

var version = "dev"

func main() {
	port := flag.Int("port", 8080, "HTTP port")
	dataDir := flag.String("data-dir", "./data", "Data directory")
	flag.Parse()

	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("nurproxy %s\n", version)
		return
	}

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

	// Create API server, wiring in the hub + reconciler so the stream endpoint
	// works and domain changes push to connected agents immediately.
	srv := api.NewServer(database, version)
	srv.SetAgentHub(hub, rec)

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
