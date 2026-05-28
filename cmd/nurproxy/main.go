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

	"github.com/NurRobin/NurProxy/internal/orchestrator/api"
	"github.com/NurRobin/NurProxy/internal/orchestrator/db"
	"github.com/NurRobin/NurProxy/internal/shared/crypto"
	_ "github.com/NurRobin/NurProxy/internal/provider/cloudflare"
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

	// Create API server
	srv := api.NewServer(database, version)

	// Serve embedded dashboard + API
	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Handler())

	distFS, err := fs.Sub(web.Assets, "dist")
	if err != nil {
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
		httpSrv.Shutdown(context.Background())
	}()

	log.Printf("NurProxy %s listening on :%d", version, *port)
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}
