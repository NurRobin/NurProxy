//go:build sandbox

// Command fakeupstream is the backend the live sandbox proxies to: a tiny HTTP
// server that answers every request with a fixed marker plus what it received,
// so a client on the far side of the real Caddy can tell the request went all
// the way through.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Marker starts every response body; tests and the live sandbox script grep
// for it.
const Marker = "nurproxy-sandbox-upstream"

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "address to listen on")
	name := flag.String("name", "app", "name echoed in every response")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Sandbox-Upstream", *name)
		_, _ = fmt.Fprintf(w, "%s name=%s host=%s path=%s forwarded_proto=%s\n",
			Marker, *name, r.Host, r.URL.RequestURI(), r.Header.Get("X-Forwarded-Proto"))
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("fake upstream %q listening on %s", *name, *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
