package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// readJSON decodes the request body into v.
func readJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// pathParam extracts a path parameter from Go 1.22+ request patterns.
func pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}

// clientIP returns the peer's IP for rate-limiting keys. It deliberately uses
// the transport-level RemoteAddr and NOT X-Forwarded-For: a brute-force client
// could spoof XFF to dodge per-IP lockout. Operators terminating TLS at a
// trusted reverse proxy accept that the limiter keys on the proxy's address.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
