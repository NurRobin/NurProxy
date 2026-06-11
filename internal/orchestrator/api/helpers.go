package api

import (
	"encoding/json"
	"errors"
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

// maxJSONBody caps the size of a request body readJSON will decode. Without a
// limit an agent-token holder could OOM the orchestrator with a giant
// heartbeat/ack and write unbounded content into SQLite. A few MiB is far above
// any legitimate control-plane payload.
const maxJSONBody = 4 << 20 // 4 MiB

// readJSON decodes the request body into v, rejecting bodies larger than
// maxJSONBody.
func readJSON(r *http.Request, v interface{}) error {
	return readJSONLimit(r, v, maxJSONBody)
}

// readJSONLimit decodes the request body into v, rejecting bodies larger than
// maxBytes. Callers that legitimately need a larger cap (e.g. an apply-ack with
// many routes) can raise the limit, but a ceiling is always enforced.
func readJSONLimit(r *http.Request, v interface{}, maxBytes int64) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return fmt.Errorf("request body too large (max %d bytes)", maxBytes)
		}
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
