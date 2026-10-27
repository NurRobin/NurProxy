package main

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestNewHTTPServer asserts the orchestrator listener is hardened against
// Slowloris / idle-connection exhaustion: ReadHeaderTimeout, IdleTimeout and
// MaxHeaderBytes must be set, while WriteTimeout stays zero so the long-lived
// agent SSE stream and log-tail responses are never severed by a write deadline.
func TestNewHTTPServer(t *testing.T) {
	const addr = ":8080"
	srv := newHTTPServer(addr, http.NewServeMux())

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"addr", srv.Addr, addr},
		{"read_header_timeout", srv.ReadHeaderTimeout, 15 * time.Second},
		{"idle_timeout", srv.IdleTimeout, 90 * time.Second},
		{"max_header_bytes", srv.MaxHeaderBytes, 1 << 20},
		{"write_timeout_unset", srv.WriteTimeout, time.Duration(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}

	if srv.Handler == nil {
		t.Error("handler must not be nil")
	}
}

// TestFailUnknownCommand asserts a typo'd subcommand exits non-zero with a
// usage hint instead of falling through to booting the server, while a
// flag-looking first argument returns so `nurproxy -port 9000` still starts
// the server. failUnknownCommand calls os.Exit, so the rejecting branch runs
// in a subprocess (same pattern as the cmdRestore tests).
func TestFailUnknownCommand(t *testing.T) {
	if arg := os.Getenv("NP_TEST_UNKNOWN_CMD"); arg != "" {
		failUnknownCommand(arg)
		return // reached only when arg looks like a flag
	}

	run := func(arg string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestFailUnknownCommand$")
		cmd.Env = append(os.Environ(), "NP_TEST_UNKNOWN_CMD="+arg)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stderr.String(), err
	}

	// A typo'd subcommand ("domian" for "domain") must exit 1 and name itself.
	stderr, err := run("domian")
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
		t.Fatalf("typo'd subcommand should exit non-zero, got err=%v", err)
	}
	if !strings.Contains(stderr, `unknown command "domian"`) || !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr missing unknown-command message + usage:\n%s", stderr)
	}

	// A flag must NOT be rejected — the server path owns flag parsing.
	if _, err := run("-port"); err != nil {
		t.Fatalf("flag-looking argument must not be rejected, got err=%v", err)
	}
}
