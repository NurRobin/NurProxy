package logging

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestLevelFromEnv(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{" info ", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"nonsense", slog.LevelInfo},
	}
	for _, tt := range tests {
		if got := levelFromEnv(tt.in); got != tt.want {
			t.Errorf("levelFromEnv(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSetup_returnsLoggerAndSetsDefault(t *testing.T) {
	t.Setenv("NP_LOG_LEVEL", "warn")
	t.Setenv("NP_LOG_FORMAT", "json")

	logger := Setup("test-component")
	if logger == nil {
		t.Fatal("Setup returned nil logger")
	}
	// Setup must install a default usable by slog's top-level functions.
	if slog.Default() == nil {
		t.Fatal("slog.Default() is nil after Setup")
	}
	// Level gating: debug must be below the configured warn threshold.
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug should be disabled when NP_LOG_LEVEL=warn")
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelError) {
		t.Error("error should be enabled when NP_LOG_LEVEL=warn")
	}
}

// The whole point of Setup is that legacy log.Printf calls flow through the slog
// handler (so they get the configured format/level). This verifies the
// slog.SetDefault -> standard-log bridge: a log.Printf lands as a JSON record.
func TestSetup_bridgesStandardLogPackage(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

	log.Printf("listening on :%d", 8080)

	out := buf.String()
	if !strings.Contains(out, `"msg":"listening on :8080"`) {
		t.Errorf("log.Printf did not bridge to JSON slog handler; got: %q", out)
	}
}
