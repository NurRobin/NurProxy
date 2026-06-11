package logging

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"os"
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

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what was
// written. Setup installs handlers that write to os.Stderr, so this exercises
// the real wiring rather than a hand-built handler.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}
	return out
}

// Regression: with NP_LOG_LEVEL raised, native slog records below the threshold
// are filtered, but legacy log.Printf lines must still emit. Previously the
// std-log bridge inherited the slog level and silently dropped every legacy
// warning/error line when NP_LOG_LEVEL was warn/error.
func TestSetup_legacyLogNotSilencedByLevel(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	t.Cleanup(func() {
		// Restore standard log defaults touched by Setup.
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
		log.SetPrefix("")
	})

	tests := []struct {
		name            string
		level           string
		wantLegacy      bool // legacy log.Printf line present
		wantNativeInfo  bool // native slog.Info present
		wantNativeError bool // native slog.Error present
	}{
		{name: "error level keeps legacy, drops native info", level: "error", wantLegacy: true, wantNativeInfo: false, wantNativeError: true},
		{name: "warn level keeps legacy, drops native info", level: "warn", wantLegacy: true, wantNativeInfo: false, wantNativeError: true},
		{name: "info level keeps everything", level: "info", wantLegacy: true, wantNativeInfo: true, wantNativeError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NP_LOG_LEVEL", tt.level)
			t.Setenv("NP_LOG_FORMAT", "json")

			out := captureStderr(t, func() {
				Setup("test-component")
				log.Printf("legacy-line %d", 42)
				slog.Info("native-info-line")
				slog.Error("native-error-line")
			})

			gotLegacy := strings.Contains(out, "legacy-line 42")
			if gotLegacy != tt.wantLegacy {
				t.Errorf("legacy log.Printf present = %v, want %v; out=%q", gotLegacy, tt.wantLegacy, out)
			}
			gotInfo := strings.Contains(out, "native-info-line")
			if gotInfo != tt.wantNativeInfo {
				t.Errorf("native slog.Info present = %v, want %v; out=%q", gotInfo, tt.wantNativeInfo, out)
			}
			gotError := strings.Contains(out, "native-error-line")
			if gotError != tt.wantNativeError {
				t.Errorf("native slog.Error present = %v, want %v; out=%q", gotError, tt.wantNativeError, out)
			}

			// Legacy lines must carry the component attr (bridge preserves it).
			if tt.wantLegacy && !strings.Contains(out, `"component":"test-component"`) {
				t.Errorf("legacy line missing component attribute; out=%q", out)
			}
		})
	}
}
