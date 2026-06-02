// Package logging configures the process-wide structured logger (slog) for both
// the orchestrator and the agent. It is the single place that decides log level
// and output format, driven by environment variables so the same binary can run
// quiet in production or verbose for debugging without a rebuild.
//
// Crucially, Setup also routes the standard library's log package through the
// slog handler (slog.SetDefault bridges log.Default's output). That means the
// many existing log.Printf call sites across the codebase immediately gain level
// filtering and JSON output without each one being rewritten — new code should
// prefer slog directly, but legacy log.Printf output is no longer unstructured.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Setup builds an slog logger from the environment and installs it as the
// default (for both slog and the standard log package). It returns the logger
// for callers that want to log with attributes directly.
//
// Environment:
//   - NP_LOG_LEVEL: debug | info | warn | error   (default: info)
//   - NP_LOG_FORMAT: text | json                  (default: text)
//
// component is added as a stable attribute on every record (e.g. "orchestrator"
// or "agent") so mixed log streams stay attributable.
func Setup(component string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: levelFromEnv(os.Getenv("NP_LOG_LEVEL"))}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NP_LOG_FORMAT"))) {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	logger := slog.New(handler)
	if component != "" {
		logger = logger.With(slog.String("component", component))
	}

	// Installs logger for slog's top-level functions AND bridges the standard
	// log package's output through this handler (at LevelInfo), so existing
	// log.Printf calls are captured by the same level/format configuration.
	slog.SetDefault(logger)
	return logger
}

// levelFromEnv maps an NP_LOG_LEVEL string to an slog.Level, defaulting to Info
// for empty or unrecognized values.
func levelFromEnv(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
