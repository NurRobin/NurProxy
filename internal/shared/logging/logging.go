// Package logging configures the process-wide structured logger (slog) for both
// the orchestrator and the agent. It is the single place that decides log level
// and output format, driven by environment variables so the same binary can run
// quiet in production or verbose for debugging without a rebuild.
//
// Crucially, Setup also routes the standard library's log package through the
// slog handler (so log.Default's output is captured). That means the many
// existing log.Printf call sites across the codebase immediately gain slog's
// output format without each one being rewritten — new code should prefer slog
// directly, but legacy log.Printf output is no longer unstructured.
//
// Legacy log.Printf lines carry no slog level, so they are deliberately routed
// through an UNFILTERED handler: raising NP_LOG_LEVEL to warn/error filters
// native slog records but never silences legacy log.Printf output (which is
// overwhelmingly used for warnings and errors). Native slog calls still honor
// NP_LOG_LEVEL exactly.
package logging

import (
	"log"
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
	level := levelFromEnv(os.Getenv("NP_LOG_LEVEL"))
	json := strings.ToLower(strings.TrimSpace(os.Getenv("NP_LOG_FORMAT"))) == "json"

	logger := slog.New(withComponent(newHandler(json, level), component))

	// Install logger for slog's top-level functions. This honors NP_LOG_LEVEL
	// for all native slog calls.
	slog.SetDefault(logger)

	// Bridge the standard log package separately. slog.SetDefault also redirects
	// log.Default's output through the slog handler, but it emits those records
	// at LevelInfo — which means raising NP_LOG_LEVEL to warn/error would
	// silently DROP every legacy log.Printf line (the bulk of which are warnings
	// and errors). To avoid that, route log.Default through an UNFILTERED handler
	// (LevelDebug) so legacy lines always emit regardless of NP_LOG_LEVEL, while
	// native slog above keeps its level filtering.
	bridge := slog.New(withComponent(newHandler(json, slog.LevelDebug), component))
	log.SetOutput(slog.NewLogLogger(bridge.Handler(), slog.LevelInfo).Writer())
	log.SetFlags(0) // slog adds its own timestamp; avoid a duplicate from log.
	log.SetPrefix("")

	return logger
}

// newHandler builds a text or JSON handler writing to stderr at the given level.
func newHandler(json bool, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if json {
		return slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.NewTextHandler(os.Stderr, opts)
}

// withComponent attaches the component attribute to a handler when non-empty.
func withComponent(h slog.Handler, component string) slog.Handler {
	if component == "" {
		return h
	}
	return h.WithAttrs([]slog.Attr{slog.String("component", component)})
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
