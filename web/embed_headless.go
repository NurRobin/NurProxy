//go:build headless

// Package web in the headless build embeds no dashboard assets, trimming the
// embedded payload (~540 kB) and dropping the UI attack surface. The
// orchestrator is then driven purely via the API/CLI (configured by .env/flags).
package web

import "embed"

// Assets is an empty FS in headless builds (no //go:embed directive).
var Assets embed.FS

// HasUI is false in the headless build.
const HasUI = false
