//go:build !headless

package web

import "embed"

//go:embed all:dist
var Assets embed.FS

// HasUI reports whether this build embeds the dashboard. True in the default
// build; false in the headless build (see embed_headless.go).
const HasUI = true
