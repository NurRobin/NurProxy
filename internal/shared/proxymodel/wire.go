package proxymodel

// This file defines the agent↔orchestrator wire format for config sync (§3, B1).
//
// The flip (Phase 3): the orchestrator no longer pushes pre-rendered Caddy JSON.
// It pushes *intent* — a set of RouteIntent, each a backend-neutral Route plus a
// stable artifact identity. The agent renders the intent natively (only it knows
// the host's proxy binary/version/layout), applies it, and reports back the
// rendered content + checksum in one atomic apply-ACK (ArtifactReport). The
// orchestrator round-trips that rendered artifact into its central versioned
// store, so the store is authoritative without the orchestrator modeling every
// host.
//
// Bandwidth is a non-issue: configs are KB-sized — full content rides the ACK on
// change, checksums ride the heartbeat.

// RouteIntent is one unit of desired state pushed to an agent: a stable artifact
// identity plus the backend-neutral Route the agent must render natively. The
// orchestrator assigns ArtifactID (stable per domain) so the agent can echo it
// back in its ArtifactReport, letting the orchestrator round-trip the rendered
// content into the correct store row without re-deriving identity from content.
type RouteIntent struct {
	// ArtifactID is the orchestrator-assigned stable identity of the config
	// artifact this intent renders into. The agent echoes it in its report.
	ArtifactID string `json:"artifact_id"`
	// Backend names the proxy backend that must render this intent ("caddy" |
	// "nginx" | "apache"). The agent selects the matching renderer.
	Backend string `json:"backend"`
	// Route is the backend-neutral intent the agent renders natively.
	Route Route `json:"route"`
}

// IntentSet is the full desired set of route intents pushed to an agent in one
// "routes" event — a sync snapshot (the agent reconciles its whole managed set
// against it, exactly like the prior route snapshot).
type IntentSet struct {
	// Intents is the complete desired set; an empty slice means "manage nothing".
	Intents []RouteIntent `json:"intents"`
}

// ArtifactReport is the agent's atomic apply-ACK for one artifact: the rendered
// native content + its checksum, plus whether the apply succeeded. The
// orchestrator round-trips Content into the versioned store as the live artifact
// (B1, §3); a non-empty Error attributes a per-artifact apply failure without
// failing the whole batch.
type ArtifactReport struct {
	// ArtifactID echoes the RouteIntent.ArtifactID this report answers.
	ArtifactID string `json:"artifact_id"`
	// Host is the FQDN the artifact serves, used to converge domain status.
	Host string `json:"host"`
	// Backend names the renderer that produced Content.
	Backend string `json:"backend"`
	// TargetKind locates the artifact ("file" | "caddy-route").
	TargetKind string `json:"target_kind"`
	// TargetPath is the file path or virtual route handle.
	TargetPath string `json:"target_path"`
	// Content is the rendered native config (Caddy route JSON for built-in).
	// Carried in the ACK so the orchestrator stores it as the versioned artifact.
	Content string `json:"content"`
	// Checksum is the SHA-256 (hex) of Content, computed by the agent.
	Checksum string `json:"checksum"`
	// Enabled reports whether the artifact is active on the host.
	Enabled bool `json:"enabled"`
	// Error is the per-artifact apply error, empty on success.
	Error string `json:"error,omitempty"`
}

// ApplyAck is the body the agent POSTs after applying a pushed IntentSet. It
// carries one ArtifactReport per intent it attempted, so the orchestrator can
// round-trip every rendered artifact into the store and converge domain status
// in a single message (atomic apply-report, §3/B1).
type ApplyAck struct {
	// Reports is one entry per attempted artifact (success or per-item error).
	Reports []ArtifactReport `json:"reports"`
}

// ArtifactChecksum is the agent's per-heartbeat report of one managed artifact's
// on-disk (or live admin-API) state (§11). The agent computes the checksum of
// the artifact it currently has applied; the orchestrator compares it against
// the accepted checksum in the store and marks the artifact drifted when they
// diverge. Bandwidth is a non-issue: only the artifact identity + checksum ride
// the heartbeat, never the full content (that rides the apply-ACK on change).
type ArtifactChecksum struct {
	// ArtifactID is the stable identity the agent echoes from the RouteIntent it
	// applied (e.g. "dom-7"), matching a row in the central store.
	ArtifactID string `json:"artifact_id"`
	// Checksum is the SHA-256 (hex) of the artifact's current on-disk/live content,
	// computed by the agent the same way the orchestrator computes it.
	Checksum string `json:"checksum"`
}
