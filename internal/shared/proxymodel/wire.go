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
//
// Certs ride the same push so the agent has everything it needs to go live in one
// message ("everything is ready, go live", §5 preflight). The orchestrator gathers
// or issues the certificates first, then pushes them alongside the intent set; the
// agent installs the certs (InstallCerts) BEFORE applying any referencing config
// (Apply), so a generated config that points at cert files never fails validation
// for a missing file. Certs ride the existing agent-initiated stream — there is no
// inbound probe of the agent (invariant #2).
type IntentSet struct {
	// Intents is the complete desired set; an empty slice means "manage nothing".
	Intents []RouteIntent `json:"intents"`
	// Certs are the certificate bundles the agent must install before Apply
	// (preflight ordering, §5/§7). Empty when the orchestrator has no cert material
	// for this agent (e.g. self-ACME fallback or no TLS).
	Certs []CertBundle `json:"certs,omitempty"`
}

// CertBundle is one leaf certificate plus its private key destined for an agent's
// cert store (§7). It is the wire form of the agent-side proxy.CertBundle: the
// orchestrator issues/gathers it centrally (DNS-01 via lego) and pushes it down
// the agent-initiated stream, where the agent writes it to disk (encrypting the
// key at rest) before applying the config that references it. The key is sensitive
// and only ever travels over the stream's TLS transport.
type CertBundle struct {
	// Host is the FQDN the certificate covers, e.g. "app.example.com". The agent
	// derives the on-disk file names from it.
	Host string `json:"host"`
	// CertPEM is the leaf certificate plus issuer chain in PEM form (public).
	CertPEM string `json:"cert_pem"`
	// KeyPEM is the private key in PEM form (sensitive; encrypted at rest by the
	// agent after install).
	KeyPEM string `json:"key_pem"`
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
	// Warnings lists proxy options the backend dropped because it cannot express
	// them (invariant #4). Each is "<option>: <reason>". The orchestrator audits
	// each entry so the operator sees, in the central audit log, exactly what was
	// silently dropped — the "audited" half of invariant #4 (the agent already
	// logged them locally).
	Warnings []string `json:"warnings,omitempty"`
}

// ApplyAck is the body the agent POSTs after applying a pushed IntentSet. It
// carries one ArtifactReport per intent it attempted, so the orchestrator can
// round-trip every rendered artifact into the store and converge domain status
// in a single message (atomic apply-report, §3/B1).
type ApplyAck struct {
	// Reports is one entry per attempted artifact (success or per-item error).
	Reports []ArtifactReport `json:"reports"`
}

// LogTailRequest starts an on-demand log tail on the agent (§15). The
// orchestrator pushes it down the agent-initiated stream when an operator opens
// the log view in the dashboard; the agent tails the requested file and POSTs
// LogChunks back up the same control plane (the orchestrator never reads the
// agent inbound — invariant #2). The tail stops on a matching LogTailStop or when
// the agent's stream drops. This is deliberately on-demand: there is never a
// continuous log firehose.
type LogTailRequest struct {
	// SessionID is the orchestrator-assigned tail identity. The agent echoes it on
	// every LogChunk and matches it against a LogTailStop. One open dashboard view
	// owns one session.
	SessionID string `json:"session_id"`
	// Path is the log file to tail. The agent validates it against the proxy's
	// configured log paths (proxy_log_paths, §9): a path outside that allowlist is
	// refused with an error chunk, so a compromised orchestrator cannot read
	// arbitrary files off the agent.
	Path string `json:"path"`
	// Lines is how many trailing lines to send as the initial backlog before
	// following new writes. Zero means a backend default.
	Lines int `json:"lines,omitempty"`
}

// LogTailStop ends an on-demand tail session started by a LogTailRequest (§15).
// The orchestrator pushes it when the operator closes the log view; the agent
// stops the matching tailer and frees the open file. Stopping an unknown session
// is a no-op.
type LogTailStop struct {
	// SessionID identifies the tail to stop (matches a prior LogTailRequest).
	SessionID string `json:"session_id"`
}

// LogChunk is one batch of tailed log lines the agent POSTs back to the
// orchestrator over the agent-initiated control plane (§15). The orchestrator
// buffers chunks per session and serves them to the open dashboard view. A chunk
// carries either log lines, a terminal Error (e.g. path not allowed, file gone),
// or EOF when the tail has stopped.
type LogChunk struct {
	// SessionID ties the chunk to its tail session (echoes LogTailRequest).
	SessionID string `json:"session_id"`
	// Path is the file the lines came from, echoed for the UI.
	Path string `json:"path"`
	// Lines are the freshly read log lines (newline already stripped per line).
	Lines []string `json:"lines,omitempty"`
	// Error is a terminal tail error (path refused, open failed). When set the
	// session is finished and the agent has stopped the tailer.
	Error string `json:"error,omitempty"`
	// EOF reports that the tail session has ended (stop requested or stream gone).
	EOF bool `json:"eof,omitempty"`
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
