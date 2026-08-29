package certmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/NurRobin/NurProxy/internal/shared/dnsname"
)

const (
	CurrentContractVersion    = 1
	MaxExportsPerSnapshot     = 128
	MaxDestinationsPerExport  = 4
	MaxCertificateBundles     = 128
	MaxPEMBytes               = 1 << 20
	MaxArgvEntries            = 32
	MaxArgBytes               = 1024
	MaxArgvBytes              = 8 << 10
	MaxSnapshotChunks         = 64
	MaxChunkBytes             = 3 << 20
	MaxAssembledSnapshotBytes = 8 << 20
	MaxActionTimeoutSeconds   = 300
	MaxPlanLifetime           = 5 * time.Minute
)

const (
	maxIDBytes       = 128
	maxNameBytes     = 200
	maxIdentityBytes = 128
	maxErrorCode     = 96
	maxRiskBytes     = 512
	maxRisks         = 16
)

type ExportMode string

const (
	ExportModeSymlink ExportMode = "symlink"
	ExportModeCopy    ExportMode = "copy"
)

type DestinationKind string

const (
	DestinationCert       DestinationKind = "cert"
	DestinationChain      DestinationKind = "chain"
	DestinationFullChain  DestinationKind = "fullchain"
	DestinationPrivateKey DestinationKind = "private_key"
)

type ActionKind string

const (
	ActionNone    ActionKind = "none"
	ActionSystemd ActionKind = "systemd"
	ActionCommand ActionKind = "command"
)

type Health string

const (
	HealthPending  Health = "pending"
	HealthHealthy  Health = "healthy"
	HealthDegraded Health = "degraded"
	HealthFailed   Health = "failed"
	HealthDisabled Health = "disabled"
)

type DeploymentPhase string

const (
	DeploymentPlanned     DeploymentPhase = "planned"
	DeploymentValidating  DeploymentPhase = "validating"
	DeploymentApplying    DeploymentPhase = "applying"
	DeploymentSucceeded   DeploymentPhase = "succeeded"
	DeploymentRollingBack DeploymentPhase = "rolling_back"
	DeploymentRolledBack  DeploymentPhase = "rolled_back"
	DeploymentFailed      DeploymentPhase = "failed"
)

type RollbackResult string

const (
	RollbackNotNeeded RollbackResult = "not_needed"
	RollbackPending   RollbackResult = "pending"
	RollbackSucceeded RollbackResult = "succeeded"
	RollbackFailed    RollbackResult = "failed"
)

type CleanupOutcome string

const (
	CleanupRemoved        CleanupOutcome = "removed"
	CleanupPreserved      CleanupOutcome = "operator_replacement_preserved"
	CleanupFailed         CleanupOutcome = "failed"
	CleanupOutcomePending CleanupOutcome = "pending"
)

type CleanupPhase string

const (
	CleanupPending     CleanupPhase = "pending"
	CleanupApplying    CleanupPhase = "applying"
	CleanupCompleted   CleanupPhase = "completed"
	CleanupPhaseFailed CleanupPhase = "failed"
)

type Capability string

const (
	CapabilityCertificateExports Capability = "certificate_exports_v1"
	CapabilityChunkedInventory   Capability = "chunked_export_inventory_v1"
	CapabilitySymlinkMode        Capability = "symlink_export_v1"
	CapabilityCopyMode           Capability = "copy_export_v1"
	CapabilitySystemdAction      Capability = "systemd_action_v1"
	CapabilityCommandAction      Capability = "command_action_v1"
)

type Destination struct {
	Kind DestinationKind `json:"kind"`
	Path string          `json:"path"`
}

type PermissionPolicy struct {
	Owner          string `json:"owner"`
	Group          string `json:"group"`
	PublicMode     string `json:"public_mode"`
	PrivateKeyMode string `json:"private_key_mode"`
}

type PostDeployAction struct {
	Kind           ActionKind `json:"kind"`
	SystemdService string     `json:"systemd_service,omitempty"`
	Argv           []string   `json:"argv,omitempty"`
	TimeoutSeconds int        `json:"timeout_seconds,omitempty"`
}

type CertificateExport struct {
	ID                 string           `json:"id"`
	Name               string           `json:"name"`
	CertificateHost    string           `json:"certificate_host"`
	AgentID            string           `json:"agent_id"`
	Enabled            bool             `json:"enabled"`
	Mode               ExportMode       `json:"mode"`
	Destinations       []Destination    `json:"destinations"`
	Permissions        PermissionPolicy `json:"permissions"`
	Action             PostDeployAction `json:"action"`
	DesiredFingerprint string           `json:"desired_fingerprint,omitempty"`
}

type CleanupIntent struct {
	ExportID           string        `json:"export_id"`
	Revision           uint64        `json:"revision"`
	CertificateHost    string        `json:"certificate_host"`
	DesiredFingerprint string        `json:"desired_fingerprint"`
	Mode               ExportMode    `json:"mode"`
	Destinations       []Destination `json:"destinations"`
}

type ExportInventory struct {
	Revision   uint64              `json:"revision"`
	ChunkIndex int                 `json:"chunk_index"`
	ChunkCount int                 `json:"chunk_count"`
	Exports    []CertificateExport `json:"exports,omitempty"`
	Keep       []string            `json:"keep,omitempty"`
	Cleanup    []CleanupIntent     `json:"cleanup,omitempty"`
}

type CertificateMaterial struct {
	Host           string `json:"host"`
	CertPEM        string `json:"cert_pem"`
	KeyPEM         string `json:"key_pem"`
	MaterializeKey bool   `json:"materialize_key,omitempty"`
}

type ExportStatus struct {
	ExportID           string    `json:"export_id"`
	Health             Health    `json:"health"`
	DesiredFingerprint string    `json:"desired_fingerprint,omitempty"`
	AppliedFingerprint string    `json:"applied_fingerprint,omitempty"`
	LastErrorCode      string    `json:"last_error_code,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

type ExportDeployment struct {
	DeploymentID       string          `json:"deployment_id"`
	ExportID           string          `json:"export_id"`
	DesiredFingerprint string          `json:"desired_fingerprint"`
	AppliedFingerprint string          `json:"applied_fingerprint,omitempty"`
	Phase              DeploymentPhase `json:"phase"`
	Rollback           RollbackResult  `json:"rollback"`
	ErrorCode          string          `json:"error_code,omitempty"`
	OccurredAt         time.Time       `json:"occurred_at,omitempty"`
}

type CleanupAcknowledgement struct {
	ExportID           string         `json:"export_id"`
	Revision           uint64         `json:"revision"`
	DesiredFingerprint string         `json:"desired_fingerprint"`
	Phase              CleanupPhase   `json:"phase"`
	Outcome            CleanupOutcome `json:"outcome"`
	Rollback           RollbackResult `json:"rollback"`
	ErrorCode          string         `json:"error_code,omitempty"`
}

type AgentCapabilities struct {
	ContractVersion    int          `json:"contract_version"`
	CapabilityRevision string       `json:"capability_revision"`
	Features           []Capability `json:"features"`
	MaxExports         int          `json:"max_exports"`
	MaxDestinations    int          `json:"max_destinations"`
	MaxChunks          int          `json:"max_chunks"`
}

type ExportPlanRequest struct {
	RequestID   string            `json:"request_id"`
	Export      CertificateExport `json:"export"`
	RequestedAt time.Time         `json:"requested_at"`
}

type ExportPlanRequestEnvelope struct {
	Request ExportPlanRequest `json:"request"`
}

type ExportPlanResultEnvelope struct {
	Result ExportPlanResult `json:"result"`
}

type ResolvedDestination struct {
	Kind DestinationKind `json:"kind"`
	Path string          `json:"path"`
	UID  int             `json:"uid"`
	GID  int             `json:"gid"`
	Mode string          `json:"mode"`
}

type ResolvedAction struct {
	Kind           ActionKind `json:"kind"`
	SystemdService string     `json:"systemd_service,omitempty"`
	Executable     string     `json:"executable,omitempty"`
	Argv           []string   `json:"argv,omitempty"`
	TimeoutSeconds int        `json:"timeout_seconds,omitempty"`
	Allowed        bool       `json:"allowed,omitempty"`
}

type ExportPlanResult struct {
	RequestID            string                `json:"request_id"`
	ExportID             string                `json:"export_id"`
	SpecHash             string                `json:"spec_hash"`
	CapabilityRevision   string                `json:"capability_revision"`
	ResolvedDestinations []ResolvedDestination `json:"resolved_destinations"`
	ResolvedAction       ResolvedAction        `json:"resolved_action"`
	Risks                []string              `json:"risks,omitempty"`
	FreshnessToken       string                `json:"freshness_token"`
	ExpiresAt            time.Time             `json:"expires_at"`
}

func (e CertificateExport) Validate() error {
	if err := exportID("export ID", e.ID); err != nil {
		return err
	}
	if err := boundedText("export name", e.Name, 1, maxNameBytes); err != nil {
		return err
	}
	if err := canonicalHost(e.CertificateHost); err != nil {
		return err
	}
	if err := boundedText("agent ID", e.AgentID, 1, maxIDBytes); err != nil {
		return err
	}
	if !e.Mode.valid() {
		return fmt.Errorf("unknown export mode %q", e.Mode)
	}
	if len(e.Destinations) == 0 || len(e.Destinations) > MaxDestinationsPerExport {
		return fmt.Errorf("destinations must contain 1..%d entries", MaxDestinationsPerExport)
	}
	kinds, paths := map[DestinationKind]struct{}{}, map[string]struct{}{}
	for i, destination := range e.Destinations {
		if err := destination.Validate(); err != nil {
			return fmt.Errorf("destination %d: %w", i, err)
		}
		if _, exists := kinds[destination.Kind]; exists {
			return fmt.Errorf("duplicate destination kind %q", destination.Kind)
		}
		if _, exists := paths[destination.Path]; exists {
			return fmt.Errorf("duplicate destination path %q", destination.Path)
		}
		kinds[destination.Kind], paths[destination.Path] = struct{}{}, struct{}{}
	}
	if err := e.Permissions.Validate(); err != nil {
		return err
	}
	if err := e.Action.Validate(); err != nil {
		return err
	}
	return optionalFingerprint(e.DesiredFingerprint)
}

func (d Destination) Validate() error {
	if !d.Kind.valid() {
		return fmt.Errorf("unknown destination kind %q", d.Kind)
	}
	if err := boundedText("destination path", d.Path, 1, 4096); err != nil {
		return err
	}
	if !filepath.IsAbs(d.Path) || filepath.Clean(d.Path) != d.Path || d.Path == string(filepath.Separator) {
		return fmt.Errorf("destination path must be absolute, clean, and non-root")
	}
	return nil
}

func (p PermissionPolicy) Validate() error {
	if err := identity("owner", p.Owner); err != nil {
		return err
	}
	if err := identity("group", p.Group); err != nil {
		return err
	}
	if !validMode(p.PublicMode) || !validMode(p.PrivateKeyMode) {
		return fmt.Errorf("modes must be four octal digits and may not set special bits")
	}
	return nil
}

func (a PostDeployAction) Validate() error {
	if !a.Kind.valid() {
		return fmt.Errorf("unknown post-deploy action %q", a.Kind)
	}
	if a.TimeoutSeconds < 0 || a.TimeoutSeconds > MaxActionTimeoutSeconds {
		return fmt.Errorf("timeout exceeds bounds")
	}
	switch a.Kind {
	case ActionNone:
		if a.SystemdService != "" || len(a.Argv) != 0 || a.TimeoutSeconds != 0 {
			return fmt.Errorf("none action contains extra fields")
		}
	case ActionSystemd:
		if !validService(a.SystemdService) || len(a.Argv) != 0 || a.TimeoutSeconds == 0 {
			return fmt.Errorf("invalid systemd action")
		}
	case ActionCommand:
		if a.SystemdService != "" || a.TimeoutSeconds == 0 || len(a.Argv) == 0 || len(a.Argv) > MaxArgvEntries {
			return fmt.Errorf("invalid command action")
		}
		totalArgBytes := 0
		for i, arg := range a.Argv {
			if err := boundedText(fmt.Sprintf("argv[%d]", i), arg, 1, MaxArgBytes); err != nil {
				return err
			}
			totalArgBytes += len(arg)
		}
		if totalArgBytes > MaxArgvBytes {
			return fmt.Errorf("argv aggregate exceeds limit")
		}
		if !filepath.IsAbs(a.Argv[0]) || filepath.Clean(a.Argv[0]) != a.Argv[0] {
			return fmt.Errorf("command executable must be absolute and clean")
		}
	}
	return nil
}

func (i ExportInventory) Validate() error {
	if i.Revision == 0 {
		return fmt.Errorf("inventory revision is required")
	}
	if i.ChunkCount < 1 || i.ChunkCount > MaxSnapshotChunks || i.ChunkIndex < 0 || i.ChunkIndex >= i.ChunkCount {
		return fmt.Errorf("invalid chunk coordinates")
	}
	actualBytes, err := InventorySerializedBytes(i)
	if err != nil {
		return err
	}
	if actualBytes > MaxChunkBytes {
		return fmt.Errorf("inventory chunk exceeds limit")
	}
	if len(i.Exports) > MaxExportsPerSnapshot || len(i.Keep) > MaxExportsPerSnapshot || len(i.Cleanup) > MaxExportsPerSnapshot {
		return fmt.Errorf("export inventory exceeds limit")
	}
	return i.validatePayload()
}

func (i ExportInventory) validatePayload() error {
	if len(i.Exports) > MaxExportsPerSnapshot || len(i.Keep) > MaxExportsPerSnapshot || len(i.Cleanup) > MaxExportsPerSnapshot || len(i.Exports)+len(i.Cleanup) > MaxExportsPerSnapshot {
		return fmt.Errorf("assembled export inventory exceeds collection limits")
	}
	ids, paths := map[string]struct{}{}, map[string]string{}
	for n, export := range i.Exports {
		if err := export.Validate(); err != nil {
			return fmt.Errorf("export %d: %w", n, err)
		}
		if _, exists := ids[export.ID]; exists {
			return fmt.Errorf("duplicate export ID %q", export.ID)
		}
		ids[export.ID] = struct{}{}
		for _, destination := range export.Destinations {
			if previous, exists := paths[destination.Path]; exists && previous != export.ID {
				return fmt.Errorf("destination path %q belongs to multiple exports", destination.Path)
			}
			paths[destination.Path] = export.ID
		}
	}
	seenKeep := map[string]struct{}{}
	for _, id := range i.Keep {
		if err := exportID("keep export ID", id); err != nil {
			return err
		}
		if _, exists := seenKeep[id]; exists {
			return fmt.Errorf("duplicate keep export ID %q", id)
		}
		seenKeep[id] = struct{}{}
	}
	seenCleanup := map[string]struct{}{}
	for n, cleanup := range i.Cleanup {
		if err := cleanup.Validate(); err != nil {
			return fmt.Errorf("cleanup %d: %w", n, err)
		}
		if _, exists := seenCleanup[cleanup.ExportID]; exists {
			return fmt.Errorf("duplicate cleanup export ID %q", cleanup.ExportID)
		}
		if _, exists := ids[cleanup.ExportID]; exists {
			return fmt.Errorf("export %q is both desired and cleanup", cleanup.ExportID)
		}
		if _, exists := seenKeep[cleanup.ExportID]; exists {
			return fmt.Errorf("export %q is both kept and cleanup", cleanup.ExportID)
		}
		for _, destination := range cleanup.Destinations {
			if previous, exists := paths[destination.Path]; exists {
				return fmt.Errorf("cleanup destination path %q conflicts with export %q", destination.Path, previous)
			}
			paths[destination.Path] = cleanup.ExportID
		}
		seenCleanup[cleanup.ExportID] = struct{}{}
	}
	return nil
}

func InventorySerializedBytes(inventory ExportInventory) (int, error) {
	raw, err := json.Marshal(inventory)
	if err != nil {
		return 0, fmt.Errorf("encode inventory payload: %w", err)
	}
	return len(raw), nil
}

func ValidateInventoryChunks(chunks []ExportInventory) error {
	if len(chunks) == 0 || len(chunks) > MaxSnapshotChunks {
		return fmt.Errorf("invalid inventory chunk count")
	}
	first := chunks[0]
	if first.ChunkCount != len(chunks) {
		return fmt.Errorf("incomplete inventory chunk set")
	}
	combined := ExportInventory{Revision: first.Revision, ChunkIndex: 0, ChunkCount: 1}
	totalBytes := 0
	for index, chunk := range chunks {
		if err := chunk.Validate(); err != nil {
			return fmt.Errorf("chunk %d: %w", index, err)
		}
		if chunk.ChunkIndex != index {
			return fmt.Errorf("inventory chunks are missing or reordered")
		}
		if chunk.Revision != first.Revision || chunk.ChunkCount != first.ChunkCount {
			return fmt.Errorf("inventory chunk metadata mismatch")
		}
		serializedBytes, err := InventorySerializedBytes(chunk)
		if err != nil {
			return err
		}
		totalBytes += serializedBytes
		if totalBytes > MaxAssembledSnapshotBytes {
			return fmt.Errorf("assembled inventory exceeds limit")
		}
		combined.Exports = append(combined.Exports, chunk.Exports...)
		combined.Keep = append(combined.Keep, chunk.Keep...)
		combined.Cleanup = append(combined.Cleanup, chunk.Cleanup...)
	}
	return combined.validatePayload()
}

func (c CleanupIntent) Validate() error {
	if err := exportID("cleanup export ID", c.ExportID); err != nil {
		return err
	}
	if err := canonicalHost(c.CertificateHost); err != nil {
		return err
	}
	if err := requiredFingerprint(c.DesiredFingerprint); err != nil {
		return err
	}
	if c.Revision == 0 || !c.Mode.valid() || len(c.Destinations) == 0 || len(c.Destinations) > MaxDestinationsPerExport {
		return fmt.Errorf("invalid cleanup intent")
	}
	seenPaths := map[string]struct{}{}
	seenKinds := map[DestinationKind]struct{}{}
	for _, destination := range c.Destinations {
		if err := destination.Validate(); err != nil {
			return err
		}
		if _, exists := seenPaths[destination.Path]; exists {
			return fmt.Errorf("duplicate cleanup destination")
		}
		if _, exists := seenKinds[destination.Kind]; exists {
			return fmt.Errorf("duplicate cleanup destination kind")
		}
		seenPaths[destination.Path] = struct{}{}
		seenKinds[destination.Kind] = struct{}{}
	}
	return nil
}

func ValidateCertificateMaterials(materials []CertificateMaterial) error {
	if len(materials) > MaxCertificateBundles {
		return fmt.Errorf("too many certificate bundles")
	}
	hosts := map[string]struct{}{}
	raw, err := json.Marshal(materials)
	if err != nil {
		return fmt.Errorf("encode certificate bundles: %w", err)
	}
	if len(raw) > MaxAssembledSnapshotBytes {
		return fmt.Errorf("aggregate certificate material exceeds bound")
	}
	if len(raw) > MaxChunkBytes {
		return fmt.Errorf("certificate bundles exceed one wire chunk")
	}
	for i, material := range materials {
		if err := canonicalHost(material.Host); err != nil {
			return fmt.Errorf("certificate bundle %d: %w", i, err)
		}
		if _, exists := hosts[material.Host]; exists {
			return fmt.Errorf("duplicate certificate host %q", material.Host)
		}
		hosts[material.Host] = struct{}{}
		if len(material.CertPEM) == 0 || len(material.KeyPEM) == 0 || len(material.CertPEM) > MaxPEMBytes || len(material.KeyPEM) > MaxPEMBytes {
			return fmt.Errorf("certificate material exceeds bounds")
		}
		encoded, err := json.Marshal(material)
		if err != nil || len(encoded) > MaxChunkBytes {
			return fmt.Errorf("certificate bundle %d exceeds chunk bound", i)
		}
	}
	return nil
}

func (s ExportStatus) Validate() error {
	if err := exportID("export ID", s.ExportID); err != nil {
		return err
	}
	if !s.Health.valid() {
		return fmt.Errorf("unknown export health %q", s.Health)
	}
	if err := optionalFingerprint(s.DesiredFingerprint); err != nil {
		return err
	}
	if err := optionalFingerprint(s.AppliedFingerprint); err != nil {
		return err
	}
	if err := optionalCode(s.LastErrorCode); err != nil {
		return err
	}
	switch s.Health {
	case HealthPending:
		if s.LastErrorCode != "" {
			return fmt.Errorf("pending export status cannot contain an error")
		}
	case HealthHealthy:
		if s.DesiredFingerprint == "" || s.AppliedFingerprint != s.DesiredFingerprint || s.LastErrorCode != "" {
			return fmt.Errorf("invalid healthy export status")
		}
	case HealthDegraded:
		if s.DesiredFingerprint == "" || s.AppliedFingerprint == "" || s.LastErrorCode == "" {
			return fmt.Errorf("invalid degraded export status")
		}
	case HealthFailed:
		if s.LastErrorCode == "" {
			return fmt.Errorf("failed export status requires an error code")
		}
	case HealthDisabled:
		if s.LastErrorCode != "" {
			return fmt.Errorf("disabled export status cannot contain an error")
		}
	}
	return nil
}

func (d ExportDeployment) Validate() error {
	if err := boundedText("deployment ID", d.DeploymentID, 1, maxIDBytes); err != nil {
		return err
	}
	if err := exportID("export ID", d.ExportID); err != nil {
		return err
	}
	if err := requiredFingerprint(d.DesiredFingerprint); err != nil {
		return err
	}
	if err := optionalFingerprint(d.AppliedFingerprint); err != nil {
		return err
	}
	if !d.Phase.valid() || !d.Rollback.valid() {
		return fmt.Errorf("invalid deployment phase or rollback result")
	}
	if err := optionalCode(d.ErrorCode); err != nil {
		return err
	}
	switch d.Phase {
	case DeploymentPlanned, DeploymentValidating, DeploymentApplying:
		if d.AppliedFingerprint != "" || d.Rollback != RollbackNotNeeded || d.ErrorCode != "" {
			return fmt.Errorf("in-progress deployment contains terminal state")
		}
	case DeploymentSucceeded:
		if d.AppliedFingerprint != d.DesiredFingerprint || d.Rollback != RollbackNotNeeded || d.ErrorCode != "" {
			return fmt.Errorf("invalid succeeded deployment state")
		}
	case DeploymentRollingBack:
		if d.Rollback != RollbackPending || d.ErrorCode == "" {
			return fmt.Errorf("invalid rolling-back deployment state")
		}
	case DeploymentRolledBack:
		if d.AppliedFingerprint == "" || d.Rollback != RollbackSucceeded || d.ErrorCode == "" {
			return fmt.Errorf("invalid rolled-back deployment state")
		}
	case DeploymentFailed:
		if d.ErrorCode == "" || (d.Rollback != RollbackNotNeeded && d.Rollback != RollbackFailed) {
			return fmt.Errorf("invalid failed deployment state")
		}
	}
	return nil
}

func (c CleanupAcknowledgement) Validate() error {
	if err := exportID("export ID", c.ExportID); err != nil {
		return err
	}
	if err := requiredFingerprint(c.DesiredFingerprint); err != nil {
		return err
	}
	if c.Revision == 0 || !c.Phase.valid() || !c.Outcome.valid() || !c.Rollback.valid() {
		return fmt.Errorf("invalid cleanup acknowledgement")
	}
	if err := optionalCode(c.ErrorCode); err != nil {
		return err
	}
	switch c.Phase {
	case CleanupPending, CleanupApplying:
		if c.Outcome != CleanupOutcomePending || c.Rollback != RollbackNotNeeded || c.ErrorCode != "" {
			return fmt.Errorf("invalid in-progress cleanup state")
		}
	case CleanupCompleted:
		if (c.Outcome != CleanupRemoved && c.Outcome != CleanupPreserved) || c.Rollback != RollbackNotNeeded || c.ErrorCode != "" {
			return fmt.Errorf("invalid completed cleanup state")
		}
	case CleanupPhaseFailed:
		if c.Outcome != CleanupFailed || c.ErrorCode == "" || (c.Rollback != RollbackNotNeeded && c.Rollback != RollbackSucceeded && c.Rollback != RollbackFailed) {
			return fmt.Errorf("invalid failed cleanup state")
		}
	}
	return nil
}

func (c AgentCapabilities) Validate() error {
	if c.ContractVersion != CurrentContractVersion {
		return fmt.Errorf("unsupported certificate export contract version %d", c.ContractVersion)
	}
	if err := boundedText("capability revision", c.CapabilityRevision, 1, maxIDBytes); err != nil {
		return err
	}
	seen := map[Capability]struct{}{}
	for _, feature := range c.Features {
		if !feature.valid() {
			return fmt.Errorf("unknown capability %q", feature)
		}
		if _, exists := seen[feature]; exists {
			return fmt.Errorf("duplicate capability %q", feature)
		}
		seen[feature] = struct{}{}
	}
	if c.MaxExports < 0 || c.MaxExports > MaxExportsPerSnapshot || c.MaxDestinations < 0 || c.MaxDestinations > MaxDestinationsPerExport || c.MaxChunks < 0 || c.MaxChunks > MaxSnapshotChunks {
		return fmt.Errorf("capability maxima exceed contract")
	}
	return nil
}

func SupportsExports(c *AgentCapabilities) bool {
	if c == nil || c.Validate() != nil {
		return false
	}
	for _, feature := range c.Features {
		if feature == CapabilityCertificateExports {
			return true
		}
	}
	return false
}

func (r ExportPlanRequest) Validate() error {
	if err := boundedText("request ID", r.RequestID, 1, maxIDBytes); err != nil {
		return err
	}
	if r.RequestedAt.IsZero() {
		return fmt.Errorf("requested_at is required")
	}
	return r.Export.Validate()
}

func (e ExportPlanRequestEnvelope) Validate() error { return e.Request.Validate() }

func (e ExportPlanResultEnvelope) Validate() error { return e.Result.Validate() }

func (r ExportPlanResult) Validate() error { return r.ValidateAt(time.Now()) }

func (r ExportPlanResult) ValidateAt(now time.Time) error {
	if err := boundedText("request ID", r.RequestID, 1, maxIDBytes); err != nil {
		return err
	}
	if err := exportID("export ID", r.ExportID); err != nil {
		return err
	}
	if err := requiredFingerprint(r.SpecHash); err != nil {
		return fmt.Errorf("spec hash: %w", err)
	}
	if err := boundedText("capability revision", r.CapabilityRevision, 1, maxIDBytes); err != nil {
		return err
	}
	if err := boundedText("freshness token", r.FreshnessToken, 16, 512); err != nil {
		return err
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) || r.ExpiresAt.After(now.Add(MaxPlanLifetime)) {
		return fmt.Errorf("plan token is stale or has excessive lifetime")
	}
	if len(r.ResolvedDestinations) == 0 || len(r.ResolvedDestinations) > MaxDestinationsPerExport || len(r.Risks) > maxRisks {
		return fmt.Errorf("plan aggregate exceeds bounds")
	}
	seenPaths := map[string]struct{}{}
	seenKinds := map[DestinationKind]struct{}{}
	for _, destination := range r.ResolvedDestinations {
		if err := destination.Validate(); err != nil {
			return err
		}
		if _, exists := seenPaths[destination.Path]; exists {
			return fmt.Errorf("duplicate resolved destination")
		}
		if _, exists := seenKinds[destination.Kind]; exists {
			return fmt.Errorf("duplicate resolved destination kind")
		}
		seenPaths[destination.Path] = struct{}{}
		seenKinds[destination.Kind] = struct{}{}
	}
	if err := r.ResolvedAction.Validate(); err != nil {
		return err
	}
	for _, risk := range r.Risks {
		if err := boundedText("risk", risk, 1, maxRiskBytes); err != nil {
			return err
		}
	}
	return nil
}

func (r ResolvedDestination) Validate() error {
	if err := (Destination{Kind: r.Kind, Path: r.Path}).Validate(); err != nil {
		return err
	}
	if r.UID < 0 || r.GID < 0 || !validMode(r.Mode) {
		return fmt.Errorf("invalid resolved ownership or mode")
	}
	return nil
}

func (r ResolvedAction) Validate() error {
	action := PostDeployAction{Kind: r.Kind, SystemdService: r.SystemdService, Argv: r.Argv, TimeoutSeconds: r.TimeoutSeconds}
	if r.Kind == ActionCommand {
		if r.Executable == "" || len(r.Argv) == 0 || r.Argv[0] != r.Executable {
			return fmt.Errorf("resolved executable must match argv[0]")
		}
	} else if r.Executable != "" {
		return fmt.Errorf("unexpected resolved executable")
	}
	return action.Validate()
}

func DecodeStrict(data []byte, dst any) error {
	if len(data) > MaxAssembledSnapshotBytes {
		return fmt.Errorf("JSON exceeds maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	if validator, ok := dst.(interface{ Validate() error }); ok {
		return validator.Validate()
	}
	return nil
}

func (v *ExportMode) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "export mode", func(s string) bool { return ExportMode(s).valid() }, func(s string) { *v = ExportMode(s) })
}
func (v *DestinationKind) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "destination kind", func(s string) bool { return DestinationKind(s).valid() }, func(s string) { *v = DestinationKind(s) })
}
func (v *ActionKind) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "action kind", func(s string) bool { return ActionKind(s).valid() }, func(s string) { *v = ActionKind(s) })
}
func (v *Health) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "health", func(s string) bool { return Health(s).valid() }, func(s string) { *v = Health(s) })
}
func (v *DeploymentPhase) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "deployment phase", func(s string) bool { return DeploymentPhase(s).valid() }, func(s string) { *v = DeploymentPhase(s) })
}
func (v *RollbackResult) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "rollback result", func(s string) bool { return RollbackResult(s).valid() }, func(s string) { *v = RollbackResult(s) })
}
func (v *CleanupOutcome) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "cleanup outcome", func(s string) bool { return CleanupOutcome(s).valid() }, func(s string) { *v = CleanupOutcome(s) })
}
func (v *CleanupPhase) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "cleanup phase", func(s string) bool { return CleanupPhase(s).valid() }, func(s string) { *v = CleanupPhase(s) })
}
func (v *Capability) UnmarshalJSON(b []byte) error {
	return unmarshalEnum(b, "capability", func(s string) bool { return Capability(s).valid() }, func(s string) { *v = Capability(s) })
}

func unmarshalEnum(b []byte, name string, valid func(string) bool, set func(string)) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !valid(s) {
		return fmt.Errorf("unknown %s %q", name, s)
	}
	set(s)
	return nil
}
func (v ExportMode) valid() bool { return v == ExportModeSymlink || v == ExportModeCopy }
func (v DestinationKind) valid() bool {
	return v == DestinationCert || v == DestinationChain || v == DestinationFullChain || v == DestinationPrivateKey
}
func (v ActionKind) valid() bool { return v == ActionNone || v == ActionSystemd || v == ActionCommand }
func (v Health) valid() bool {
	return v == HealthPending || v == HealthHealthy || v == HealthDegraded || v == HealthFailed || v == HealthDisabled
}
func (v DeploymentPhase) valid() bool {
	return v == DeploymentPlanned || v == DeploymentValidating || v == DeploymentApplying || v == DeploymentSucceeded || v == DeploymentRollingBack || v == DeploymentRolledBack || v == DeploymentFailed
}
func (v RollbackResult) valid() bool {
	return v == RollbackNotNeeded || v == RollbackPending || v == RollbackSucceeded || v == RollbackFailed
}
func (v CleanupOutcome) valid() bool {
	return v == CleanupOutcomePending || v == CleanupRemoved || v == CleanupPreserved || v == CleanupFailed
}
func (v CleanupPhase) valid() bool {
	return v == CleanupPending || v == CleanupApplying || v == CleanupCompleted || v == CleanupPhaseFailed
}
func (v Capability) valid() bool {
	switch v {
	case CapabilityCertificateExports, CapabilityChunkedInventory, CapabilitySymlinkMode, CapabilityCopyMode, CapabilitySystemdAction, CapabilityCommandAction:
		return true
	}
	return false
}

var identityPattern = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+)$`)
var exportIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var servicePattern = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+\.service$`)
var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)

func boundedText(name, value string, min, max int) error {
	if len(value) < min || len(value) > max {
		return fmt.Errorf("%s length must be %d..%d bytes", name, min, max)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", name)
		}
	}
	return nil
}
func exportID(name, value string) error {
	if !exportIDPattern.MatchString(value) {
		return fmt.Errorf("%s must use the path-safe export ID format", name)
	}
	return nil
}
func canonicalHost(host string) error {
	if host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "*") {
		return fmt.Errorf("certificate host must be a canonical non-wildcard FQDN")
	}
	if err := dnsname.ValidateSubdomain(host); err != nil {
		return err
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf("certificate host must be an FQDN")
	}
	return nil
}
func identity(name, value string) error {
	if err := boundedText(name, value, 1, maxIdentityBytes); err != nil {
		return err
	}
	if !identityPattern.MatchString(value) {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}
func validMode(value string) bool {
	if len(value) != 4 || value[0] != '0' {
		return false
	}
	for _, c := range value[1:] {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}
func validService(value string) bool {
	return len(value) <= maxIdentityBytes && servicePattern.MatchString(value)
}
func requiredFingerprint(value string) error {
	if !fingerprintPattern.MatchString(value) {
		return fmt.Errorf("fingerprint must be 64 lowercase hexadecimal characters")
	}
	return nil
}
func optionalFingerprint(value string) error {
	if value == "" {
		return nil
	}
	return requiredFingerprint(value)
}
func optionalCode(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxErrorCode || !codePattern.MatchString(value) {
		return fmt.Errorf("invalid sanitized error code")
	}
	return nil
}
