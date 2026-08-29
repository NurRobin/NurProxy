//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/apache"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/nginx"
	"github.com/NurRobin/NurProxy/internal/shared/apachegen"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
	"github.com/NurRobin/NurProxy/internal/shared/nginxgen"
	"github.com/NurRobin/NurProxy/internal/shared/nginxparse"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
	"golang.org/x/sys/unix"
)

type managedApplyAction struct {
	agentUID       uint32
	ownerUID       uint32
	stagingRootUID uint32
	target         ProxyTargetConfig
	layout         ManagedApplyTargetConfig
	journal        *Journal
	host           proxyServiceHost
}

type managedCompiledFile struct {
	ResourceID string `json:"resource_id,omitempty"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Mode       uint32 `json:"mode"`
	Class      string `json:"class"`
	Delete     bool   `json:"delete"`
	Preserve   bool   `json:"preserve"`
	Content    []byte `json:"-"`
}

type managedCompiledLink struct {
	Path     string `json:"path"`
	Target   string `json:"target"`
	Delete   bool   `json:"delete"`
	Preserve bool   `json:"preserve"`
}

type managedCompilation struct {
	Files []managedCompiledFile `json:"files"`
	Links []managedCompiledLink `json:"links"`
}

type managedFileSnapshot struct {
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	LinkTarget string `json:"link_target"`
	Content    []byte `json:"content"`
}

type managedApplySnapshot struct {
	Files []managedFileSnapshot `json:"files"`
}

func newManagedApplyAction(agentUID uint32, target ProxyTargetConfig, layout ManagedApplyTargetConfig, journal *Journal, host proxyServiceHost) (*managedApplyAction, error) {
	if agentUID == 0 || target.Validate() != nil || layout.Validate(target.Kind) != nil || journal == nil || host == nil {
		return nil, fmt.Errorf("managed apply action is not safely configured")
	}
	return &managedApplyAction{agentUID: agentUID, ownerUID: 0, stagingRootUID: 0, target: target, layout: layout, journal: journal, host: host}, nil
}

func (a *managedApplyAction) Plan(ctx context.Context, intent helperprotocol.ApplyIntent) (ManagedApplyMaterial, error) {
	compilation, err := a.compile(intent)
	if err != nil {
		return ManagedApplyMaterial{}, err
	}
	executionHash, err := managedCompilationDigest(compilation)
	if err != nil {
		return ManagedApplyMaterial{}, err
	}
	fingerprint, err := a.fingerprint(ctx, compilation)
	if err != nil {
		return ManagedApplyMaterial{}, err
	}
	return ManagedApplyMaterial{
		CustomPolicyVersion: a.layout.CustomPolicyVersion,
		ExecutionPlanHash:   executionHash, ResourceFingerprint: fingerprint,
		RollbackCoverage: helperprotocol.RollbackCoveragePartial,
	}, nil
}

func (a *managedApplyAction) Rediscover(ctx context.Context, plan helperprotocol.ManagedApplyPlan, intent helperprotocol.ApplyIntent) (string, string, error) {
	if plan.OperationID != intent.OperationID || plan.CustomPolicyVersion != a.layout.CustomPolicyVersion {
		return "", "", fmt.Errorf("managed plan does not match local policy")
	}
	compilation, err := a.compile(intent)
	if err != nil {
		return "", "", err
	}
	executionHash, err := managedCompilationDigest(compilation)
	if err != nil {
		return "", "", err
	}
	fingerprint, err := a.fingerprint(ctx, compilation)
	return executionHash, fingerprint, err
}

func (a *managedApplyAction) Prepare(ctx context.Context, operationID string, plan helperprotocol.ManagedApplyPlan, intent helperprotocol.ApplyIntent) (PreparedAction, error) {
	compilation, err := a.compile(intent)
	if err != nil {
		return PreparedAction{}, err
	}
	executionHash, err := managedCompilationDigest(compilation)
	if err != nil || executionHash != plan.ExecutionPlanHash {
		return PreparedAction{}, fmt.Errorf("managed compilation changed before snapshot")
	}
	fingerprint, err := a.fingerprint(ctx, compilation)
	if err != nil || fingerprint != plan.ResourceFingerprint {
		return PreparedAction{}, fmt.Errorf("managed targets changed before snapshot")
	}
	snapshot, err := captureManagedSnapshot(compilation, a.ownerUID)
	if err != nil {
		return PreparedAction{}, err
	}
	digest, err := a.journal.StoreSnapshot(operationID, snapshot)
	if err != nil {
		return PreparedAction{}, err
	}
	return PreparedAction{SnapshotDigest: digest, RollbackCoverage: helperprotocol.RollbackCoveragePartial}, nil
}

func (a *managedApplyAction) Execute(ctx context.Context, operationID string, plan helperprotocol.ManagedApplyPlan, intent helperprotocol.ApplyIntent, prepared PreparedAction) (ActionResult, error) {
	if _, err := a.loadSnapshot(operationID, prepared); err != nil {
		return ActionResult{}, err
	}
	compilation, err := a.compile(intent)
	if err != nil {
		return ActionResult{}, err
	}
	executionHash, err := managedCompilationDigest(compilation)
	if err != nil || executionHash != plan.ExecutionPlanHash {
		return ActionResult{}, fmt.Errorf("managed compilation changed after snapshot")
	}
	fingerprint, err := a.fingerprint(ctx, compilation)
	if err != nil || fingerprint != plan.ResourceFingerprint {
		return ActionResult{}, fmt.Errorf("managed targets changed after snapshot")
	}
	if !compilation.hasDeletions() {
		if err := a.host.Validate(ctx, a.target); err != nil {
			return ActionResult{}, fmt.Errorf("native proxy validation failed before managed mutation: %w", err)
		}
	}
	mutated := false
	for _, link := range compilation.Links {
		if !link.Delete {
			continue
		}
		removed, err := removeManagedLink(link, a.ownerUID)
		if err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = mutated || removed
	}
	for _, file := range compilation.Files {
		if !file.Delete {
			continue
		}
		removed, err := removeManagedFile(file, a.ownerUID)
		if err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = mutated || removed
	}
	for _, file := range compilation.Files {
		if file.Delete || file.Preserve {
			continue
		}
		if err := installManagedFile(file, a.ownerUID); err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = true
	}
	for _, link := range compilation.Links {
		if link.Delete || link.Preserve {
			continue
		}
		if err := installManagedLink(link, a.ownerUID); err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = true
	}
	if !mutated {
		artifacts, err := a.attestManagedArtifacts(compilation)
		if err != nil {
			return ActionResult{}, fmt.Errorf("managed proxy artifact attestation failed: %w", err)
		}
		return ActionResult{Mutated: false, Validated: true, SanitizedResult: "managed proxy state already converged", ManagedArtifacts: artifacts}, nil
	}
	if err := a.host.Validate(ctx, a.target); err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("native proxy validation failed after managed commit: %w", err)
	}
	if err := a.host.Mutate(ctx, a.target, proxyServiceReload); err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("proxy reload failed after managed commit: %w", err)
	}
	if err := a.host.Validate(ctx, a.target); err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("native proxy validation failed after managed reload: %w", err)
	}
	post, err := a.host.Inspect(ctx, a.target)
	if err != nil || !post.Active || post.Kind != a.target.Kind || post.Unit != a.target.Unit {
		return ActionResult{Mutated: true}, fmt.Errorf("managed proxy postcondition could not be proven")
	}
	artifacts, err := a.attestManagedArtifacts(compilation)
	if err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("managed proxy artifact attestation failed: %w", err)
	}
	return ActionResult{Mutated: true, Validated: true, SanitizedResult: fmt.Sprintf("applied %d managed files and %d activation links", len(compilation.Files), len(compilation.Links)), ManagedArtifacts: artifacts}, nil
}

func (a *managedApplyAction) Rollback(ctx context.Context, operationID string, _ helperprotocol.ManagedApplyPlan, _ helperprotocol.ApplyIntent, prepared PreparedAction) error {
	snapshot, err := a.loadSnapshot(operationID, prepared)
	if err != nil {
		return err
	}
	for index := len(snapshot.Files) - 1; index >= 0; index-- {
		if err := restoreManagedSnapshot(snapshot.Files[index], a.ownerUID); err != nil {
			return err
		}
	}
	if err := a.host.Validate(ctx, a.target); err != nil {
		return fmt.Errorf("restored proxy state is invalid: %w", err)
	}
	if err := a.host.Mutate(ctx, a.target, proxyServiceReload); err != nil {
		return fmt.Errorf("reload after managed rollback failed: %w", err)
	}
	return a.host.Validate(ctx, a.target)
}

func (a *managedApplyAction) loadSnapshot(operationID string, prepared PreparedAction) (managedApplySnapshot, error) {
	payload, err := a.journal.LoadSnapshot(operationID, prepared.SnapshotDigest)
	if err != nil {
		return managedApplySnapshot{}, err
	}
	snapshot, err := helperprotocol.Decode[managedApplySnapshot](payload)
	if err != nil {
		return managedApplySnapshot{}, fmt.Errorf("managed apply snapshot is invalid: %w", err)
	}
	if snapshot.Files == nil {
		return managedApplySnapshot{}, fmt.Errorf("managed apply snapshot has a null file set")
	}
	return snapshot, nil
}

func (a *managedApplyAction) compile(intent helperprotocol.ApplyIntent) (managedCompilation, error) {
	if intent.Validate() != nil || intent.HelperInstanceID == "" {
		return managedCompilation{}, fmt.Errorf("invalid managed apply intent")
	}
	certificates, err := a.loadStagedCertificates(intent)
	if err != nil {
		return managedCompilation{}, err
	}
	compilation := managedCompilation{Files: []managedCompiledFile{}, Links: []managedCompiledLink{}}
	for host, pair := range certificates {
		base := certstore.SanitizeHost(host)
		compilation.Files = append(compilation.Files,
			compiledFile(filepath.Join(a.layout.CertificateDir, base+".crt"), pair.cert, 0o644, "secret"),
			compiledFile(filepath.Join(a.layout.CertificateDir, base+".key.plain"), pair.key, 0o600, "secret"),
		)
	}
	for _, routeIntent := range intent.Routes {
		if routeIntent.Backend != a.target.Kind {
			return managedCompilation{}, fmt.Errorf("route backend does not match root-owned proxy mapping")
		}
		route := routeIntent.Route
		certPath, keyPath := "", ""
		if _, ok := certificates[route.Host]; ok {
			base := certstore.SanitizeHost(route.Host)
			certPath = filepath.Join(a.layout.CertificateDir, base+".crt")
			keyPath = filepath.Join(a.layout.CertificateDir, base+".key.plain")
		}
		authPath := ""
		if route.BasicAuth != nil || route.IsRaw() {
			authPath = filepath.Join(a.layout.CertificateDir, "auth-"+certstore.SanitizeHost(route.Host)+".htpasswd")
		}
		if route.BasicAuth != nil {
			compilation.Files = append(compilation.Files, compiledFile(authPath, []byte(route.BasicAuth.Username+":"+route.BasicAuth.PasswordHash+"\n"), 0o600, "secret"))
		}
		available := filepath.Join(a.layout.AvailableDir, managedFileName(a.target.Kind, route.Host))
		var content string
		preserve := false
		if route.IsRaw() {
			if a.target.Kind != "nginx" || nginxparse.ValidateManaged(route.Raw.Content, nginxparse.ManagedPolicy{Host: route.Host, CertPath: certPath, KeyPath: keyPath, AuthPath: authPath}) != nil {
				content = route.Raw.Content
				preserve = true
			} else {
				content = route.Raw.Content
			}
		} else {
			content, err = a.renderRoute(route, certPath, keyPath, authPath)
		}
		if err != nil {
			return managedCompilation{}, err
		}
		if !preserve {
			preserve, err = exactUnmarkedManagedFile(available, []byte(content), a.ownerUID)
			if err != nil {
				return managedCompilation{}, err
			}
		}
		if !preserve && !route.IsRaw() && route.BasicAuth != nil {
			legacyAuthPath := strings.TrimSuffix(available, ".conf") + ".htpasswd"
			legacyContent, legacyErr := a.renderRoute(route, certPath, keyPath, legacyAuthPath)
			if legacyErr != nil {
				return managedCompilation{}, legacyErr
			}
			preserve, err = exactUnmarkedManagedFile(available, []byte(legacyContent), a.ownerUID)
			if err != nil {
				return managedCompilation{}, err
			}
			if preserve {
				content = legacyContent
			}
		}
		compiledContent := []byte(proxy.StampManagedArtifact(content))
		if preserve {
			compiledContent = []byte(content)
		}
		file := compiledFile(available, compiledContent, 0o644, "vhost")
		file.ResourceID = routeIntent.ArtifactID
		file.Preserve = preserve
		compilation.Files = append(compilation.Files, file)
		if a.layout.EnabledDir != "" {
			compilation.Links = append(compilation.Links, managedCompiledLink{Path: filepath.Join(a.layout.EnabledDir, filepath.Base(available)), Target: available, Preserve: preserve})
		}
	}
	for _, deletion := range intent.DeletionSet {
		if deletion.Backend != a.target.Kind {
			return managedCompilation{}, fmt.Errorf("managed deletion backend does not match root-owned proxy mapping")
		}
		available := filepath.Join(a.layout.AvailableDir, managedFileName(a.target.Kind, deletion.Host))
		compilation.Files = append(compilation.Files, managedCompiledFile{Path: available, Class: "vhost", Delete: true})
		compilation.Files = append(compilation.Files, managedCompiledFile{Path: filepath.Join(a.layout.CertificateDir, "auth-"+certstore.SanitizeHost(deletion.Host)+".htpasswd"), Class: "secret", Delete: true})
		if a.layout.EnabledDir != "" {
			compilation.Links = append(compilation.Links, managedCompiledLink{Path: filepath.Join(a.layout.EnabledDir, filepath.Base(available)), Target: available, Delete: true})
		}
	}
	if intent.PruneCertificates {
		keep := make(map[string]struct{}, len(intent.CertificateKeep))
		for _, host := range intent.CertificateKeep {
			keep[certstore.SanitizeHost(host)] = struct{}{}
		}
		entries, err := os.ReadDir(a.layout.CertificateDir)
		if err != nil {
			return managedCompilation{}, fmt.Errorf("read exclusive managed certificate directory: %w", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			base, recognized := managedCertificateBase(name)
			if !recognized {
				continue
			}
			if _, retained := keep[base]; retained {
				continue
			}
			compilation.Files = append(compilation.Files, managedCompiledFile{Path: filepath.Join(a.layout.CertificateDir, name), Class: "secret", Delete: true})
		}
	}
	sort.Slice(compilation.Files, func(i, j int) bool {
		if compilation.Files[i].Class != compilation.Files[j].Class {
			return compilation.Files[i].Class == "secret"
		}
		return compilation.Files[i].Path < compilation.Files[j].Path
	})
	sort.Slice(compilation.Links, func(i, j int) bool { return compilation.Links[i].Path < compilation.Links[j].Path })
	targets := make(map[string]struct{}, len(compilation.Files))
	for _, file := range compilation.Files {
		if _, exists := targets[file.Path]; exists {
			return managedCompilation{}, fmt.Errorf("managed compilation contains a duplicate file target")
		}
		targets[file.Path] = struct{}{}
	}
	return compilation, nil
}

func exactUnmarkedManagedFile(path string, desired []byte, ownerUID uint32) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != ownerUID || info.Mode().Perm()&0o022 != 0 || info.Size() < 0 || info.Size() > maxConfigFileBytes {
		return false, nil
	}
	content, err := readNoFollowFile(path, info.Size())
	if err != nil {
		return false, err
	}
	return !proxy.HasManagedArtifactMarker(string(content)) && bytes.Equal(content, desired), nil
}

type stagedCertificatePair struct{ cert, key []byte }

func (a *managedApplyAction) loadStagedCertificates(intent helperprotocol.ApplyIntent) (map[string]stagedCertificatePair, error) {
	byHost := make(map[string]stagedCertificatePair)
	for _, artifact := range intent.Artifacts {
		if artifact.Kind != "certificate" && artifact.Kind != "source_key" {
			return nil, fmt.Errorf("unsupported staged artifact kind")
		}
		name, err := helperprotocol.StagedArtifactFileName(artifact)
		if err != nil {
			return nil, err
		}
		data, err := readStagedArtifact(a.layout.StagingDir, intent.OperationID, name, artifact, a.agentUID, a.stagingRootUID)
		if err != nil {
			return nil, err
		}
		pair := byHost[artifact.Name]
		if artifact.Kind == "certificate" {
			pair.cert = data
		} else {
			pair.key = data
		}
		byHost[artifact.Name] = pair
	}
	for host, pair := range byHost {
		if len(pair.cert) == 0 || len(pair.key) == 0 {
			return nil, fmt.Errorf("staged certificate pair is incomplete")
		}
		if _, err := tls.X509KeyPair(pair.cert, pair.key); err != nil {
			return nil, fmt.Errorf("staged certificate pair for %s is invalid", host)
		}
	}
	return byHost, nil
}

func (a *managedApplyAction) renderRoute(route proxymodel.Route, certPath, keyPath, authPath string) (string, error) {
	switch a.target.Kind {
	case "nginx":
		result, err := nginxgen.Render(nginxgen.Input{Route: route, NginxVersion: a.layout.ProxyVersion, CertPath: certPath, KeyPath: keyPath, AuthFile: authPath})
		if err != nil {
			return "", err
		}
		var content strings.Builder
		if result.HTTPPreamble != "" {
			content.WriteString(result.HTTPPreamble)
			if !strings.HasSuffix(result.HTTPPreamble, "\n") {
				content.WriteByte('\n')
			}
			content.WriteByte('\n')
		}
		content.WriteString(result.Server)
		return content.String(), nil
	case "apache":
		result, err := apachegen.Render(apachegen.Input{Route: route, CertPath: certPath, KeyPath: keyPath, AuthFile: authPath})
		if err != nil {
			return "", err
		}
		var content strings.Builder
		if result.Preamble != "" {
			content.WriteString(result.Preamble)
			if !strings.HasSuffix(result.Preamble, "\n") {
				content.WriteByte('\n')
			}
			content.WriteByte('\n')
		}
		content.WriteString(result.VHost)
		return content.String(), nil
	default:
		return "", fmt.Errorf("managed renderer is unavailable for proxy kind")
	}
}

func managedFileName(kind, host string) string {
	if kind == "apache" {
		return apache.ManagedFileName(host)
	}
	return nginx.ManagedFileName(host)
}

func managedCertificateBase(name string) (string, bool) {
	for _, suffix := range []string{".key.plain", ".key.enc", ".crt", ".key"} {
		if base := strings.TrimSuffix(name, suffix); base != name && base != "" && certstore.SanitizeHost(base) == base {
			return base, true
		}
	}
	return "", false
}

func compiledFile(path string, content []byte, mode os.FileMode, class string) managedCompiledFile {
	digest := sha256.Sum256(content)
	return managedCompiledFile{Path: path, SHA256: hex.EncodeToString(digest[:]), Mode: uint32(mode.Perm()), Class: class, Content: append([]byte(nil), content...)}
}

func managedCompilationDigest(compilation managedCompilation) (string, error) {
	return helperprotocol.Digest(compilation)
}

func (c managedCompilation) hasDeletions() bool {
	for _, file := range c.Files {
		if file.Delete {
			return true
		}
	}
	for _, link := range c.Links {
		if link.Delete {
			return true
		}
	}
	return false
}

func (a *managedApplyAction) fingerprint(ctx context.Context, compilation managedCompilation) (string, error) {
	if err := validateManagedCompilationTargets(compilation); err != nil {
		return "", err
	}
	facts, err := a.host.Inspect(ctx, a.target)
	if err != nil {
		return "", err
	}
	current := make([]managedFileSnapshot, 0, len(compilation.Files)+len(compilation.Links))
	for _, file := range compilation.Files {
		var item managedFileSnapshot
		var err error
		if file.Preserve {
			item, err = inspectPreservedManagedFile(file, a.ownerUID)
		} else {
			item, err = inspectManagedPath(file.Path, file.Class, "", a.ownerUID)
		}
		if err != nil {
			return "", err
		}
		current = append(current, item)
	}
	for _, link := range compilation.Links {
		item, err := inspectManagedPath(link.Path, "link", link.Target, a.ownerUID)
		if err != nil {
			return "", err
		}
		if link.Preserve && !item.Exists {
			return "", fmt.Errorf("policy-foreign raw configuration has no exact live activation link")
		}
		current = append(current, item)
	}
	return helperprotocol.Digest(struct {
		Proxy   proxyServiceFacts     `json:"proxy"`
		Targets []managedFileSnapshot `json:"targets"`
	}{Proxy: facts, Targets: current})
}

func validateManagedCompilationTargets(compilation managedCompilation) error {
	if compilation.Files == nil || compilation.Links == nil {
		return fmt.Errorf("managed compilation has noncanonical collections")
	}
	totalReceiptContent := 0
	for _, file := range compilation.Files {
		if validatePrivatePath(file.Path) != nil || (file.Class != "vhost" && file.Class != "secret") {
			return fmt.Errorf("managed compilation contains an invalid file")
		}
		if file.Delete {
			if file.ResourceID != "" || file.Preserve || file.SHA256 != "" || file.Mode != 0 || len(file.Content) != 0 {
				return fmt.Errorf("managed compilation contains an invalid file deletion")
			}
			continue
		}
		if !validDigest(file.SHA256) || (file.Mode != 0o600 && file.Mode != 0o644) {
			return fmt.Errorf("managed compilation contains invalid file content")
		}
		if file.Preserve && file.Class != "vhost" {
			return fmt.Errorf("managed compilation preserves an unsupported file class")
		}
		digest := sha256.Sum256(file.Content)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return fmt.Errorf("managed compilation content digest mismatch")
		}
		if file.Class == "vhost" {
			if file.ResourceID == "" || len(file.ResourceID) > 128 {
				return fmt.Errorf("managed vhost has no bounded resource identity")
			}
			totalReceiptContent += len(file.Content)
			if totalReceiptContent > helperprotocol.MaxManagedReceiptContentBytes {
				return fmt.Errorf("managed vhost receipts exceed protocol content limit")
			}
		} else if file.ResourceID != "" {
			return fmt.Errorf("managed secret unexpectedly has a resource identity")
		}
	}
	for _, link := range compilation.Links {
		if validatePrivatePath(link.Path) != nil || validatePrivatePath(link.Target) != nil {
			return fmt.Errorf("managed compilation contains an invalid activation link")
		}
		if link.Delete && link.Preserve {
			return fmt.Errorf("managed compilation contains an invalid preserved link deletion")
		}
	}
	return nil
}

func (a *managedApplyAction) attestManagedArtifacts(compilation managedCompilation) ([]helperprotocol.ManagedArtifactReceipt, error) {
	if err := validateManagedCompilationTargets(compilation); err != nil {
		return nil, err
	}
	enabledByTarget := make(map[string]bool, len(compilation.Links))
	for _, link := range compilation.Links {
		if link.Delete {
			continue
		}
		item, err := inspectManagedPath(link.Path, "link", link.Target, a.ownerUID)
		if err != nil || !item.Exists {
			return nil, fmt.Errorf("activation link postcondition is not exact")
		}
		enabledByTarget[link.Target] = true
	}
	artifacts := make([]helperprotocol.ManagedArtifactReceipt, 0, len(compilation.Files))
	for _, file := range compilation.Files {
		if file.Delete || file.Class != "vhost" {
			continue
		}
		var item managedFileSnapshot
		var err error
		if file.Preserve {
			item, err = inspectPreservedManagedFile(file, a.ownerUID)
		} else {
			item, err = inspectManagedPath(file.Path, file.Class, "", a.ownerUID)
		}
		if err != nil || !item.Exists {
			return nil, fmt.Errorf("managed vhost postcondition is not exact")
		}
		digest := sha256.Sum256(item.Content)
		actualChecksum := hex.EncodeToString(digest[:])
		if !file.Preserve && actualChecksum != file.SHA256 {
			return nil, fmt.Errorf("managed vhost content changed before attestation")
		}
		receipt := helperprotocol.ManagedArtifactReceipt{
			ArtifactID: file.ResourceID, Backend: a.target.Kind, TargetKind: "file", TargetPath: file.Path,
			Content: string(item.Content), Checksum: actualChecksum,
			Enabled: a.layout.EnabledDir == "" || enabledByTarget[file.Path], Warnings: []string{},
		}
		if !receipt.Enabled || receipt.Validate() != nil {
			return nil, fmt.Errorf("managed artifact receipt is invalid")
		}
		artifacts = append(artifacts, receipt)
	}
	return artifacts, nil
}

func inspectPreservedManagedFile(file managedCompiledFile, ownerUID uint32) (managedFileSnapshot, error) {
	item := managedFileSnapshot{Path: file.Path, Content: []byte{}}
	info, err := os.Lstat(file.Path)
	if err != nil {
		return item, fmt.Errorf("policy-foreign raw configuration is not already present: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != ownerUID || info.Mode().Perm()&0o022 != 0 || info.Size() < 0 || info.Size() > maxConfigFileBytes {
		return item, fmt.Errorf("policy-foreign raw configuration is not a protected privileged file")
	}
	content, err := readNoFollowFile(file.Path, info.Size())
	if err != nil {
		return item, err
	}
	exact := bytes.Equal(content, file.Content)
	if !exact {
		exact = bytes.Equal(content, []byte(proxy.StampManagedArtifact(string(file.Content))))
	}
	if !exact {
		return item, fmt.Errorf("policy-foreign raw configuration differs from the protected live file")
	}
	item.Exists = true
	item.Mode = uint32(info.Mode())
	item.UID = stat.Uid
	item.GID = stat.Gid
	item.Content = content
	return item, nil
}

func removeManagedFile(file managedCompiledFile, ownerUID uint32) (bool, error) {
	if !file.Delete || (file.Class != "vhost" && file.Class != "secret") {
		return false, fmt.Errorf("invalid managed file deletion")
	}
	current, err := inspectManagedPath(file.Path, file.Class, "", ownerUID)
	if err != nil {
		return false, err
	}
	if !current.Exists {
		return false, nil
	}
	dir := filepath.Dir(file.Path)
	if err := validatePrivilegedManagedDirectory(dir, ownerUID); err != nil {
		return false, err
	}
	if err := os.Remove(file.Path); err != nil {
		return false, err
	}
	return true, syncDirectory(dir)
}

func removeManagedLink(link managedCompiledLink, ownerUID uint32) (bool, error) {
	if !link.Delete {
		return false, fmt.Errorf("invalid managed activation deletion")
	}
	current, err := inspectManagedPath(link.Path, "link", link.Target, ownerUID)
	if err != nil {
		return false, err
	}
	if !current.Exists {
		return false, nil
	}
	dir := filepath.Dir(link.Path)
	if err := validatePrivilegedManagedDirectory(dir, ownerUID); err != nil {
		return false, err
	}
	if err := os.Remove(link.Path); err != nil {
		return false, err
	}
	return true, syncDirectory(dir)
}

func readStagedArtifact(root, operationID, name string, artifact helperprotocol.LogicalArtifact, agentUID, stagingRootUID uint32) ([]byte, error) {
	if validatePrivatePath(root) != nil || !validConfigID(operationID) || filepath.Base(name) != name {
		return nil, fmt.Errorf("staged artifact identity is invalid")
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil || rootStat.Uid != stagingRootUID || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Mode&0o007 != 0 {
		return nil, fmt.Errorf("staging root is not root-owned and bounded")
	}
	operationFD, err := openManagedComponentAt(rootFD, operationID, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	defer unix.Close(operationFD)
	var operationStat unix.Stat_t
	if err := unix.Fstat(operationFD, &operationStat); err != nil || operationStat.Uid != agentUID || operationStat.Mode&unix.S_IFMT != unix.S_IFDIR || operationStat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("staged artifact directory is not private to the agent")
	}
	fd, err := openManagedComponentAt(operationFD, name, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid staged artifact descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || fileOwnerUID(info) != agentUID || info.Mode().Perm()&0o077 != 0 || info.Size() != artifact.Size {
		return nil, fmt.Errorf("staged artifact identity or permissions are invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, helperprotocol.MaxArtifactBytes+1))
	if err != nil || int64(len(data)) != artifact.Size {
		return nil, fmt.Errorf("staged artifact size changed while reading")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != artifact.SHA256 {
		return nil, fmt.Errorf("staged artifact digest does not match signed manifest")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return nil, fmt.Errorf("staged artifact changed while reading")
	}
	return data, nil
}

func openManagedComponentAt(dirFD int, component string, flags int) (int, error) {
	return openManagedComponentAtWith(dirFD, component, flags, unix.Openat2, unix.Openat)
}

func openManagedComponentAtWith(
	dirFD int,
	component string,
	flags int,
	openat2 func(int, string, *unix.OpenHow) (int, error),
	openat func(int, string, int, uint32) (int, error),
) (int, error) {
	if component == "" || component == "." || component == ".." || filepath.Base(component) != component || strings.ContainsRune(component, '\x00') {
		return -1, fmt.Errorf("managed path component is invalid")
	}
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS)
	fd, err := openat2(dirFD, component, &unix.OpenHow{Flags: uint64(flags), Resolve: resolve})
	if err == nil || !errors.Is(err, unix.ENOSYS) {
		return fd, err
	}
	return openat(dirFD, component, flags|unix.O_NOFOLLOW, 0)
}

func captureManagedSnapshot(compilation managedCompilation, ownerUID uint32) (managedApplySnapshot, error) {
	if err := validateManagedCompilationTargets(compilation); err != nil {
		return managedApplySnapshot{}, err
	}
	snapshot := managedApplySnapshot{Files: make([]managedFileSnapshot, 0, len(compilation.Files)+len(compilation.Links))}
	for _, file := range compilation.Files {
		if file.Preserve {
			continue
		}
		item, err := inspectManagedPath(file.Path, file.Class, "", ownerUID)
		if err != nil {
			return managedApplySnapshot{}, err
		}
		snapshot.Files = append(snapshot.Files, item)
	}
	for _, link := range compilation.Links {
		if link.Preserve {
			continue
		}
		item, err := inspectManagedPath(link.Path, "link", link.Target, ownerUID)
		if err != nil {
			return managedApplySnapshot{}, err
		}
		snapshot.Files = append(snapshot.Files, item)
	}
	return snapshot, nil
}

func inspectManagedPath(path, class, expectedLinkTarget string, ownerUID uint32) (managedFileSnapshot, error) {
	item := managedFileSnapshot{Path: path, Content: []byte{}}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return item, nil
	}
	if err != nil {
		return item, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return item, fmt.Errorf("managed target has no unix identity")
	}
	item.Exists = true
	item.Mode = uint32(info.Mode())
	item.UID = stat.Uid
	item.GID = stat.Gid
	switch class {
	case "link":
		if info.Mode()&os.ModeSymlink == 0 || stat.Uid != ownerUID {
			return item, fmt.Errorf("activation target is not a symlink")
		}
		item.LinkTarget, err = os.Readlink(path)
		if err != nil || item.LinkTarget != expectedLinkTarget {
			return item, fmt.Errorf("activation symlink is not exact NurProxy provenance")
		}
	case "vhost", "secret":
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return item, fmt.Errorf("managed target is not a regular file")
		}
		if info.Size() < 0 || info.Size() > maxConfigFileBytes {
			return item, fmt.Errorf("managed target exceeds snapshot limit")
		}
		item.Content, err = readNoFollowFile(path, info.Size())
		if err != nil {
			return item, err
		}
		if stat.Uid != ownerUID {
			return item, fmt.Errorf("managed file is not owned by the configured privileged identity")
		}
		if class == "vhost" && !proxy.HasManagedArtifactMarker(string(item.Content)) {
			return item, fmt.Errorf("refusing to overwrite operator-owned proxy configuration")
		}
	default:
		return item, fmt.Errorf("unknown managed target class")
	}
	return item, nil
}

func installManagedFile(file managedCompiledFile, ownerUID uint32) error {
	if err := validateManagedCompilationTargets(managedCompilation{Files: []managedCompiledFile{file}, Links: []managedCompiledLink{}}); err != nil {
		return err
	}
	if _, err := inspectManagedPath(file.Path, file.Class, "", ownerUID); err != nil {
		return err
	}
	dir := filepath.Dir(file.Path)
	if err := validatePrivilegedManagedDirectory(dir, ownerUID); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".nurproxy-helper-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	tmpInfo, err := tmp.Stat()
	if err != nil || fileOwnerUID(tmpInfo) != ownerUID {
		return fmt.Errorf("managed temporary file owner is not the privileged identity")
	}
	if err := tmp.Chmod(os.FileMode(file.Mode)); err != nil {
		return err
	}
	if _, err := tmp.Write(file.Content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, file.Path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func installManagedLink(link managedCompiledLink, ownerUID uint32) error {
	if validatePrivatePath(link.Path) != nil || validatePrivatePath(link.Target) != nil {
		return fmt.Errorf("invalid managed activation link")
	}
	if _, err := inspectManagedPath(link.Path, "link", link.Target, ownerUID); err != nil && !errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(link.Path); !errors.Is(statErr, os.ErrNotExist) {
			return err
		}
	}
	dir := filepath.Dir(link.Path)
	if err := validatePrivilegedManagedDirectory(dir, ownerUID); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".nurproxy-helper-link-%d", os.Getpid()))
	if err := os.Symlink(link.Target, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, link.Path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func restoreManagedSnapshot(snapshot managedFileSnapshot, ownerUID uint32) error {
	dir := filepath.Dir(snapshot.Path)
	if err := validatePrivilegedManagedDirectory(dir, ownerUID); err != nil {
		return err
	}
	if !snapshot.Exists {
		if err := os.Remove(snapshot.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(dir)
	}
	mode := os.FileMode(snapshot.Mode)
	if mode&os.ModeSymlink != 0 {
		tmp := filepath.Join(dir, fmt.Sprintf(".nurproxy-helper-restore-link-%d", os.Getpid()))
		if err := os.Symlink(snapshot.LinkTarget, tmp); err != nil {
			return err
		}
		defer os.Remove(tmp)
		if err := os.Lchown(tmp, int(snapshot.UID), int(snapshot.GID)); err != nil {
			return err
		}
		if err := os.Rename(tmp, snapshot.Path); err != nil {
			return err
		}
		return syncDirectory(dir)
	}
	tmp, err := os.CreateTemp(dir, ".nurproxy-helper-restore-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		return err
	}
	if err := tmp.Chown(int(snapshot.UID), int(snapshot.GID)); err != nil {
		return err
	}
	if _, err := tmp.Write(snapshot.Content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, snapshot.Path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func validatePrivilegedManagedDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileOwnerUID(info) != ownerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("managed destination directory is not owned by the configured privileged identity")
	}
	return nil
}
