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
	// workerGroup resolves the GID of the proxy worker that reads basic-auth
	// files per request.
	workerGroup func() (uint32, error)
}

type managedCompiledFile struct {
	ResourceID string `json:"resource_id,omitempty"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Mode       uint32 `json:"mode"`
	GID        uint32 `json:"gid,omitempty"`
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
	// RetainedCertificates names unretained certificate bases that were kept
	// because surviving proxy config still references them.
	RetainedCertificates []string `json:"retained_certificates,omitempty"`
	// UnscannedConfigs names surviving config files too large to scan; while
	// any exist, no certificate is pruned.
	UnscannedConfigs []string `json:"unscanned_configs,omitempty"`
	// RetainedAuthFiles names basic-auth files of unrouted hosts that were kept
	// because surviving proxy config still references them.
	RetainedAuthFiles []string `json:"retained_auth_files,omitempty"`
	// LeftoverVhosts names NurProxy-named vhost files this apply neither
	// writes nor deletes (see leftoverManagedVhosts).
	LeftoverVhosts []string `json:"leftover_vhosts,omitempty"`
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
	workerGroup := func() (uint32, error) {
		return resolveProxyWorkerGroup(target.Kind, layout.AvailableDir, readTrustedProxyMainConfig, lookupGroupID)
	}
	return &managedApplyAction{agentUID: agentUID, ownerUID: 0, stagingRootUID: 0, target: target, layout: layout, journal: journal, host: host, workerGroup: workerGroup}, nil
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
	snapshot, err := captureManagedSnapshot(compilation, a.ownerUID, a.layout)
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
		if !file.Delete || isManagedAuthDeletion(file) {
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
		changed, err := installManagedFile(file, a.ownerUID, a.layout)
		if err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = mutated || changed
	}
	for _, link := range compilation.Links {
		if link.Delete || link.Preserve {
			continue
		}
		changed, err := installManagedLink(link, a.ownerUID)
		if err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = mutated || changed
	}
	if mutated {
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
	}
	// Auth files go only after the reload, so the running workers never point
	// at a missing user file (which nginx answers with 500, not 401). Nothing
	// references them any more, so removing them needs no further reload.
	for _, file := range compilation.Files {
		if !file.Delete || !isManagedAuthDeletion(file) {
			continue
		}
		removed, err := removeManagedFile(file, a.ownerUID)
		if err != nil {
			return ActionResult{Mutated: mutated}, err
		}
		mutated = mutated || removed
	}
	if !mutated {
		artifacts, err := a.attestManagedArtifacts(compilation)
		if err != nil {
			return ActionResult{}, fmt.Errorf("managed proxy artifact attestation failed: %w", err)
		}
		return ActionResult{Mutated: false, Validated: true, SanitizedResult: "managed proxy state already converged" + compilation.retentionNote(), ManagedArtifacts: artifacts}, nil
	}
	artifacts, err := a.attestManagedArtifacts(compilation)
	if err != nil {
		return ActionResult{Mutated: true}, fmt.Errorf("managed proxy artifact attestation failed: %w", err)
	}
	return ActionResult{Mutated: true, Validated: true, SanitizedResult: fmt.Sprintf("applied %d managed files and %d activation links", len(compilation.Files), len(compilation.Links)) + compilation.retentionNote(), ManagedArtifacts: artifacts}, nil
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
	authDir := a.layout.AuthDir()
	authGID, authGIDErr, authGIDResolved := uint32(0), error(nil), false
	resolveAuthGID := func() (uint32, error) {
		if !authGIDResolved {
			authGIDResolved = true
			if a.workerGroup == nil {
				authGIDErr = fmt.Errorf("no worker group resolver")
			} else {
				authGID, authGIDErr = a.workerGroup()
			}
		}
		return authGID, authGIDErr
	}
	routeHosts := make(map[string]struct{}, len(intent.Routes))
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
		routeHosts[certstore.SanitizeHost(route.Host)] = struct{}{}
		authPath := ""
		if route.BasicAuth != nil || route.IsRaw() {
			authPath = managedAuthFilePath(authDir, route.Host)
		}
		available := filepath.Join(a.layout.AvailableDir, managedFileName(a.target.Kind, route.Host))
		var content string
		preserve := false
		if route.IsRaw() {
			content, preserve, err = a.admitRawRoute(route, certPath, keyPath, authPath)
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
		// The auth/ file is only written when the vhost actually uses it, so a
		// preserved legacy vhost with its own sidecar needs no worker group.
		needsAuthFile := route.BasicAuth != nil && authPath != "" && bytes.Contains(compiledContent, []byte(authPath))
		if needsAuthFile {
			gid, err := resolveAuthGID()
			if err != nil {
				return managedCompilation{}, fmt.Errorf("basic auth for %s: cannot write %s because the %s worker group is unknown (fix the proxy's user/Group setting, or remove basic auth from this route): %w", route.Host, authPath, a.target.Kind, err)
			}
			authFile := compiledFile(authPath, []byte(route.BasicAuth.Username+":"+route.BasicAuth.PasswordHash+"\n"), 0o640, "auth")
			authFile.GID = gid
			compilation.Files = append(compilation.Files, authFile)
		}
		// Auth files the vhost does not reference are removed: the pre-#147
		// certs/ location, and the auth/ file once basic auth is switched off.
		stale := []managedCompiledFile{{Path: legacyManagedAuthFilePath(a.layout.CertificateDir, route.Host), Class: "secret", Delete: true}}
		if !needsAuthFile {
			stale = append(stale, managedCompiledFile{Path: managedAuthFilePath(authDir, route.Host), Class: "auth", Delete: true})
		}
		for _, deletion := range stale {
			if bytes.Contains(compiledContent, []byte(deletion.Path)) {
				continue
			}
			if err := appendExistingDeletion(&compilation, deletion); err != nil {
				return managedCompilation{}, err
			}
		}
		if a.layout.EnabledDir != "" {
			compilation.Links = append(compilation.Links, managedCompiledLink{Path: filepath.Join(a.layout.EnabledDir, filepath.Base(available)), Target: available, Preserve: preserve})
		}
	}
	for _, deletion := range intent.DeletionSet {
		if deletion.Backend != a.target.Kind {
			return managedCompilation{}, fmt.Errorf("managed deletion backend does not match root-owned proxy mapping")
		}
		available := filepath.Join(a.layout.AvailableDir, managedFileName(a.target.Kind, deletion.Host))
		unmarked, err := unmarkedRegularFile(available)
		if err != nil {
			return managedCompilation{}, err
		}
		if unmarked {
			// Never delete a vhost without NurProxy provenance; it is reported
			// as a leftover in this and every later receipt instead.
			continue
		}
		compilation.Files = append(compilation.Files, managedCompiledFile{Path: available, Class: "vhost", Delete: true})
		compilation.Files = append(compilation.Files,
			managedCompiledFile{Path: managedAuthFilePath(authDir, deletion.Host), Class: "auth", Delete: true},
			managedCompiledFile{Path: legacyManagedAuthFilePath(a.layout.CertificateDir, deletion.Host), Class: "secret", Delete: true},
		)
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
		type pruneCandidate struct{ base, name string }
		var candidates []pruneCandidate
		var candidateBases []string
		var authCandidates []managedCompiledFile
		seenBases := make(map[string]struct{})
		for _, entry := range entries {
			name := entry.Name()
			if host, ok := managedAuthFileHost(name); ok {
				// Legacy certs/ auth files of hosts this push does not route.
				path := filepath.Join(a.layout.CertificateDir, name)
				if _, routed := routeHosts[host]; !routed && !compilation.hasTarget(path) {
					authCandidates = append(authCandidates, managedCompiledFile{Path: path, Class: "secret", Delete: true})
				}
				continue
			}
			base, recognized := managedCertificateBase(name)
			if !recognized {
				continue
			}
			if _, retained := keep[base]; retained {
				continue
			}
			candidates = append(candidates, pruneCandidate{base: base, name: name})
			if _, seen := seenBases[base]; !seen {
				seenBases[base] = struct{}{}
				candidateBases = append(candidateBases, base)
			}
		}
		authEntries, err := os.ReadDir(authDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return managedCompilation{}, fmt.Errorf("read managed auth directory: %w", err)
		}
		for _, entry := range authEntries {
			host, ok := managedAuthFileHost(entry.Name())
			path := filepath.Join(authDir, entry.Name())
			if _, routed := routeHosts[host]; !ok || routed || compilation.hasTarget(path) {
				continue
			}
			authCandidates = append(authCandidates, managedCompiledFile{Path: path, Class: "auth", Delete: true})
		}
		// Nothing that surviving config still references is pruned: not a
		// certificate, and not the auth file of an unrouted host whose vhost
		// stays on disk (an unmarked leftover, or a route omitted this push).
		var config survivingConfig
		if len(candidateBases) > 0 || len(authCandidates) > 0 {
			config, err = a.loadSurvivingConfig(compilation)
			if err != nil {
				return managedCompilation{}, err
			}
		}
		compilation.UnscannedConfigs = config.unscanned
		stillReferenced := make(map[string]struct{})
		for _, base := range candidateBases {
			if config.referencesCertificate(base) {
				stillReferenced[base] = struct{}{}
				compilation.RetainedCertificates = append(compilation.RetainedCertificates, base)
			}
		}
		sort.Strings(compilation.RetainedCertificates)
		for _, candidate := range candidates {
			if _, inUse := stillReferenced[candidate.base]; inUse {
				continue
			}
			compilation.Files = append(compilation.Files, managedCompiledFile{Path: filepath.Join(a.layout.CertificateDir, candidate.name), Class: "secret", Delete: true})
		}
		for _, candidate := range authCandidates {
			if config.references(filepath.Base(candidate.Path)) {
				compilation.RetainedAuthFiles = append(compilation.RetainedAuthFiles, candidate.Path)
				continue
			}
			compilation.Files = append(compilation.Files, candidate)
		}
		sort.Strings(compilation.RetainedAuthFiles)
	}
	leftovers, err := a.leftoverManagedVhosts(compilation)
	if err != nil {
		return managedCompilation{}, err
	}
	compilation.LeftoverVhosts = leftovers
	sort.Slice(compilation.Files, func(i, j int) bool {
		if compilation.Files[i].Class != compilation.Files[j].Class {
			return managedClassOrder(compilation.Files[i].Class) < managedClassOrder(compilation.Files[j].Class)
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

// admitRawRoute decides whether a raw route is written or kept as an exact
// policy-foreign file. nginxparse never admits a raw config that carries
// auth_basic, so raw basic-auth routes are policy-foreign. Those saved from a
// pre-#147 artifact point auth_basic_user_file at certs/, which the worker
// cannot read. When such a raw config is exactly what the generator rendered
// for this route with the old path, it is re-rendered with the auth/ path;
// any other raw config still on the old path is refused with an error that
// names both paths.
func (a *managedApplyAction) admitRawRoute(route proxymodel.Route, certPath, keyPath, authPath string) (string, bool, error) {
	content := route.Raw.Content
	if a.target.Kind != "nginx" {
		return content, true, nil
	}
	if nginxparse.ValidateManaged(content, nginxparse.ManagedPolicy{Host: route.Host, CertPath: certPath, KeyPath: keyPath, AuthPath: authPath}) == nil {
		return content, false, nil
	}
	legacy := legacyManagedAuthFilePath(a.layout.CertificateDir, route.Host)
	if !strings.Contains(content, legacy) {
		return content, true, nil
	}
	if route.BasicAuth != nil {
		structured := route
		structured.Raw = proxymodel.RawConfig{}
		legacyRender, err := a.renderRoute(structured, certPath, keyPath, legacy)
		if err != nil {
			return "", false, err
		}
		if proxy.StampManagedArtifact(content) == proxy.StampManagedArtifact(legacyRender) {
			current, err := a.renderRoute(structured, certPath, keyPath, authPath)
			return current, false, err
		}
	}
	return "", false, fmt.Errorf("raw nginx config for %s uses auth_basic_user_file %s, which the %s worker cannot read; change it to %s", route.Host, legacy, a.target.Kind, authPath)
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
		// The rendered file must stay inside the same directive allowlists as
		// a raw config, so a renderer defect can never become a root write.
		if err := nginxparse.ValidateRendered(content.String(), nginxparse.ManagedPolicy{Host: route.Host, CertPath: certPath, KeyPath: keyPath, AuthPath: authPath}); err != nil {
			return "", fmt.Errorf("rendered nginx config for %s failed the managed policy: %w", route.Host, err)
		}
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

// readTrustedProxyMainConfig reads a root-owned proxy main config that only
// root can modify, so a worker group taken from it is operator intent.
func readTrustedProxyMainConfig(path string) ([]byte, error) {
	return readTrustedConfigOwnedBy(path, 0)
}

// readTrustedConfigOwnedBy opens path without following symlinks and checks
// type, owner and mode on the opened descriptor, so a swap after the check
// cannot substitute another file.
func readTrustedConfigOwnedBy(path string, ownerUID uint32) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid config descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != ownerUID || stat.Mode&0o022 != 0 || stat.Size < 0 || stat.Size > maxConfigFileBytes {
		return nil, fmt.Errorf("%s is not a regular file owned by uid %d and writable only by its owner", path, ownerUID)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxConfigFileBytes {
		return nil, fmt.Errorf("%s exceeds the config size limit", path)
	}
	return payload, nil
}

func managedCertificateBase(name string) (string, bool) {
	for _, suffix := range []string{".key.plain", ".key.enc", ".crt", ".key"} {
		if base := strings.TrimSuffix(name, suffix); base != name && base != "" && certstore.SanitizeHost(base) == base {
			return base, true
		}
	}
	return "", false
}

func managedAuthFilePath(authDir, host string) string {
	return filepath.Join(authDir, "auth-"+certstore.SanitizeHost(host)+".htpasswd")
}

// legacyManagedAuthFilePath is where helpers before #147 wrote auth files. The
// proxy worker cannot read it, so it is only ever deleted.
func legacyManagedAuthFilePath(certificateDir, host string) string {
	return filepath.Join(certificateDir, "auth-"+certstore.SanitizeHost(host)+".htpasswd")
}

// managedAuthFileHost returns the sanitized host of an auth-<host>.htpasswd name.
func managedAuthFileHost(name string) (string, bool) {
	host, ok := strings.CutPrefix(name, "auth-")
	if !ok {
		return "", false
	}
	host, ok = strings.CutSuffix(host, ".htpasswd")
	if !ok || host == "" || certstore.SanitizeHost(host) != host {
		return "", false
	}
	return host, true
}

func managedClassOrder(class string) int {
	switch class {
	case "secret":
		return 0
	case "auth":
		return 1
	default:
		return 2
	}
}

// appendExistingDeletion schedules a deletion only when the target exists, so
// converged hosts keep a deletion-free plan (and pre-mutation validation).
func appendExistingDeletion(compilation *managedCompilation, deletion managedCompiledFile) error {
	if compilation.hasTarget(deletion.Path) {
		return nil
	}
	if _, err := os.Lstat(deletion.Path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect stale managed auth file: %w", err)
	}
	compilation.Files = append(compilation.Files, deletion)
	return nil
}

func (c managedCompilation) hasTarget(path string) bool {
	for _, file := range c.Files {
		if file.Path == path {
			return true
		}
	}
	return false
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
	if err := validateManagedCompilationTargets(compilation, a.layout); err != nil {
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

// validateManagedCompilationTargets also pins each secret-bearing class to its
// directory: secrets to CertificateDir, auth files to the auth directory.
func validateManagedCompilationTargets(compilation managedCompilation, layout ManagedApplyTargetConfig) error {
	if compilation.Files == nil || compilation.Links == nil {
		return fmt.Errorf("managed compilation has noncanonical collections")
	}
	totalReceiptContent := 0
	for _, file := range compilation.Files {
		if validatePrivatePath(file.Path) != nil || !validManagedFileClass(file.Class) {
			return fmt.Errorf("managed compilation contains an invalid file")
		}
		if _, ok := managedAuthFileHost(filepath.Base(file.Path)); file.Class == "auth" && (!ok || filepath.Dir(file.Path) != layout.AuthDir()) {
			return fmt.Errorf("managed auth file is outside the auth directory or has an unexpected name")
		}
		if file.Class == "secret" && filepath.Dir(file.Path) != layout.CertificateDir {
			return fmt.Errorf("managed secret is outside the certificate directory")
		}
		if file.Delete {
			if file.ResourceID != "" || file.Preserve || file.SHA256 != "" || file.Mode != 0 || file.GID != 0 || len(file.Content) != 0 {
				return fmt.Errorf("managed compilation contains an invalid file deletion")
			}
			continue
		}
		if !validDigest(file.SHA256) || !validManagedFileMode(file.Class, file.Mode) || (file.Class != "auth" && file.GID != 0) {
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

// isManagedAuthDeletion reports deletions of basic-auth user files, in auth/
// or in the pre-#147 certs/ location. Execute removes them after the reload.
func isManagedAuthDeletion(file managedCompiledFile) bool {
	if !file.Delete {
		return false
	}
	_, named := managedAuthFileHost(filepath.Base(file.Path))
	return file.Class == "auth" || (file.Class == "secret" && named)
}

func validManagedFileClass(class string) bool {
	return class == "vhost" || class == "secret" || class == "auth"
}

// validManagedFileMode pins each class to its modes. Auth files are the only
// group-readable class: root:<worker group> 0640.
func validManagedFileMode(class string, mode uint32) bool {
	if class == "auth" {
		return mode == 0o640
	}
	return mode == 0o600 || mode == 0o644
}

func (a *managedApplyAction) attestManagedArtifacts(compilation managedCompilation) ([]helperprotocol.ManagedArtifactReceipt, error) {
	if err := validateManagedCompilationTargets(compilation, a.layout); err != nil {
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
	if !file.Delete || !validManagedFileClass(file.Class) {
		return false, fmt.Errorf("invalid managed file deletion")
	}
	pending, err := managedFileChangePending(file, ownerUID)
	if err != nil || !pending {
		return false, err
	}
	dir := filepath.Dir(file.Path)
	if err := os.Remove(file.Path); err != nil {
		return false, err
	}
	return true, syncDirectory(dir)
}

func removeManagedLink(link managedCompiledLink, ownerUID uint32) (bool, error) {
	if !link.Delete {
		return false, fmt.Errorf("invalid managed activation deletion")
	}
	pending, err := managedLinkChangePending(link, ownerUID)
	if err != nil || !pending {
		return false, err
	}
	dir := filepath.Dir(link.Path)
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
	defer func() { _ = unix.Close(rootFD) }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil || rootStat.Uid != stagingRootUID || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Mode&0o007 != 0 {
		return nil, fmt.Errorf("staging root is not root-owned and bounded")
	}
	operationFD, err := openManagedComponentAt(rootFD, operationID, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(operationFD) }()
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

func captureManagedSnapshot(compilation managedCompilation, ownerUID uint32, layout ManagedApplyTargetConfig) (managedApplySnapshot, error) {
	if err := validateManagedCompilationTargets(compilation, layout); err != nil {
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
	case "vhost", "secret", "auth":
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

func installManagedFile(file managedCompiledFile, ownerUID uint32, layout ManagedApplyTargetConfig) (bool, error) {
	if err := validateManagedCompilationTargets(managedCompilation{Files: []managedCompiledFile{file}, Links: []managedCompiledLink{}}, layout); err != nil {
		return false, err
	}
	pending, err := managedFileChangePending(file, ownerUID)
	if err != nil || !pending {
		return false, err
	}
	dir := filepath.Dir(file.Path)
	if file.Class == "auth" {
		if err := ensureManagedAuthDirectory(dir, layout, ownerUID, file.GID); err != nil {
			return false, err
		}
		if err := validatePrivilegedManagedDirectory(dir, ownerUID); err != nil {
			return false, err
		}
		current, err := inspectManagedPath(file.Path, file.Class, "", ownerUID)
		if err != nil {
			return false, err
		}
		if managedFileConverged(current, file) {
			// Only the directory's group or mode needed repair.
			return true, nil
		}
	}
	tmp, err := os.CreateTemp(dir, ".nurproxy-helper-*")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	tmpInfo, err := tmp.Stat()
	if err != nil || fileOwnerUID(tmpInfo) != ownerUID {
		return false, fmt.Errorf("managed temporary file owner is not the privileged identity")
	}
	if file.Class == "auth" {
		if err := tmp.Chown(int(ownerUID), int(file.GID)); err != nil {
			return false, err
		}
	}
	if err := tmp.Chmod(os.FileMode(file.Mode)); err != nil {
		return false, err
	}
	if _, err := tmp.Write(file.Content); err != nil {
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, file.Path); err != nil {
		return false, err
	}
	if err := syncDirectory(dir); err != nil {
		return true, err
	}
	return true, nil
}

func installManagedLink(link managedCompiledLink, ownerUID uint32) (bool, error) {
	if validatePrivatePath(link.Path) != nil || validatePrivatePath(link.Target) != nil {
		return false, fmt.Errorf("invalid managed activation link")
	}
	pending, err := managedLinkChangePending(link, ownerUID)
	if err != nil || !pending {
		return false, err
	}
	dir := filepath.Dir(link.Path)
	tmp := filepath.Join(dir, fmt.Sprintf(".nurproxy-helper-link-%d", os.Getpid()))
	if err := os.Symlink(link.Target, tmp); err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Rename(tmp, link.Path); err != nil {
		return false, err
	}
	if err := syncDirectory(dir); err != nil {
		return true, err
	}
	return true, nil
}

func restoreManagedSnapshot(snapshot managedFileSnapshot, ownerUID uint32) error {
	dir := filepath.Dir(snapshot.Path)
	if !snapshot.Exists {
		// Nothing to undo while the target is still absent; its directory (for
		// example a freshly created auth/) may not exist either.
		if _, err := os.Lstat(snapshot.Path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
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
		defer func() { _ = os.Remove(tmp) }()
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

// ensureManagedAuthDirectory creates or repairs the auth directory as
// owner:<worker gid> 0750. Only that directory is opened to the worker group;
// its parent must stay privileged.
func ensureManagedAuthDirectory(dir string, layout ManagedApplyTargetConfig, ownerUID, gid uint32) error {
	if dir != layout.AuthDir() || validatePrivatePath(dir) != nil {
		return fmt.Errorf("refusing to manage %s as the auth directory", dir)
	}
	parent := filepath.Dir(dir)
	if err := validatePrivilegedManagedDirectory(parent, ownerUID); err != nil {
		return err
	}
	created := false
	if err := os.Mkdir(dir, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create managed auth directory: %w", err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open managed auth directory: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != ownerUID {
		return fmt.Errorf("managed auth directory is not owned by the configured privileged identity")
	}
	if stat.Gid != gid {
		if err := unix.Fchown(fd, int(ownerUID), int(gid)); err != nil {
			return fmt.Errorf("set managed auth directory group: %w", err)
		}
	}
	if stat.Mode&0o7777 != 0o750 {
		if err := unix.Fchmod(fd, 0o750); err != nil {
			return fmt.Errorf("set managed auth directory mode: %w", err)
		}
	}
	if created {
		return syncDirectory(parent)
	}
	return nil
}

func validatePrivilegedManagedDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || fileOwnerUID(info) != ownerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("managed destination directory is not owned by the configured privileged identity")
	}
	return nil
}
