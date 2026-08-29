package nginx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func (b *Backend) InspectRecovery(_ context.Context, desired proxy.RecoveryDesired) ([]proxy.RecoveryCandidate, error) {
	available, err := canonicalRecoveryDir(b.layout.Available)
	if err != nil {
		return nil, err
	}
	enabled := ""
	if !b.layout.IsConfD() {
		enabled, err = canonicalRecoveryDir(b.layout.Enabled)
		if err != nil {
			return nil, err
		}
	}
	keep := canonicalRecoverySet(desired.KeepTargets, available)
	active := canonicalRecoveryPaths(desired.ActiveOperationPaths, available)
	entries, err := os.ReadDir(available)
	if err != nil {
		return nil, err
	}
	var candidates []proxy.RecoveryCandidate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(available, name)
		if strings.HasSuffix(name, tempSuffix) {
			if _, busy := active[path]; busy || !strings.HasPrefix(name, managedPrefix) || !strings.HasSuffix(name, confSuffix+tempSuffix) {
				continue
			}
			identity, marked, captureErr := proxy.CaptureManagedRecoveryPath(path)
			if captureErr != nil || !marked {
				continue
			}
			host := recoveryHostFromFileBase(strings.TrimSuffix(strings.TrimPrefix(name, managedPrefix), confSuffix+tempSuffix))
			candidates = append(candidates, proxy.NewRecoveryCandidate(recoverymodel.ActionRemoveManagedTemp, host, identity))
			continue
		}
		if !IsManagedFile(name) {
			continue
		}
		identity, marked, captureErr := proxy.CaptureManagedRecoveryPath(path)
		if captureErr != nil || !marked {
			continue
		}
		if _, wanted := keep[path]; wanted {
			continue
		}
		host := recoveryHostFromFileBase(strings.TrimSuffix(strings.TrimPrefix(name, managedPrefix), confSuffix))
		identities := []proxy.RecoveryPathIdentity{identity}
		if enabled != "" {
			linkPath := filepath.Join(enabled, name)
			if linkIdentity, linkErr := proxy.CaptureRecoveryPath(linkPath); linkErr == nil && linkIdentity.Exists && recoveryLinkTargets(linkIdentity, enabled, path) {
				identities = append(identities, linkIdentity)
			}
		}
		identities = appendExistingRecoveryPaths(identities, strings.TrimSuffix(path, confSuffix)+htpasswdSuffix)
		if b.certs != nil {
			identities = appendExistingRecoveryPaths(identities, b.certs.AllRecoveryPaths(host)...)
		}
		candidates = append(candidates, proxy.NewRecoveryCandidate(recoverymodel.ActionPruneManagedOrphan, host, identities...))
	}
	certCandidates, err := b.inspectCertRecovery(desired.KeepCertHosts)
	if err != nil {
		return nil, err
	}
	return append(candidates, certCandidates...), nil
}

func (b *Backend) ExecuteRecovery(_ context.Context, candidate proxy.RecoveryCandidate, bundles map[string]proxy.CertBundle) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	switch candidate.Action {
	case recoverymodel.ActionPruneManagedOrphan, recoverymodel.ActionRemoveManagedTemp:
		if err := proxy.RemoveRecoveryCandidatePaths(candidate); err != nil {
			return err
		}
	case recoverymodel.ActionRematerializeCertBundle:
		if err := recheckRecoveryIdentities(candidate); err != nil {
			return err
		}
		bundle, ok := bundles[candidate.Host]
		if !ok || bundle.Host != candidate.Host {
			return fmt.Errorf("nginx recovery bundle unavailable")
		}
		if b.certs == nil {
			return proxy.ErrRecoveryUnsupported
		}
		materialize := bundle.MaterializeKey || recoveryCandidatePathExists(candidate, b.certs.RecoveryPaths(candidate.Host).RuntimeKeyPath)
		if err := b.certs.InstallRecoveryBundle(certstore.Bundle{Host: bundle.Host, CertPEM: bundle.CertPEM, KeyPEM: bundle.KeyPEM, MaterializePlain: materialize}, recoveryCandidateWriter(candidate)); err != nil {
			return err
		}
	case recoverymodel.ActionRematerializeRuntimeKey:
		if b.certs == nil {
			return proxy.ErrRecoveryUnsupported
		}
		if err := recheckRecoveryIdentities(candidate); err != nil {
			return err
		}
		if err := b.certs.RefreshRuntimeKey(candidate.Host, recoveryCandidateWriter(candidate)); err != nil {
			return err
		}
	default:
		return proxy.ErrRecoveryUnsupported
	}
	return nil
}

func (b *Backend) ReloadRecovery(ctx context.Context) error {
	if b.runner == nil {
		return nil
	}
	if err := b.runner.Reload(ctx); err != nil {
		return proxy.NewFailure(proxy.KindNginx, proxy.FailurePhaseReload, err.Error(), err)
	}
	return nil
}

func (b *Backend) inspectCertRecovery(hosts []string) ([]proxy.RecoveryCandidate, error) {
	if b.certs == nil {
		return nil, nil
	}
	var candidates []proxy.RecoveryCandidate
	for _, host := range hosts {
		inspection, err := b.certs.InspectRecovery(host)
		if err != nil {
			return nil, err
		}
		action := recoverymodel.Action("")
		switch {
		case !inspection.BundlePresent || !inspection.BundleValid:
			action = recoverymodel.ActionRematerializeCertBundle
		case inspection.RuntimeKeyState == certstore.RuntimeKeyMissing || inspection.RuntimeKeyState == certstore.RuntimeKeyMismatch:
			action = recoverymodel.ActionRematerializeRuntimeKey
		}
		if action == "" {
			continue
		}
		identities, err := captureRecoveryPaths(inspection.CertPath, inspection.SourceKeyPath, inspection.RuntimeKeyPath)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, proxy.NewRecoveryCandidate(action, host, identities...))
	}
	return candidates, nil
}

func canonicalRecoveryDir(path string) (string, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("invalid recovery layout")
	}
	return canonical, nil
}

func canonicalRecoverySet(targets []proxy.Target, available string) map[string]struct{} {
	set := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.Kind != proxy.TargetKindFile || !filepath.IsAbs(target.Path) || filepath.Clean(target.Path) != target.Path {
			continue
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(target.Path))
		if err == nil && parent == available {
			set[filepath.Join(parent, filepath.Base(target.Path))] = struct{}{}
		}
	}
	return set
}

func canonicalRecoveryPaths(paths []string, available string) map[string]struct{} {
	set := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			continue
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err == nil && parent == available {
			set[filepath.Join(parent, filepath.Base(path))] = struct{}{}
		}
	}
	return set
}

func recoveryLinkTargets(identity proxy.RecoveryPathIdentity, parent, target string) bool {
	if identity.SymlinkTarget == "" {
		return false
	}
	resolved := identity.SymlinkTarget
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(parent, resolved)
	}
	return filepath.Clean(resolved) == target
}

func recoveryHostFromFileBase(base string) string {
	if strings.HasPrefix(base, "_wildcard.") {
		return "*." + strings.TrimPrefix(base, "_wildcard.")
	}
	return base
}

func appendExistingRecoveryPaths(identities []proxy.RecoveryPathIdentity, paths ...string) []proxy.RecoveryPathIdentity {
	seen := make(map[string]struct{}, len(identities)+len(paths))
	for _, identity := range identities {
		seen[identity.Path] = struct{}{}
	}
	for _, path := range paths {
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		identity, err := proxy.CaptureRecoveryPath(path)
		if err == nil && identity.Exists {
			identities = append(identities, identity)
			seen[path] = struct{}{}
		}
	}
	return identities
}

func captureRecoveryPaths(paths ...string) ([]proxy.RecoveryPathIdentity, error) {
	identities := make([]proxy.RecoveryPathIdentity, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		identity, err := proxy.CaptureRecoveryPath(path)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
		seen[path] = struct{}{}
	}
	return identities, nil
}

func recheckRecoveryIdentities(candidate proxy.RecoveryCandidate) error {
	if len(candidate.Paths) != len(candidate.Identities) {
		return errors.New("recovery identity count mismatch")
	}
	for i, identity := range candidate.Identities {
		if candidate.Paths[i] != identity.Path {
			return errors.New("recovery identity path mismatch")
		}
		if err := identity.Recheck(); err != nil {
			return err
		}
	}
	return nil
}

func recoveryCandidateWriter(candidate proxy.RecoveryCandidate) certstore.RecoveryWriteFunc {
	identities := make(map[string]proxy.RecoveryPathIdentity, len(candidate.Identities))
	for _, identity := range candidate.Identities {
		identities[identity.Path] = identity
	}
	return func(path string, data []byte, mode os.FileMode) error {
		identity, ok := identities[path]
		if !ok {
			return fmt.Errorf("nginx recovery destination was not authorized")
		}
		return proxy.ReplaceRecoveryPath(identity, data, mode)
	}
}

func recoveryCandidatePathExists(candidate proxy.RecoveryCandidate, path string) bool {
	for _, identity := range candidate.Identities {
		if identity.Path == path {
			return identity.Exists
		}
	}
	return false
}
