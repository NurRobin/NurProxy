package caddy

import (
	"context"
	"errors"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/agent/proxy/certstore"
	"github.com/NurRobin/NurProxy/internal/shared/recoverymodel"
)

func (b *Backend) InspectRecovery(_ context.Context, desired proxy.RecoveryDesired) ([]proxy.RecoveryCandidate, error) {
	if b.certs == nil {
		return nil, nil
	}
	var candidates []proxy.RecoveryCandidate
	for _, host := range desired.KeepCertHosts {
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

func (b *Backend) ExecuteRecovery(ctx context.Context, candidate proxy.RecoveryCandidate, bundles map[string]proxy.CertBundle) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	if candidate.Action != recoverymodel.ActionRematerializeCertBundle && candidate.Action != recoverymodel.ActionRematerializeRuntimeKey {
		return proxy.ErrRecoveryUnsupported
	}
	if b.certs == nil {
		return proxy.ErrRecoveryUnsupported
	}
	if err := recheckRecoveryIdentities(candidate); err != nil {
		return err
	}
	switch candidate.Action {
	case recoverymodel.ActionRematerializeCertBundle:
		bundle, ok := bundles[candidate.Host]
		if !ok || bundle.Host != candidate.Host {
			return fmt.Errorf("caddy recovery bundle unavailable")
		}
		if err := b.certs.InstallRecoveryBundle(certstore.Bundle{Host: bundle.Host, CertPEM: bundle.CertPEM, KeyPEM: bundle.KeyPEM, MaterializePlain: bundle.MaterializeKey}); err != nil {
			return err
		}
	case recoverymodel.ActionRematerializeRuntimeKey:
		if err := b.certs.RefreshRuntimeKey(candidate.Host); err != nil {
			return err
		}
	}
	return b.Validate(ctx)
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
