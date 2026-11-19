package db

import (
	"errors"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/provider"
)

// ErrProxiedUnsupported is returned by ValidateDomainProxied when a domain asks
// for a proxied record it cannot have. Callers map it to a 400.
var ErrProxiedUnsupported = errors.New("proxied not supported")

// ValidateDomainProxied checks a domain's requested proxy setting (#126).
// Leaving it unset or setting it to false is always allowed. true needs a
// served domain (cert-only domains do not manage public DNS) in a zone whose
// DNS provider supports proxying (Cloudflare).
func (d *DB) ValidateDomainProxied(zoneID string, certOnly bool, proxied *bool) error {
	if proxied == nil || !*proxied {
		return nil
	}
	if certOnly {
		return fmt.Errorf("%w: cert-only domains do not manage a public DNS record", ErrProxiedUnsupported)
	}
	zone, err := d.GetZone(zoneID)
	if err != nil {
		return fmt.Errorf("resolving zone: %w", err)
	}
	prov, err := d.GetProvider(zone.ProviderID)
	if err != nil {
		return fmt.Errorf("resolving provider for zone %s: %w", zone.Name, err)
	}
	if !provider.SupportsProxied(prov.Type) {
		return fmt.Errorf("%w: zone %s uses DNS provider %q, which has no proxy mode (only Cloudflare does)", ErrProxiedUnsupported, zone.Name, prov.Type)
	}
	return nil
}
