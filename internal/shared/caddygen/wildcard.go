package caddygen

import (
	"errors"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/models"
	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

// ZoneWildcardHost is the certificate store key of a zone's shared wildcard
// certificate: "*.<zone>". It never collides with the apex domain's per-host
// certificate, which is keyed by the bare zone name.
func ZoneWildcardHost(zoneName string) string {
	return "*." + strings.TrimSuffix(zoneName, ".")
}

// ValidateTLSWildcard refuses a TLSWildcard opt-in the shared zone certificate
// cannot cover. "*.<zone>" matches exactly one label below the apex, so the
// apex itself and deeper names ("a.b.<zone>") are rejected, and only central
// TLS serves a provided certificate at all. A domain that did not opt in is
// always valid.
func ValidateTLSWildcard(d models.Domain) error {
	if !d.ProxyConfig.TLSWildcard {
		return nil
	}
	if d.IsApex() || d.Subdomain == "" {
		return errors.New("tls_wildcard: the zone apex is not covered by a *.<zone> certificate; keep its own certificate")
	}
	if strings.Contains(d.Subdomain, ".") {
		return errors.New("tls_wildcard: only a single label directly below the zone can use the zone wildcard certificate (e.g. app.example.com, not app.sub.example.com)")
	}
	if TLSPolicyForDomain(d) != proxymodel.TLSPolicyCentral {
		return errors.New("tls_wildcard: requires central TLS (tls_policy central and ssl_mode not off)")
	}
	return nil
}

// WildcardCertHost returns the store key of the zone wildcard certificate the
// domain is served with, or "" when it uses a per-host certificate: the domain
// must opt in and pass ValidateTLSWildcard.
func WildcardCertHost(d models.Domain, zoneName string) string {
	if !d.ProxyConfig.TLSWildcard || zoneName == "" || ValidateTLSWildcard(d) != nil {
		return ""
	}
	return ZoneWildcardHost(zoneName)
}
