// Package dnsname validates DNS names used by NurProxy, so malformed input is
// rejected at the API boundary instead of failing later at the DNS provider or
// when the agent renders proxy config.
package dnsname

import (
	"fmt"
	"strings"
)

// ValidateSubdomain checks that s is a valid subdomain label sequence to place
// under a managed zone (e.g. "jellyfin", "api.internal", or a leading "*" for a
// wildcard). It enforces the DNS label rules: each dot-separated label is 1–63
// characters of letters, digits, or hyphens, not starting or ending with a
// hyphen; the whole name is at most 253 characters. A single leading "*" label
// is allowed (wildcard); "*" anywhere else is rejected. Validation is
// case-insensitive.
func ValidateSubdomain(s string) error {
	if s == "" {
		return fmt.Errorf("subdomain is required")
	}
	if len(s) > 253 {
		return fmt.Errorf("subdomain is too long (max 253 characters)")
	}
	labels := strings.Split(s, ".")
	for i, label := range labels {
		if label == "*" && i == 0 {
			continue // a leading wildcard label is allowed
		}
		if err := validateLabel(label); err != nil {
			return fmt.Errorf("invalid subdomain %q: %w", s, err)
		}
	}
	return nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label (check for leading, trailing, or doubled dots)")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q exceeds 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q must not start or end with a hyphen", label)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return fmt.Errorf("label %q contains an invalid character %q (allowed: letters, digits, hyphen)", label, r)
		}
	}
	return nil
}
