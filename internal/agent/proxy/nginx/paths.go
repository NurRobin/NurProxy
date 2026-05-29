package nginx

import (
	"path/filepath"
	"strings"
)

// managedPrefix namespaces the files this backend owns under sites-available /
// sites-enabled. A NurProxy-managed vhost lives at
// sites-available/nurproxy-<domain>.conf; the prefix lets ReadManaged and drift
// checks tell our files apart from the operator's hand-rolled ones (§4, §11).
const managedPrefix = "nurproxy-"

// confSuffix is the file extension for a managed vhost file.
const confSuffix = ".conf"

// Layout resolves the Debian/Ubuntu nginx directory pair the backend writes to
// (§9): sites-available holds the real files, sites-enabled holds symlinks nginx
// includes. Both are derived from the config dir the agent detected. For the
// canonical Debian layout ConfigDir is /etc/nginx/sites-available, so Enabled is
// its sibling sites-enabled; when ConfigDir is the nginx root we append the
// standard subdirectories.
type Layout struct {
	// Available is the directory holding the real managed vhost files
	// (sites-available).
	Available string
	// Enabled is the directory holding the activation symlinks (sites-enabled).
	Enabled string
}

// ResolveLayout derives the sites-available / sites-enabled pair from a detected
// config dir. It is pure (string manipulation only) so the path logic is
// unit-testable without a host. Three cases:
//
//   - configDir ends in "sites-available" → Enabled is its sibling sites-enabled.
//   - configDir ends in "sites-enabled" → Available is its sibling sites-available.
//   - otherwise (e.g. /etc/nginx) → append sites-available / sites-enabled.
func ResolveLayout(configDir string) Layout {
	clean := filepath.Clean(configDir)
	base := filepath.Base(clean)
	parent := filepath.Dir(clean)

	switch base {
	case "sites-available":
		return Layout{Available: clean, Enabled: filepath.Join(parent, "sites-enabled")}
	case "sites-enabled":
		return Layout{Available: filepath.Join(parent, "sites-available"), Enabled: clean}
	default:
		return Layout{
			Available: filepath.Join(clean, "sites-available"),
			Enabled:   filepath.Join(clean, "sites-enabled"),
		}
	}
}

// ManagedFileName returns the file name a managed vhost for host occupies:
// nurproxy-<host>.conf. The host is sanitized to a safe file-name base so a
// crafted host can never escape the config dir or collide with a path separator.
// It is pure and unit-testable.
func ManagedFileName(host string) string {
	return managedPrefix + sanitizeHostForFile(host) + confSuffix
}

// AvailablePath is the absolute path of the managed vhost file for host in the
// sites-available directory.
func (l Layout) AvailablePath(host string) string {
	return filepath.Join(l.Available, ManagedFileName(host))
}

// EnabledPath is the absolute path of the activation symlink for host in the
// sites-enabled directory.
func (l Layout) EnabledPath(host string) string {
	return filepath.Join(l.Enabled, ManagedFileName(host))
}

// IsManagedFile reports whether a file name (not a full path) is one this
// backend owns — used by ReadManaged and drift checks to skip the operator's
// own vhosts. It is pure and unit-testable.
func IsManagedFile(name string) bool {
	return strings.HasPrefix(name, managedPrefix) && strings.HasSuffix(name, confSuffix)
}

// sanitizeHostForFile turns an FQDN into a safe file-name component, mapping a
// leading wildcard "*." to "_wildcard." and stripping path separators / parent
// refs so the resulting name stays inside the config dir. It mirrors the cert
// store's host sanitation so a host maps to a consistent base everywhere.
func sanitizeHostForFile(host string) string {
	h := strings.TrimSpace(host)
	h = strings.ReplaceAll(h, "*.", "_wildcard.")
	h = strings.ReplaceAll(h, "/", "_")
	h = strings.ReplaceAll(h, "\\", "_")
	h = strings.ReplaceAll(h, "..", "_")
	return h
}
