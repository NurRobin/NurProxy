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

// confSuffix is the file extension for a managed vhost file. Both Debian
// (sites-available) and RHEL (conf.d) use a .conf extension; on RHEL conf.d only
// *.conf files are auto-included, so the suffix is load-bearing there.
const confSuffix = ".conf"

// Layout resolves the nginx directory layout the backend writes to (§9). nginx
// has two on-disk conventions, mirroring Apache:
//
//   - Debian/Ubuntu: real files in /etc/nginx/sites-available, activated by a
//     symlink in /etc/nginx/sites-enabled (what the distro's include glob picks
//     up). Enabled is non-empty for this layout.
//   - RHEL/Fedora: a flat /etc/nginx/conf.d where every *.conf is auto-included
//     by the stock `include /etc/nginx/conf.d/*.conf;`; there is no
//     enable/disable symlink step. Enabled is empty for this layout.
//
// The agent's nginx backend keys its symlink behavior off whether Enabled is
// set: with a sites-enabled dir it symlinks (Debian), without one the file's
// presence in conf.d is the activation (RHEL).
type Layout struct {
	// Available is the directory holding the real managed vhost files
	// (sites-available on Debian, conf.d on RHEL).
	Available string
	// Enabled is the directory holding the activation symlinks (sites-enabled on
	// Debian). Empty for the RHEL conf.d layout, where presence == enabled.
	Enabled string
}

// IsConfD reports whether this is the flat RHEL/Fedora conf.d layout (no separate
// enable step). True when there is no sites-enabled directory.
func (l Layout) IsConfD() bool { return l.Enabled == "" }

// ResolveLayout derives the nginx directory layout from a detected config dir.
// It is pure (string manipulation only) so the path logic is unit-testable
// without a host. Cases:
//
//   - configDir ends in "sites-available" → Debian; Enabled is sibling
//     sites-enabled.
//   - configDir ends in "sites-enabled" → Debian; Available is sibling
//     sites-available.
//   - configDir ends in "conf.d" → RHEL/Fedora flat layout; Enabled empty.
//   - otherwise (e.g. the /etc/nginx root) → default to the Debian
//     sites-available / sites-enabled pair.
func ResolveLayout(configDir string) Layout {
	clean := filepath.Clean(configDir)
	base := filepath.Base(clean)
	parent := filepath.Dir(clean)

	switch base {
	case "sites-available":
		return Layout{Available: clean, Enabled: filepath.Join(parent, "sites-enabled")}
	case "sites-enabled":
		return Layout{Available: filepath.Join(parent, "sites-available"), Enabled: clean}
	case "conf.d":
		// RHEL/Fedora: managed files live in conf.d, no enable step.
		return Layout{Available: clean, Enabled: ""}
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
// sites-enabled directory. Meaningless (empty Enabled) on the RHEL conf.d layout.
func (l Layout) EnabledPath(host string) string {
	if l.Enabled == "" {
		return ""
	}
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
