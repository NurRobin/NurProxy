//go:build linux

package helper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
)

// managedCertificateSuffixes lists every on-disk file name a certificate store
// entry can have. A config that references any of them keeps the whole entry.
var managedCertificateSuffixes = []string{".crt", ".key", ".key.plain", ".key.enc"}

// referencedCertificateBases returns the subset of candidate certificate bases
// that a proxy config file which survives this apply still references.
//
// Surviving config is: every vhost the compilation writes or preserves, plus
// every regular file in the available/enabled directories that the compilation
// neither writes nor deletes. Activation symlinks are skipped because they
// point at files that are already scanned in the available directory.
func (a *managedApplyAction) referencedCertificateBases(compilation managedCompilation, candidates []string) ([]string, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	touched := make(map[string]struct{}, len(compilation.Files))
	var contents [][]byte
	for _, file := range compilation.Files {
		touched[file.Path] = struct{}{}
		if file.Class == "vhost" && !file.Delete {
			contents = append(contents, file.Content)
		}
	}
	for _, dir := range []string{a.layout.AvailableDir, a.layout.EnabledDir} {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read managed config directory for certificate references: %w", err)
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if _, ok := touched[path]; ok {
				continue
			}
			info, err := os.Lstat(path)
			if err != nil {
				return nil, fmt.Errorf("inspect managed config file for certificate references: %w", err)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if info.Size() > maxConfigFileBytes {
				return nil, fmt.Errorf("managed config file %s is too large to prove certificate references", entry.Name())
			}
			content, err := readNoFollowFile(path, info.Size())
			if err != nil {
				return nil, fmt.Errorf("read managed config file for certificate references: %w", err)
			}
			contents = append(contents, content)
		}
	}
	var referenced []string
	for _, base := range candidates {
		if certificateBaseReferenced(a.layout.CertificateDir, base, contents) {
			referenced = append(referenced, base)
		}
	}
	sort.Strings(referenced)
	return referenced, nil
}

// retentionNote is appended to the receipt message so the operator can see
// what the helper deliberately left in place, and why.
func (c managedCompilation) retentionNote() string {
	note := ""
	if len(c.RetainedCertificates) > 0 {
		note += fmt.Sprintf("; kept %d unretained certificate(s) still referenced by proxy config: %s",
			len(c.RetainedCertificates), boundedHostList(c.RetainedCertificates))
	}
	if len(c.UnmarkedDeletions) > 0 {
		note += fmt.Sprintf("; left %d tombstoned vhost(s) without NurProxy marker in place, remove manually: %s",
			len(c.UnmarkedDeletions), boundedHostList(c.UnmarkedDeletions))
	}
	return note
}

func boundedHostList(hosts []string) string {
	const shown = 10
	if len(hosts) <= shown {
		return strings.Join(hosts, ", ")
	}
	return strings.Join(hosts[:shown], ", ") + fmt.Sprintf(" and %d more", len(hosts)-shown)
}

// unmarkedRegularFile reports whether path is an existing regular file that
// does not carry the NurProxy managed-artifact marker. Anything else (absent,
// symlink, marked) returns false and is left to the normal provenance checks.
func unmarkedRegularFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigFileBytes {
		return false, nil
	}
	content, err := readNoFollowFile(path, info.Size())
	if err != nil {
		return false, err
	}
	return !proxy.HasManagedArtifactMarker(string(content)), nil
}

func certificateBaseReferenced(certificateDir, base string, contents [][]byte) bool {
	for _, suffix := range managedCertificateSuffixes {
		needle := []byte(filepath.Join(certificateDir, base+suffix))
		for _, content := range contents {
			if bytes.Contains(content, needle) {
				return true
			}
		}
	}
	return false
}
