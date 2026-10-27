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
	"syscall"

	"github.com/NurRobin/NurProxy/internal/agent/proxy"
	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

// managedCertificateSuffixes lists every on-disk file name a certificate store
// entry can have. A config that references any of them keeps the whole entry.
var managedCertificateSuffixes = []string{".crt", ".key", ".key.plain", ".key.enc"}

// survivingConfig is the proxy config that is still on disk after an apply,
// loaded so prune decisions can ask whether something still references a
// certificate or basic-auth file.
type survivingConfig struct {
	contents [][]byte
	// unscanned names surviving config files that could not be read in full
	// (larger than maxConfigFileBytes). While any exist, nothing is pruned,
	// because a reference in them cannot be ruled out.
	unscanned []string
}

// loadSurvivingConfig reads every vhost the compilation writes or preserves,
// plus every regular file in the available/enabled directories that the
// compilation neither writes nor deletes. Symlinks in those directories are
// followed to regular files outside the already scanned set, as long as the
// target is not owned by the unprivileged agent (the fingerprint's trust
// rule). The auth and certificate directories are never scanned: they hold
// referenced files, not config.
func (a *managedApplyAction) loadSurvivingConfig(compilation managedCompilation) (survivingConfig, error) {
	var config survivingConfig
	touched := make(map[string]struct{}, len(compilation.Files))
	for _, file := range compilation.Files {
		touched[file.Path] = struct{}{}
		if file.Class == "vhost" && !file.Delete {
			config.contents = append(config.contents, file.Content)
		}
	}
	scanned := make(map[string]struct{})
	scan := func(path, display string) error {
		if _, done := scanned[path]; done {
			return nil
		}
		scanned[path] = struct{}{}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect config file for prune references: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxConfigFileBytes {
			config.unscanned = append(config.unscanned, display)
			return nil
		}
		content, err := readNoFollowFile(path, info.Size())
		if err != nil {
			return fmt.Errorf("read config file for prune references: %w", err)
		}
		config.contents = append(config.contents, content)
		return nil
	}
	var links []string
	for _, dir := range []string{a.layout.AvailableDir, a.layout.EnabledDir} {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return config, fmt.Errorf("read managed config directory for prune references: %w", err)
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if _, ok := touched[path]; ok {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				links = append(links, path)
				continue
			}
			if err := scan(path, entry.Name()); err != nil {
				return config, err
			}
		}
	}
	for _, link := range links {
		target, err := filepath.EvalSymlinks(link)
		if err != nil {
			continue // dangling activation link: nothing to load
		}
		if _, ok := touched[target]; ok {
			continue
		}
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid == a.agentUID {
			continue
		}
		if err := scan(target, filepath.Base(link)+" -> "+target); err != nil {
			return config, err
		}
	}
	sort.Strings(config.unscanned)
	return config, nil
}

// references reports whether surviving config may still use a file with the
// given base name. It matches "/<name>" so any absolute or differently spelled
// path (double slashes, symlinked directories, the pre-#147 certs/ location of
// an auth file) still counts. A false positive keeps the file for as long as
// the matching config exists; it never deletes anything. With unscanned files
// every name counts as referenced.
func (c survivingConfig) references(name string) bool {
	if len(c.unscanned) > 0 {
		return true
	}
	needle := []byte("/" + name)
	for _, content := range c.contents {
		if bytes.Contains(content, needle) {
			return true
		}
	}
	return false
}

// referencesCertificate reports whether any store file of base is referenced.
func (c survivingConfig) referencesCertificate(base string) bool {
	for _, suffix := range managedCertificateSuffixes {
		if c.references(base + suffix) {
			return true
		}
	}
	return false
}

// leftoverManagedVhosts lists NurProxy-named vhost files in the available
// directory that are neither written nor deleted by this apply: routes the
// orchestrator did not send this time, and tombstoned vhosts the helper
// refused to delete because they carry no NurProxy marker. They are reported
// in every receipt while they exist. Auth and certificate files are never
// listed; they live in other directories.
func (a *managedApplyAction) leftoverManagedVhosts(compilation managedCompilation) ([]string, error) {
	entries, err := os.ReadDir(a.layout.AvailableDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed config directory for leftovers: %w", err)
	}
	touched := make(map[string]struct{}, len(compilation.Files))
	for _, file := range compilation.Files {
		touched[file.Path] = struct{}{}
	}
	prefix := strings.TrimSuffix(managedFileName(a.target.Kind, "x"), "x.conf")
	var leftovers []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".conf") {
			continue
		}
		if _, ok := touched[filepath.Join(a.layout.AvailableDir, name)]; ok {
			continue
		}
		leftovers = append(leftovers, name)
	}
	sort.Strings(leftovers)
	return leftovers, nil
}

// retentionNote is appended to the receipt message so the operator can see
// what the helper deliberately left in place, and why. Execute and Converged
// both use it, so a converged receipt carries the same notes.
func (c managedCompilation) retentionNote() string {
	note := ""
	if len(c.UnscannedConfigs) > 0 {
		note += fmt.Sprintf("; prune skipped, %d config file(s) too large to scan for references: %s",
			len(c.UnscannedConfigs), boundedList(c.UnscannedConfigs))
	} else {
		if len(c.RetainedCertificates) > 0 {
			note += fmt.Sprintf("; kept %d unretained certificate(s) still referenced by proxy config: %s",
				len(c.RetainedCertificates), boundedList(c.RetainedCertificates))
		}
		if len(c.RetainedAuthFiles) > 0 {
			note += fmt.Sprintf("; kept %d unrouted basic-auth file(s) still referenced by proxy config: %s",
				len(c.RetainedAuthFiles), boundedList(c.RetainedAuthFiles))
		}
	}
	if len(c.LeftoverVhosts) > 0 {
		note += fmt.Sprintf("; %s%s", helperprotocol.ManagedLeftoverVhostsNote, boundedList(c.LeftoverVhosts))
	}
	return note
}

func boundedList(items []string) string {
	const shown = 10
	if len(items) <= shown {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:shown], ", ") + fmt.Sprintf(" and %d more", len(items)-shown)
}

// unmarkedRegularFile reports whether path is an existing regular file that
// does not carry the NurProxy managed-artifact marker, or is too large to
// check. Absent files and symlinks return false and are left to the normal
// provenance checks.
func unmarkedRegularFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if info.Size() > maxConfigFileBytes {
		return true, nil
	}
	content, err := readNoFollowFile(path, info.Size())
	if err != nil {
		return false, err
	}
	return !proxy.HasManagedArtifactMarker(string(content)), nil
}
