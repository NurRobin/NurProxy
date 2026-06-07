// Package certstore writes centrally-issued TLS cert bundles to disk on the agent
// (§7). The orchestrator provisions certificates centrally (DNS-01 via lego) and
// pushes them down the agent-initiated stream; the agent's Proxy.InstallCerts
// delegates here to write the leaf+chain and the private key into the backend's
// cert directory, BEFORE the referencing config is applied (preflight ordering,
// §5).
//
// Private keys are sensitive, so they are encrypted at rest on the agent with the
// same AES-256-GCM primitive the orchestrator uses (invariant: keys never leave a
// host in plaintext). The leaf+chain is public and written as plain PEM so the
// proxy can read it directly. Writes are atomic (temp file + rename) so a crash
// mid-write never leaves a proxy referencing a half-written cert.
//
// This package is the testable core of InstallCerts: it takes a bundle plus a
// destination directory and an at-rest key, and produces files. No real proxy or
// network is needed to test it.
package certstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

const (
	// certSuffix is appended to the sanitized host for the public leaf+chain file.
	certSuffix = ".crt"
	// keySuffix is appended for the at-rest-encrypted private key file. The ".enc"
	// marks that the contents are AES-256-GCM ciphertext, not plaintext PEM.
	keySuffix = ".key.enc"
	// keyPlainSuffix is used when no at-rest key is configured: a plaintext PEM key.
	keyPlainSuffix = ".key"
	// keyMaterializedSuffix is the decrypted plaintext key CertPaths materializes
	// next to the ciphertext so a proxy can read it (see CertPaths). It must be
	// deleted alongside the other artifacts on Remove — a lingering decrypted key
	// negates the at-rest encryption.
	keyMaterializedSuffix = ".key.plain"

	// dirMode is the cert directory's mode: owner-only (keys live here).
	dirMode = 0o700
	// certMode is the public cert's mode (world-readable is fine; it is public).
	certMode = 0o644
	// keyMode is the private key's mode: owner read/write only.
	keyMode = 0o600
)

// Bundle is a leaf certificate plus its private key (PEM) destined for disk. It
// mirrors the agent-side proxy.CertBundle but is decoupled so this package has no
// dependency on the proxy package (keeping the testable core import-light).
type Bundle struct {
	// Host is the FQDN the certificate covers; the file names derive from it.
	Host string
	// CertPEM is the leaf certificate plus chain (public).
	CertPEM []byte
	// KeyPEM is the private key (sensitive; encrypted at rest if a key is given).
	KeyPEM []byte
}

// InstalledPaths reports where a bundle's files landed, returned by Install so a
// backend can reference them in rendered config.
type InstalledPaths struct {
	// CertPath is the public leaf+chain file path.
	CertPath string
	// KeyPath is the private key file path (encrypted at rest unless Encrypted is
	// false).
	KeyPath string
	// Encrypted reports whether the key on disk is AES-256-GCM ciphertext (true) or
	// plaintext PEM (false, when no at-rest key was configured).
	Encrypted bool
}

// Store writes cert bundles into a directory, encrypting private keys at rest with
// the configured AES-256 key. A nil/empty encryptKey writes plaintext keys (the
// caller is expected to log a warning); this keeps the agent functional on hosts
// that have not provisioned an at-rest key rather than failing the whole apply.
type Store struct {
	dir        string
	encryptKey []byte
}

// New constructs a Store rooted at dir. encryptKey is the agent-local AES-256 key
// for at-rest key encryption; pass nil to write plaintext keys.
func New(dir string, encryptKey []byte) *Store {
	return &Store{dir: dir, encryptKey: encryptKey}
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Install writes a single bundle to disk atomically and returns the resulting
// paths. The public cert is written as plain PEM; the private key is encrypted at
// rest when an at-rest key is configured. The cert directory is created with
// owner-only permissions if missing.
func (s *Store) Install(b Bundle) (InstalledPaths, error) {
	if b.Host == "" {
		return InstalledPaths{}, fmt.Errorf("certstore: bundle has no host")
	}
	if len(b.CertPEM) == 0 {
		return InstalledPaths{}, fmt.Errorf("certstore: bundle %q has empty cert", b.Host)
	}
	if len(b.KeyPEM) == 0 {
		return InstalledPaths{}, fmt.Errorf("certstore: bundle %q has empty key", b.Host)
	}
	if s.dir == "" {
		return InstalledPaths{}, fmt.Errorf("certstore: no cert directory configured")
	}

	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return InstalledPaths{}, fmt.Errorf("certstore: creating cert dir %q: %w", s.dir, err)
	}

	base := SanitizeHost(b.Host)
	certPath := filepath.Join(s.dir, base+certSuffix)

	encrypted := len(s.encryptKey) > 0
	keyName := base + keyPlainSuffix
	keyBytes := b.KeyPEM
	if encrypted {
		keyName = base + keySuffix
		ct, err := crypto.Encrypt(s.encryptKey, b.KeyPEM)
		if err != nil {
			return InstalledPaths{}, fmt.Errorf("certstore: encrypting key for %q: %w", b.Host, err)
		}
		keyBytes = ct
	}
	keyPath := filepath.Join(s.dir, keyName)

	if err := writeAtomic(certPath, b.CertPEM, certMode); err != nil {
		return InstalledPaths{}, fmt.Errorf("certstore: writing cert for %q: %w", b.Host, err)
	}
	if err := writeAtomic(keyPath, keyBytes, keyMode); err != nil {
		return InstalledPaths{}, fmt.Errorf("certstore: writing key for %q: %w", b.Host, err)
	}

	return InstalledPaths{CertPath: certPath, KeyPath: keyPath, Encrypted: encrypted}, nil
}

// ReadKey reads back a host's private key, decrypting it if it was stored
// encrypted at rest. It is the inverse of Install for the key half, used by
// backends that must hand the proxy plaintext key material (e.g. feeding Caddy's
// admin API) without leaving plaintext on disk.
func (s *Store) ReadKey(host string) ([]byte, error) {
	base := SanitizeHost(host)
	if len(s.encryptKey) > 0 {
		ct, err := os.ReadFile(filepath.Join(s.dir, base+keySuffix))
		if err != nil {
			return nil, fmt.Errorf("certstore: reading encrypted key for %q: %w", host, err)
		}
		pt, err := crypto.Decrypt(s.encryptKey, ct)
		if err != nil {
			return nil, fmt.Errorf("certstore: decrypting key for %q: %w", host, err)
		}
		return pt, nil
	}
	pt, err := os.ReadFile(filepath.Join(s.dir, base+keyPlainSuffix))
	if err != nil {
		return nil, fmt.Errorf("certstore: reading key for %q: %w", host, err)
	}
	return pt, nil
}

// ProxyPaths reports the file paths a proxy must reference to serve a host's
// provided cert: the public leaf+chain and a PLAINTEXT private key the proxy can
// read directly. When keys are encrypted at rest, the plaintext key does not
// exist as a stored artifact; CertPaths materializes it on demand.
type ProxyPaths struct {
	// CertPath is the public leaf+chain PEM file (always plaintext on disk).
	CertPath string
	// KeyPath is a plaintext private-key PEM file the proxy can load. When at-rest
	// encryption is configured, this is a decrypted copy materialized next to the
	// ciphertext (mode 0600); otherwise it is the stored plaintext key itself.
	KeyPath string
}

// CertPaths returns the cert and a proxy-readable plaintext key path for a host
// (§7, built-in Caddy on provided certs). Built-in Caddy loads cert/key files via
// its tls app, but the key is stored encrypted at rest; this decrypts it into a
// sibling plaintext file (mode 0600, atomic write) and returns that path so Caddy
// can read it. When no at-rest key is configured the stored key is already
// plaintext and is returned as-is.
//
// The cert file must already exist (written by Install); a missing cert is an
// error so the caller withholds the load_files entry rather than pointing Caddy
// at a missing file.
func (s *Store) CertPaths(host string) (ProxyPaths, error) {
	if host == "" {
		return ProxyPaths{}, fmt.Errorf("certstore: empty host")
	}
	base := SanitizeHost(host)
	certPath := filepath.Join(s.dir, base+certSuffix)
	if _, err := os.Stat(certPath); err != nil {
		return ProxyPaths{}, fmt.Errorf("certstore: cert for %q not found: %w", host, err)
	}

	if len(s.encryptKey) == 0 {
		// Stored key is already plaintext PEM.
		return ProxyPaths{CertPath: certPath, KeyPath: filepath.Join(s.dir, base+keyPlainSuffix)}, nil
	}

	// Decrypt the at-rest key into a sibling plaintext file the proxy can read.
	plain, err := s.ReadKey(host)
	if err != nil {
		return ProxyPaths{}, err
	}
	plainPath := filepath.Join(s.dir, base+keyMaterializedSuffix)
	if err := writeAtomic(plainPath, plain, keyMode); err != nil {
		return ProxyPaths{}, fmt.Errorf("certstore: materializing plaintext key for %q: %w", host, err)
	}
	return ProxyPaths{CertPath: certPath, KeyPath: plainPath}, nil
}

// Remove deletes every on-disk artifact for a host: the public leaf+chain
// (.crt), the at-rest-encrypted key (.key.enc), the plaintext key written when
// no at-rest key is configured (.key), and the decrypted key CertPaths
// materializes for the proxy (.key.plain). It is the inverse of Install plus
// CertPaths, called when a domain/route is removed so a decrypted private key
// never outlives its cert (a lingering .key.plain would negate the at-rest
// encryption). A missing file is not an error — Remove is a no-op when nothing
// was ever installed and is safe to call repeatedly (idempotent). Any
// unexpected unlink error is returned (after attempting the rest) so the caller
// can surface a key that could not be scrubbed.
func (s *Store) Remove(host string) error {
	if host == "" {
		return fmt.Errorf("certstore: empty host")
	}
	if s.dir == "" {
		return nil
	}
	base := SanitizeHost(host)
	var firstErr error
	for _, suffix := range []string{certSuffix, keySuffix, keyPlainSuffix, keyMaterializedSuffix} {
		path := filepath.Join(s.dir, base+suffix)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = fmt.Errorf("certstore: removing %q: %w", path, err)
		}
	}
	return firstErr
}

// SanitizeHost turns an FQDN into a safe file-name base, mapping a leading
// wildcard label "*." to "_wildcard." and dropping any path separators so a
// crafted host can never escape the cert directory.
func SanitizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.ReplaceAll(h, "*.", "_wildcard.")
	h = strings.ReplaceAll(h, "/", "_")
	h = strings.ReplaceAll(h, "\\", "_")
	h = strings.ReplaceAll(h, "..", "_")
	return h
}

// writeAtomic writes data to a temp file in the same directory then renames it
// into place, so a reader never observes a partial file (the rename is atomic on
// the same filesystem). The temp file is removed on any failure.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-cert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
