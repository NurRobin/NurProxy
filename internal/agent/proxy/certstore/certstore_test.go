package certstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

func TestInstall_encryptsKeyAtRest_andReadsBack(t *testing.T) {
	dir := t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := New(dir, key)

	certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")

	paths, err := s.Install(Bundle{Host: "app.example.com", CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !paths.Encrypted {
		t.Error("expected key to be encrypted at rest")
	}

	// The public cert is written as plain PEM.
	gotCert, err := os.ReadFile(paths.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !bytes.Equal(gotCert, certPEM) {
		t.Error("cert on disk should be the plaintext leaf+chain")
	}

	// The key on disk must NOT be the plaintext PEM — it is ciphertext.
	onDiskKey, err := os.ReadFile(paths.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if bytes.Contains(onDiskKey, keyPEM) || bytes.Contains(onDiskKey, []byte("secret")) {
		t.Error("private key must be encrypted at rest, found plaintext on disk")
	}

	// ReadKey round-trips to the original plaintext key.
	gotKey, err := s.ReadKey("app.example.com")
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if !bytes.Equal(gotKey, keyPEM) {
		t.Errorf("ReadKey = %q, want original key", gotKey)
	}
}

func TestInstall_noKey_writesPlaintext(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, nil)

	keyPEM := []byte("PLAINKEY")
	paths, err := s.Install(Bundle{Host: "h.example.com", CertPEM: []byte("CERT"), KeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if paths.Encrypted {
		t.Error("no at-rest key configured: key should be plaintext")
	}
	onDisk, err := os.ReadFile(paths.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !bytes.Equal(onDisk, keyPEM) {
		t.Errorf("plaintext key on disk = %q, want %q", onDisk, keyPEM)
	}
}

func TestInstall_keyFilePermissions_areOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	key, _ := crypto.GenerateKey()
	s := New(dir, key)

	paths, err := s.Install(Bundle{Host: "h.example.com", CertPEM: []byte("C"), KeyPEM: []byte("K")})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(paths.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyMode {
		t.Errorf("key mode = %o, want %o", perm, keyMode)
	}
}

func TestInstall_validation(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, nil)
	tests := []struct {
		name   string
		bundle Bundle
	}{
		{"no host", Bundle{CertPEM: []byte("c"), KeyPEM: []byte("k")}},
		{"no cert", Bundle{Host: "h", KeyPEM: []byte("k")}},
		{"no key", Bundle{Host: "h", CertPEM: []byte("c")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.Install(tt.bundle); err == nil {
				t.Error("expected error for invalid bundle")
			}
		})
	}
}

func TestInstall_overwrite_replacesInPlace(t *testing.T) {
	dir := t.TempDir()
	key, _ := crypto.GenerateKey()
	s := New(dir, key)

	if _, err := s.Install(Bundle{Host: "h.example.com", CertPEM: []byte("OLD"), KeyPEM: []byte("OLDKEY")}); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if _, err := s.Install(Bundle{Host: "h.example.com", CertPEM: []byte("NEW"), KeyPEM: []byte("NEWKEY")}); err != nil {
		t.Fatalf("second install: %v", err)
	}

	gotKey, err := s.ReadKey("h.example.com")
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if string(gotKey) != "NEWKEY" {
		t.Errorf("renewed key = %q, want NEWKEY", gotKey)
	}
	// No leftover temp files in the cert dir.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == "" && len(e.Name()) > 5 && e.Name()[:5] == ".tmp-" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestSanitizeHost(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"app.example.com", "app.example.com"},
		{"*.example.com", "_wildcard.example.com"},
		{"../etc/passwd", "__etc_passwd"},
		{"a/b", "a_b"},
	}
	for _, tt := range tests {
		if got := SanitizeHost(tt.in); got != tt.want {
			t.Errorf("SanitizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCertPaths_encrypted_materializesPlaintextKey verifies that with at-rest
// encryption, CertPaths decrypts the key into a sibling plaintext file the proxy
// can read (§7, built-in Caddy loads cert/key files).
func TestCertPaths_encrypted_materializesPlaintextKey(t *testing.T) {
	dir := t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := New(dir, key)

	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\ntopsecret\n-----END PRIVATE KEY-----\n")
	if _, err := s.Install(Bundle{Host: "app.example.com", CertPEM: []byte("CERT"), KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	paths, err := s.CertPaths("app.example.com")
	if err != nil {
		t.Fatalf("CertPaths: %v", err)
	}
	if _, err := os.Stat(paths.CertPath); err != nil {
		t.Errorf("cert path missing: %v", err)
	}
	got, err := os.ReadFile(paths.KeyPath)
	if err != nil {
		t.Fatalf("reading materialized key: %v", err)
	}
	if !bytes.Equal(got, keyPEM) {
		t.Errorf("materialized key = %q, want original plaintext", got)
	}
	if paths.KeyPath == filepath.Join(dir, "app.example.com.key.enc") {
		t.Error("materialized key must not be the ciphertext file")
	}
}

// TestCertPaths_plaintext_returnsStoredKey verifies that without at-rest
// encryption, CertPaths returns the stored plaintext key path directly.
func TestCertPaths_plaintext_returnsStoredKey(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, nil)

	if _, err := s.Install(Bundle{Host: "app.example.com", CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	paths, err := s.CertPaths("app.example.com")
	if err != nil {
		t.Fatalf("CertPaths: %v", err)
	}
	if paths.KeyPath != filepath.Join(dir, "app.example.com.key") {
		t.Errorf("key path = %q, want stored plaintext key", paths.KeyPath)
	}
}

// TestCertPaths_missingCert_errors verifies a not-yet-installed cert is an error
// so the caller withholds the load_files entry rather than pointing at a missing
// file.
func TestCertPaths_missingCert_errors(t *testing.T) {
	s := New(t.TempDir(), nil)
	if _, err := s.CertPaths("never.installed.example.com"); err == nil {
		t.Fatal("CertPaths for a missing cert returned nil error, want error")
	}
}

func TestRemove_deletesAllArtifacts(t *testing.T) {
	host := "app.example.com"
	base := SanitizeHost(host)

	tests := []struct {
		name      string
		encrypted bool
		// extra files to drop in the dir beyond Install's output, simulating the
		// CertPaths-materialized plaintext key and the no-at-rest plaintext key.
		extraSuffixes []string
	}{
		{
			name:          "encrypted at rest plus materialized plaintext",
			encrypted:     true,
			extraSuffixes: []string{keyMaterializedSuffix},
		},
		{
			name:          "plaintext key (no at-rest key)",
			encrypted:     false,
			extraSuffixes: nil,
		},
		{
			name:          "all four artifact kinds present",
			encrypted:     true,
			extraSuffixes: []string{keyPlainSuffix, keyMaterializedSuffix},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var encKey []byte
			if tc.encrypted {
				k, err := crypto.GenerateKey()
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				encKey = k
			}
			s := New(dir, encKey)

			certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
			keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
			if _, err := s.Install(Bundle{Host: host, CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
				t.Fatalf("Install: %v", err)
			}
			// Materialize the decrypted plaintext key on the encrypted path so we can
			// prove Remove scrubs it (this is the at-rest-encryption-negating file).
			if tc.encrypted {
				if _, err := s.CertPaths(host); err != nil {
					t.Fatalf("CertPaths: %v", err)
				}
			}
			// Drop any additional artifact kinds so Remove must clear them too.
			for _, suf := range tc.extraSuffixes {
				p := filepath.Join(dir, base+suf)
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatalf("seed %s: %v", suf, err)
				}
			}

			if err := s.Remove(host); err != nil {
				t.Fatalf("Remove: %v", err)
			}

			// Every artifact kind for this host must be gone.
			for _, suf := range []string{certSuffix, keySuffix, keyPlainSuffix, keyMaterializedSuffix} {
				p := filepath.Join(dir, base+suf)
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("artifact %s still present after Remove (stat err=%v)", base+suf, err)
				}
			}
		})
	}
}

func TestRemove_missingFiles_isNoOp(t *testing.T) {
	s := New(t.TempDir(), nil)
	if err := s.Remove("never.installed.example.com"); err != nil {
		t.Errorf("Remove of absent host should be a no-op, got %v", err)
	}
	// Calling it twice is also fine (idempotent).
	if err := s.Remove("never.installed.example.com"); err != nil {
		t.Errorf("second Remove should be a no-op, got %v", err)
	}
}

func TestRemove_emptyHost_errors(t *testing.T) {
	s := New(t.TempDir(), nil)
	if err := s.Remove(""); err == nil {
		t.Error("Remove with empty host should error")
	}
}
