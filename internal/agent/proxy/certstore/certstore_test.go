package certstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/crypto"
)

func testCertificatePair(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestInspectAndRefreshRuntimeKeyCryptographically(t *testing.T) {
	host := "app.example.com"
	certPEM, keyPEM := testCertificatePair(t, host)
	_, wrongKey := testCertificatePair(t, "wrong.example.com")
	encryptKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	store := New(t.TempDir(), encryptKey)
	if _, err := store.Install(Bundle{Host: host, CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}

	inspection, err := store.InspectRecovery(host)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.BundleValid || inspection.RuntimeKeyState != RuntimeKeyMissing || inspection.RuntimeKeyPath == "" {
		t.Fatalf("missing runtime inspection = %+v", inspection)
	}
	if err := store.RefreshRuntimeKey(host); err != nil {
		t.Fatal(err)
	}
	inspection, err = store.InspectRecovery(host)
	if err != nil || !inspection.BundleValid || inspection.RuntimeKeyState != RuntimeKeyValid {
		t.Fatalf("refreshed inspection = %+v, err=%v", inspection, err)
	}

	if err := os.WriteFile(inspection.RuntimeKeyPath, wrongKey, 0o600); err != nil {
		t.Fatal(err)
	}
	inspection, err = store.InspectRecovery(host)
	if err != nil || !inspection.BundleValid || inspection.RuntimeKeyState != RuntimeKeyMismatch {
		t.Fatalf("mismatched runtime inspection = %+v, err=%v", inspection, err)
	}
	if err := store.RefreshRuntimeKey(host); err != nil {
		t.Fatal(err)
	}
	if inspection, err = store.InspectRecovery(host); err != nil || inspection.RuntimeKeyState != RuntimeKeyValid {
		t.Fatalf("repaired runtime inspection = %+v, err=%v", inspection, err)
	}
}

func TestInspectRecoveryAbsentBundleAndSymlinkFailClosed(t *testing.T) {
	store := New(t.TempDir(), []byte("01234567890123456789012345678901"))
	inspection, err := store.InspectRecovery("absent.example.com")
	if err != nil || inspection.BundlePresent || inspection.BundleValid {
		t.Fatalf("absent inspection = %+v, err=%v", inspection, err)
	}

	host := "app.example.com"
	certPEM, keyPEM := testCertificatePair(t, host)
	if _, err := store.Install(Bundle{Host: host, CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(store.Dir(), SanitizeHost(host)+keyMaterializedSuffix)
	if err := os.Symlink(filepath.Join(store.Dir(), SanitizeHost(host)+keySuffix), runtimePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InspectRecovery(host); err == nil {
		t.Fatal("runtime-key symlink was accepted")
	}
}

func TestInstallRecoveryBundleRejectsCryptographicMismatch(t *testing.T) {
	host := "app.example.com"
	certPEM, _ := testCertificatePair(t, host)
	_, wrongKey := testCertificatePair(t, "wrong.example.com")
	store := New(t.TempDir(), nil)
	if err := store.InstallRecoveryBundle(Bundle{Host: host, CertPEM: certPEM, KeyPEM: wrongKey}); err == nil {
		t.Fatal("mismatched recovery bundle was installed")
	}
	if inspection, err := store.InspectRecovery(host); err != nil || inspection.BundlePresent {
		t.Fatalf("rejected bundle left artifacts: %+v err=%v", inspection, err)
	}
}

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

func TestInstall_materializePlain_writesPlaintextKey(t *testing.T) {
	dir := t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := New(dir, key) // at-rest encryption on
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret-plain\n-----END PRIVATE KEY-----\n")

	// Without MaterializePlain: only the encrypted key lands, no .key.plain.
	if _, err := s.Install(Bundle{Host: "co1.example.com", CertPEM: []byte("C"), KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "co1.example.com.key.plain")); !os.IsNotExist(err) {
		t.Error("plaintext key should NOT exist without MaterializePlain")
	}

	// With MaterializePlain: .key.plain holds the decrypted key for a hand-written config.
	if _, err := s.Install(Bundle{Host: "co2.example.com", CertPEM: []byte("C"), KeyPEM: keyPEM, MaterializePlain: true}); err != nil {
		t.Fatalf("Install (materialize): %v", err)
	}
	plain, err := os.ReadFile(filepath.Join(dir, "co2.example.com.key.plain"))
	if err != nil {
		t.Fatalf("read .key.plain: %v", err)
	}
	if !bytes.Equal(plain, keyPEM) {
		t.Errorf(".key.plain should be the decrypted key, got %q", string(plain))
	}
}

func TestPrune_removesOrphanHosts(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, nil)
	for _, h := range []string{"keep.example.com", "drop.example.com"} {
		if _, err := s.Install(Bundle{Host: h, CertPEM: []byte("C"), KeyPEM: []byte("K")}); err != nil {
			t.Fatalf("Install %s: %v", h, err)
		}
	}
	n, err := s.Prune([]string{"keep.example.com"})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "keep.example.com.crt")); err != nil {
		t.Error("kept host cert should survive")
	}
	if _, err := os.Stat(filepath.Join(dir, "drop.example.com.crt")); !os.IsNotExist(err) {
		t.Error("orphan host cert should be pruned")
	}
}

func TestInstall_refreshesExistingMaterializedKey(t *testing.T) {
	// Regression for the raw-config renewal bug: once <host>.key.plain exists on
	// disk (materialized by CertPaths or a prior MaterializePlain install), a raw
	// vhost references it directly and the backend never calls CertPaths for raw
	// routes. Install must therefore refresh the plaintext key on every push —
	// even without MaterializePlain — or a re-issued cert pairs with a stale key
	// and nginx -t fails for the whole agent.
	dir := t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := New(dir, key)

	certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf1\n-----END CERTIFICATE-----\n")
	keyPEM1 := []byte("-----BEGIN PRIVATE KEY-----\nkey1\n-----END PRIVATE KEY-----\n")
	if _, err := s.Install(Bundle{Host: "raw.example.com", CertPEM: certPEM, KeyPEM: keyPEM1}); err != nil {
		t.Fatalf("Install #1: %v", err)
	}
	// Materialize the plaintext key like a non-raw render (or first-time raw
	// setup) would.
	if _, err := s.CertPaths("raw.example.com"); err != nil {
		t.Fatalf("CertPaths: %v", err)
	}

	// Re-issue: new keypair pushed, MaterializePlain NOT set.
	keyPEM2 := []byte("-----BEGIN PRIVATE KEY-----\nkey2\n-----END PRIVATE KEY-----\n")
	if _, err := s.Install(Bundle{Host: "raw.example.com", CertPEM: certPEM, KeyPEM: keyPEM2}); err != nil {
		t.Fatalf("Install #2: %v", err)
	}

	plain, err := os.ReadFile(filepath.Join(dir, "raw.example.com.key.plain"))
	if err != nil {
		t.Fatalf("read key.plain: %v", err)
	}
	if !bytes.Equal(plain, keyPEM2) {
		t.Errorf("key.plain not refreshed on install: got %q, want new key", plain)
	}
}

func TestInstall_noMaterializedKey_staysAbsent(t *testing.T) {
	// Without MaterializePlain and without a pre-existing key.plain, Install must
	// NOT write a plaintext key — that would silently negate at-rest encryption
	// for hosts that never reference it.
	dir := t.TempDir()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := New(dir, key)
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
	if _, err := s.Install(Bundle{Host: "plainless.example.com", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "plainless.example.com.key.plain")); !os.IsNotExist(err) {
		t.Errorf("key.plain should not exist, stat err = %v", err)
	}
}
