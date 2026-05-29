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
