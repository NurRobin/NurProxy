package tls

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateAccountKeyFileFreshAndExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	first, err := LoadOrGenerateAccountKeyFile(f, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	second, err := LoadOrGenerateAccountKeyFile(f, false)
	if err != nil {
		t.Fatal(err)
	}
	a := first.(*ecdsa.PrivateKey)
	b := second.(*ecdsa.PrivateKey)
	if a.D.Cmp(b.D) != 0 {
		t.Fatal("existing account key changed")
	}
}

func TestLoadOrGenerateAccountKeyFileDoesNotFollowFinalNameSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.key")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	held := path + ".held"
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateAccountKeyFile(f, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(external); string(got) != "external" {
		t.Fatalf("external changed: %q", got)
	}
	info, err := os.Stat(held)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 0 {
		t.Fatalf("held account key size=%v", info.Size())
	}
}
