package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Two generated keys should differ
	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, key2) {
		t.Error("two generated keys should not be equal")
	}
}

func TestSaveAndLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := SaveKey(key, path); err != nil {
		t.Fatal(err)
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, loaded) {
		t.Error("loaded key does not match saved key")
	}
}

func TestLoadKey_InvalidSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")

	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadKey(path); err == nil {
		t.Error("LoadKey should fail for invalid key size")
	}
}

func TestLoadKey_NotFound(t *testing.T) {
	if _, err := LoadKey("/nonexistent/path/key"); err == nil {
		t.Error("LoadKey should fail for nonexistent file")
	}
}

func TestLoadOrGenerateKey_New(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.key")

	key, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// File should exist now
	if _, err := os.Stat(path); err != nil {
		t.Errorf("key file should exist after LoadOrGenerateKey: %v", err)
	}
}

func TestLoadOrGenerateKey_Existing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.key")

	original, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(original, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, loaded) {
		t.Error("LoadOrGenerateKey should return existing key")
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"empty", []byte("")},
		{"binary data", []byte{0x00, 0xff, 0x01, 0xfe}},
		{"long text", bytes.Repeat([]byte("a"), 10000)},
		{"json-like", []byte(`{"api_key":"sk-1234","zone":"example.com"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := Encrypt(key, tt.plaintext)
			if err != nil {
				t.Fatal(err)
			}

			pt, err := Decrypt(key, ct)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(pt, tt.plaintext) {
				t.Errorf("decrypted plaintext does not match original")
			}
		})
	}
}

func TestEncrypt_RandomNonce(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same input")
	ct1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("encrypting the same plaintext twice should produce different ciphertexts (random nonce)")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext (flip a byte near the end)
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := Decrypt(key, tampered); err == nil {
		t.Error("Decrypt should fail for tampered ciphertext")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	ct, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decrypt(key2, ct); err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key, _ := GenerateKey()
	if _, err := Decrypt(key, []byte("short")); err == nil {
		t.Error("Decrypt should fail for ciphertext shorter than nonce")
	}
}

func TestEncryptDecryptString_Roundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "hello world"},
		{"empty", ""},
		{"json config", `{"api_key":"sk-1234","endpoint":"https://api.example.com"}`},
		{"unicode", "Helloe Welt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := EncryptString(key, tt.plaintext)
			if err != nil {
				t.Fatal(err)
			}

			pt, err := DecryptString(key, ct)
			if err != nil {
				t.Fatal(err)
			}

			if pt != tt.plaintext {
				t.Errorf("DecryptString = %q, want %q", pt, tt.plaintext)
			}
		})
	}
}

func TestDecryptString_InvalidBase64(t *testing.T) {
	key, _ := GenerateKey()
	if _, err := DecryptString(key, "not-valid-base64!!!"); err == nil {
		t.Error("DecryptString should fail for invalid base64")
	}
}
