// Package crypto provides AES-256-GCM encryption for storing secrets at rest.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

const keySize = 32 // AES-256

// GenerateKey returns 32 cryptographically random bytes suitable for AES-256.
func GenerateKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

// SaveKey writes the key to path with file mode 0600.
func SaveKey(key []byte, path string) error {
	return os.WriteFile(path, key, 0600)
}

// LoadKey reads a key from the given file path.
func LoadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key size: got %d bytes, want %d", len(key), keySize)
	}
	return key, nil
}

// LoadOrGenerateKey loads an existing key from path, or generates a new one
// and saves it if the file does not exist.
func LoadOrGenerateKey(path string) ([]byte, error) {
	key, err := LoadKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// File exists but is invalid or unreadable — unwrap to check inner error
		if _, statErr := os.Stat(path); statErr == nil {
			return nil, err
		}
	}

	key, err = GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := SaveKey(key, path); err != nil {
		return nil, fmt.Errorf("saving generated key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// The nonce is prepended to the returned ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// nonce is prepended to the ciphertext
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext produced by Encrypt (nonce-prefixed AES-256-GCM).
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a plaintext string and returns the result as a base64 string.
func EncryptString(key []byte, plaintext string) (string, error) {
	ct, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptString decodes a base64 ciphertext string and decrypts it.
func DecryptString(key []byte, ciphertext string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
