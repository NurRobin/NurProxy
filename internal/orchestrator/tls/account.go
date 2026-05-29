package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadOrGenerateAccountKey loads the ACME account private key from path, or
// generates a new P-256 key and persists it (PKCS#8 PEM, 0600) if the file does
// not exist. The same account key must be reused across restarts so renewals
// continue under one registered ACME account (lego registers idempotently
// against an existing key). This is the orchestrator's ACME identity, distinct
// from the per-certificate keys.
func LoadOrGenerateAccountKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("tls: account key %s is not valid PEM", path)
		}
		key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("tls: parsing account key %s: %w", path, perr)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("tls: reading account key %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls: generating ACME account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("tls: marshaling ACME account key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("tls: writing ACME account key %s: %w", path, err)
	}
	return key, nil
}
