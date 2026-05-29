package tls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// LeafNotAfter parses the leaf (first) certificate from a PEM bundle and returns
// its NotAfter expiry. Central renewal compares this against the ≥30-day window
// (§7). Returns an error if no certificate is found.
func LeafNotAfter(certPEM []byte) (time.Time, error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("tls: parsing leaf certificate: %w", err)
		}
		return cert.NotAfter, nil
	}
	return time.Time{}, fmt.Errorf("tls: no certificate found in PEM bundle")
}
