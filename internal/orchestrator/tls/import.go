package tls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/certmodel"
)

// ImportedBundle is an operator-provided certificate after validation (#80).
// CertPEM and KeyPEM are re-encoded from the parsed blocks, so stray text and
// any private key pasted into the certificate file never reach the store.
type ImportedBundle struct {
	// CertPEM holds only CERTIFICATE blocks, leaf first.
	CertPEM string
	// KeyPEM holds exactly one private key block.
	KeyPEM    string
	Names     []string
	NotBefore time.Time
	NotAfter  time.Time
}

// ValidateImportedBundle checks an operator-provided certificate and key for
// host. The key must match the leaf, the leaf must cover host (wildcard SANs
// count, one label deep), be valid at now and usable for TLS servers, and any
// chain certificates must follow in signing order and must not be expired.
//
// The chain is deliberately NOT verified against a trusted root: import exists
// for certificates NurProxy did not issue (certbot or acme.sh migrations,
// registrar-sold wildcards, internal CAs). Whether clients trust the issuer is
// the operator's call, as it was on the host the certificate came from.
func ValidateImportedBundle(certPEM, keyPEM []byte, host string, now time.Time) (*ImportedBundle, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, errors.New("certificate and private key are both required")
	}
	if len(certPEM) > certmodel.MaxPEMBytes || len(keyPEM) > certmodel.MaxPEMBytes {
		return nil, fmt.Errorf("certificate or key exceeds %d bytes", certmodel.MaxPEMBytes)
	}

	chain, certOut, err := parseCertificateBlocks(certPEM)
	if err != nil {
		return nil, err
	}
	keyOut, err := parsePrivateKeyBlock(keyPEM)
	if err != nil {
		return nil, err
	}
	if _, err := tls.X509KeyPair(certOut, keyOut); err != nil {
		return nil, fmt.Errorf("private key does not match the certificate: %w", err)
	}

	leaf := chain[0]
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d in the bundle is not signed by certificate %d (the bundle must list the leaf first, then each issuer): %w", i+1, i+2, err)
		}
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return nil, fmt.Errorf("certificate does not cover %s (names: %s)", host, strings.Join(leafNames(leaf), ", "))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	for i, c := range chain[1:] {
		if !now.Before(c.NotAfter) {
			return nil, fmt.Errorf("chain certificate %d (%s) expired %s; remove it from the bundle", i+2, c.Subject.CommonName, c.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if !serverAuthAllowed(leaf) {
		return nil, errors.New("certificate is not valid for TLS server authentication (extended key usage)")
	}

	names := leafNames(leaf)
	if len(names) == 0 {
		names = []string{host}
	}
	return &ImportedBundle{
		CertPEM:   string(certOut),
		KeyPEM:    string(keyOut),
		Names:     names,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, nil
}

// parseCertificateBlocks returns every CERTIFICATE block in order, parsed and
// re-encoded. Other block types are dropped; a private key accidentally left in
// a combined PEM file must not end up in the public cert_pem column.
func parseCertificateBlocks(data []byte) ([]*x509.Certificate, []byte, error) {
	var (
		chain []*x509.Certificate
		out   bytes.Buffer
	)
	rest := data
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
			return nil, nil, fmt.Errorf("certificate %d in the bundle cannot be parsed: %w", len(chain)+1, err)
		}
		chain = append(chain, cert)
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return nil, nil, err
		}
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("no PEM certificate found")
	}
	return chain, out.Bytes(), nil
}

// parsePrivateKeyBlock returns the single private key block, re-encoded.
// Encrypted keys are refused: the agent has no passphrase to unlock them.
func parsePrivateKeyBlock(data []byte) ([]byte, error) {
	var found *pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
			return nil, errors.New("private key is encrypted; provide it without a passphrase")
		}
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		if found != nil {
			return nil, errors.New("key file contains more than one private key")
		}
		found = block
	}
	if found == nil {
		return nil, errors.New("no PEM private key found")
	}
	return pem.EncodeToMemory(&pem.Block{Type: found.Type, Bytes: found.Bytes}), nil
}

func serverAuthAllowed(leaf *x509.Certificate) bool {
	if len(leaf.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func leafNames(leaf *x509.Certificate) []string {
	names := append([]string(nil), leaf.DNSNames...)
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	return names
}
