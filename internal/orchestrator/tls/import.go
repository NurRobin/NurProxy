package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// ValidateImportedBundle checks an operator-provided cert bundle (#80): the
// key must match the leaf, the leaf must cover host, and the cert must not be
// expired. Returns the leaf's DNS names and NotAfter for storage — imported
// certs enter the same store issued ones do, so central renewal takes over
// automatically once the cert enters the renew window (ACME re-issues then).
// Deliberately NO chain/CA verification: importing exists precisely for certs
// NurProxy did not issue (certbot/acme.sh migrations, internal CAs); whether
// clients trust the chain is the operator's concern, matching what their old
// setup already served.
func ValidateImportedBundle(certPEM, keyPEM []byte, host string) (names []string, notAfter time.Time, err error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("tls: cert/key pair invalid: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, time.Time{}, fmt.Errorf("tls: no PEM certificate found")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("tls: parsing leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return nil, time.Time{}, fmt.Errorf("tls: certificate does not cover %s: %w", host, err)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, time.Time{}, fmt.Errorf("tls: certificate expired %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	names = leaf.DNSNames
	if len(names) == 0 {
		names = []string{host}
	}
	return names, leaf.NotAfter, nil
}
