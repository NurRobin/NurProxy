package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestLeafNotAfter_parsesExpiry(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got, err := LeafNotAfter(certPEM)
	if err != nil {
		t.Fatalf("LeafNotAfter: %v", err)
	}
	if !got.Equal(notAfter) {
		t.Errorf("notAfter = %v, want %v", got, notAfter)
	}
}

func TestLeafNotAfter_noCert_errors(t *testing.T) {
	if _, err := LeafNotAfter([]byte("not a pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
}
