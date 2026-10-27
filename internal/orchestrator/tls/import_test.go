package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// importFixture is a CA-issued leaf plus everything needed to assemble
// valid and broken bundles from it.
type importFixture struct {
	leafPEM, caPEM, keyPEM, otherKeyPEM []byte
}

type leafOpts struct {
	names     []string
	notBefore time.Time
	notAfter  time.Time
	extUsage  []x509.ExtKeyUsage
	rsaKey    bool
}

func newImportFixture(t *testing.T, opts leafOpts) importFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Import CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	var (
		leafPub any
		keyPEM  []byte
	)
	if opts.rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		leafPub = &k.PublicKey
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafPub = &k.PublicKey
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(60 * 24 * time.Hour)
	}
	if opts.extUsage == nil {
		opts.extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: opts.names[0]},
		DNSNames:     opts.names,
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		ExtKeyUsage:  opts.extUsage,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalECPrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	return importFixture{
		leafPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		caPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		keyPEM:      keyPEM,
		otherKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherDER}),
	}
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestValidateImportedBundle(t *testing.T) {
	now := time.Now()
	plain := newImportFixture(t, leafOpts{names: []string{"app.example.com", "www.example.com"}})
	wildcard := newImportFixture(t, leafOpts{names: []string{"*.example.com"}, rsaKey: true})
	expired := newImportFixture(t, leafOpts{names: []string{"app.example.com"}, notBefore: now.Add(-90 * 24 * time.Hour), notAfter: now.Add(-time.Hour)})
	future := newImportFixture(t, leafOpts{names: []string{"app.example.com"}, notBefore: now.Add(48 * time.Hour), notAfter: now.Add(90 * 24 * time.Hour)})
	clientOnly := newImportFixture(t, leafOpts{names: []string{"app.example.com"}, extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	encryptedKey := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}})

	tests := []struct {
		name      string
		cert, key []byte
		host      string
		wantErr   string
		wantNames []string
		wantCerts int
	}{
		{name: "leaf only", cert: plain.leafPEM, key: plain.keyPEM, host: "app.example.com", wantNames: []string{"app.example.com", "www.example.com"}, wantCerts: 1},
		{name: "leaf plus chain", cert: join(plain.leafPEM, plain.caPEM), key: plain.keyPEM, host: "www.example.com", wantNames: []string{"app.example.com", "www.example.com"}, wantCerts: 2},
		{name: "wildcard covers one label", cert: join(wildcard.leafPEM, wildcard.caPEM), key: wildcard.keyPEM, host: "app.example.com", wantNames: []string{"*.example.com"}, wantCerts: 2},
		{name: "combined pem: key in cert file is dropped", cert: join(plain.leafPEM, plain.keyPEM, plain.caPEM), key: plain.keyPEM, host: "app.example.com", wantNames: []string{"app.example.com", "www.example.com"}, wantCerts: 2},
		{name: "wildcard does not cover apex", cert: wildcard.leafPEM, key: wildcard.keyPEM, host: "example.com", wantErr: "does not cover example.com"},
		{name: "wildcard does not cover two labels", cert: wildcard.leafPEM, key: wildcard.keyPEM, host: "a.b.example.com", wantErr: "does not cover"},
		{name: "wrong host", cert: plain.leafPEM, key: plain.keyPEM, host: "other.example.com", wantErr: "does not cover other.example.com"},
		{name: "mismatched key", cert: plain.leafPEM, key: plain.otherKeyPEM, host: "app.example.com", wantErr: "does not match"},
		{name: "chain out of order", cert: join(plain.caPEM, plain.leafPEM), key: plain.keyPEM, host: "app.example.com", wantErr: "does not match"},
		{name: "foreign chain", cert: join(plain.leafPEM, wildcard.caPEM), key: plain.keyPEM, host: "app.example.com", wantErr: "not signed by certificate 2"},
		{name: "expired", cert: expired.leafPEM, key: expired.keyPEM, host: "app.example.com", wantErr: "expired"},
		{name: "not yet valid", cert: future.leafPEM, key: future.keyPEM, host: "app.example.com", wantErr: "not valid until"},
		{name: "client-auth only", cert: clientOnly.leafPEM, key: clientOnly.keyPEM, host: "app.example.com", wantErr: "server authentication"},
		{name: "encrypted key", cert: plain.leafPEM, key: encryptedKey, host: "app.example.com", wantErr: "encrypted"},
		{name: "two keys", cert: plain.leafPEM, key: join(plain.keyPEM, plain.otherKeyPEM), host: "app.example.com", wantErr: "more than one private key"},
		{name: "no certificate", cert: []byte("not a pem"), key: plain.keyPEM, host: "app.example.com", wantErr: "no PEM certificate"},
		{name: "no key", cert: plain.leafPEM, key: plain.leafPEM, host: "app.example.com", wantErr: "no PEM private key"},
		{name: "empty", cert: nil, key: nil, host: "app.example.com", wantErr: "both required"},
		{name: "oversized", cert: bytes.Repeat([]byte("A"), 1<<20+1), key: plain.keyPEM, host: "app.example.com", wantErr: "exceeds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateImportedBundle(tc.cert, tc.key, tc.host, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got.Names, ",") != strings.Join(tc.wantNames, ",") {
				t.Errorf("names = %v, want %v", got.Names, tc.wantNames)
			}
			if n := strings.Count(got.CertPEM, "BEGIN CERTIFICATE"); n != tc.wantCerts {
				t.Errorf("stored cert PEM has %d certificates, want %d", n, tc.wantCerts)
			}
			if strings.Contains(got.CertPEM, "PRIVATE KEY") {
				t.Error("stored cert PEM contains private key material")
			}
			if strings.Count(got.KeyPEM, "PRIVATE KEY-----") != 2 {
				t.Errorf("stored key PEM should hold exactly one key block, got %q", got.KeyPEM)
			}
			if got.NotAfter.IsZero() || !got.NotAfter.After(now) {
				t.Errorf("NotAfter = %v, want a future expiry", got.NotAfter)
			}
		})
	}
}
