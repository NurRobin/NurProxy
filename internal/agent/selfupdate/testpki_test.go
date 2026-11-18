package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// testPKI is a throwaway Fulcio look-alike: a root, an intermediate and a
// helper that issues short-lived code-signing leaves with a workflow identity.
type testPKI struct {
	root, inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
	trust             Trust
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{}
	p.rootKey = mustKey(t)
	p.interKey = mustKey(t)
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"test"}, CommonName: "test-root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	p.root = mustCert(t, rootTmpl, rootTmpl, &p.rootKey.PublicKey, p.rootKey)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{"test"}, CommonName: "test-intermediate"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	p.inter = mustCert(t, interTmpl, p.root, &p.interKey.PublicKey, p.rootKey)
	bundle := append(pemCert(p.root), pemCert(p.inter)...)
	trust, err := TrustFromPEM(bundle, DefaultRepository, GitHubActionsIssuer)
	if err != nil {
		t.Fatal(err)
	}
	p.trust = trust
	return p
}

type leafOpts struct {
	identity string
	issuer   string
	selfCA   bool // sign with an unrelated CA instead of the trusted chain
}

// sign returns cosign-style signature and base64-wrapped PEM certificate for
// data, issued to opts.identity.
func (p *testPKI) sign(t *testing.T, data []byte, opts leafOpts) (sig, cert []byte) {
	t.Helper()
	key := mustKey(t)
	u, err := url.Parse(opts.identity)
	if err != nil {
		t.Fatal(err)
	}
	issuerDER, err := asn1.MarshalWithParams(opts.issuer, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(9 * time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:        []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: oidIssuerV1, Value: []byte(opts.issuer)},
			{Id: oidIssuerV2, Value: issuerDER},
		},
	}
	parent, parentKey := p.inter, p.interKey
	if opts.selfCA {
		other := newTestPKI(t)
		parent, parentKey = other.inter, other.interKey
	}
	leaf := mustCert(t, tmpl, parent, &key.PublicKey, parentKey)
	digest := sha256.Sum256(data)
	raw, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(raw)), []byte(base64.StdEncoding.EncodeToString(pemCert(leaf)))
}

// release builds a complete signed release for version on goos/goarch whose
// archive holds binary.
func (p *testPKI) release(t *testing.T, version, goos, goarch string, binary []byte) Release {
	t.Helper()
	asset, err := AssetName(version, goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGz(t, map[string][]byte{BinaryName: binary, "LICENSE": []byte("MIT")})
	sum := sha256.Sum256(archive)
	other := sha256.Sum256([]byte("other"))
	checksums := []byte(fmt.Sprintf("%s  %s\n%s  nurproxy_%s_%s_%s.tar.gz\n", hex.EncodeToString(sum[:]), asset, hex.EncodeToString(other[:]), version, goos, goarch))
	sig, cert := p.sign(t, checksums, leafOpts{identity: p.trust.ExpectedIdentity(version), issuer: GitHubActionsIssuer})
	return Release{Version: version, Asset: asset, Checksums: checksums, Signature: sig, Certificate: cert, Archive: archive}
}

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
