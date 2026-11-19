package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/agent/certdiscover"
	agentconfig "github.com/NurRobin/NurProxy/internal/agent/config"
)

// TestDiskCertScanner_excludesOwnCerts: a vhost NurProxy rendered for a zone
// wildcard domain points at the per-FQDN copy of "*.<zone>" in the agent's
// cert dir; that copy must not come back as an adoption candidate.
func TestDiskCertScanner_excludesOwnCerts(t *testing.T) {
	dataDir := t.TempDir()
	s, configRefs := diskCertScanner(&agentconfig.Config{DataDir: dataDir})
	if !configRefs || !slices.Contains(s.Exclude, dataDir) || !slices.Contains(s.Exclude, helperCertificateDir) {
		t.Fatalf("scanner = %+v (configRefs %v), want the data dir and the helper cert dir excluded", s, configRefs)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "*.example.com"},
		DNSNames: []string{"*.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certs := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		t.Fatal(err)
	}
	crt, keyPath := filepath.Join(certs, "app.example.com.crt"), filepath.Join(certs, "app.example.com.key.plain")
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	s.CertbotLive, s.AcmeShHomes = nil, nil // keep the test off the host's real certificates
	s.Refs = []certdiscover.Pair{{CertPath: crt, KeyPath: keyPath, Source: certdiscover.SourceNginx}}
	if got := s.Scan(); len(got) != 0 {
		t.Fatalf("own wildcard copy reported as a candidate: %+v", got)
	}
}
