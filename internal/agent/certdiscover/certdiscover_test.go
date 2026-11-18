package certdiscover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

type testCert struct {
	certPEM, keyPEM []byte
	fingerprint     string
}

func mintCert(t *testing.T, notAfter time.Time, names ...string) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return testCert{
		certPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		fingerprint: hex.EncodeToString(sum[:]),
	}
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	inTwoMonths := time.Now().Add(60 * 24 * time.Hour)
	certbot := mintCert(t, inTwoMonths, "app.example.com", "www.example.com")
	acme := mintCert(t, inTwoMonths, "*.example.org")
	other := mintCert(t, inTwoMonths, "other.example.com")
	expired := mintCert(t, time.Now().Add(-time.Minute), "old.example.com")
	apacheLeaf := mintCert(t, inTwoMonths, "apache.example.com")

	live := filepath.Join(root, "letsencrypt", "live")
	write(t, filepath.Join(live, "app.example.com", "fullchain.pem"), certbot.certPEM, 0o644)
	write(t, filepath.Join(live, "app.example.com", "privkey.pem"), certbot.keyPEM, 0o600)
	write(t, filepath.Join(live, "README"), []byte("not a cert dir"), 0o644)
	// A key that belongs to another certificate.
	write(t, filepath.Join(live, "mismatch.example.com", "fullchain.pem"), other.certPEM, 0o644)
	write(t, filepath.Join(live, "mismatch.example.com", "privkey.pem"), acme.keyPEM, 0o600)
	write(t, filepath.Join(live, "old.example.com", "fullchain.pem"), expired.certPEM, 0o644)
	write(t, filepath.Join(live, "old.example.com", "privkey.pem"), expired.keyPEM, 0o600)

	home := filepath.Join(root, "acme.sh")
	write(t, filepath.Join(home, "example.org_ecc", "fullchain.cer"), acme.certPEM, 0o644)
	write(t, filepath.Join(home, "example.org_ecc", "example.org.key"), acme.keyPEM, 0o600)
	write(t, filepath.Join(home, "dnsapi", "dns_cf.sh"), []byte("#!/bin/sh"), 0o644)

	// A vhost referencing the certbot files again (deduplicated) and an
	// Apache-style combined file with a separate chain.
	combined := append(append([]byte{}, apacheLeaf.certPEM...), apacheLeaf.keyPEM...)
	write(t, filepath.Join(root, "apache", "site.pem"), combined, 0o600)
	write(t, filepath.Join(root, "apache", "chain.pem"), other.certPEM, 0o644)

	s := Scanner{
		CertbotLive: []string{live, filepath.Join(root, "missing")},
		AcmeShHomes: []string{home},
		Refs: []Pair{
			{CertPath: filepath.Join(live, "app.example.com", "fullchain.pem"), KeyPath: filepath.Join(live, "app.example.com", "privkey.pem"), Source: SourceNginx},
			{CertPath: filepath.Join(root, "apache", "site.pem"), ChainPath: filepath.Join(root, "apache", "chain.pem"), Source: SourceApache},
		},
	}
	got := s.Scan()

	byFP := map[string]int{}
	for _, dc := range got {
		if dc.Fingerprint != "" {
			byFP[dc.Fingerprint]++
		}
		if strings.Contains(dc.Error, "BEGIN") {
			t.Errorf("error leaks PEM: %q", dc.Error)
		}
	}
	if byFP[certbot.fingerprint] != 1 {
		t.Errorf("certbot cert reported %d times, want once (deduplicated)", byFP[certbot.fingerprint])
	}

	find := func(fp string) *models.DiscoveredCert {
		for i := range got {
			if got[i].Fingerprint == fp {
				return &got[i]
			}
		}
		return nil
	}
	tests := []struct {
		name    string
		fp      string
		wantErr string
		wantSrc string
	}{
		{"certbot", certbot.fingerprint, "", SourceCertbot},
		{"acme.sh ecc", acme.fingerprint, "", SourceAcmeSh},
		{"key mismatch", other.fingerprint, "does not match", SourceCertbot},
		{"expired", expired.fingerprint, "expired", SourceCertbot},
		{"apache combined file", apacheLeaf.fingerprint, "", SourceApache},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := find(tc.fp)
			if e == nil {
				t.Fatalf("not reported; got %+v", got)
			}
			if tc.wantErr == "" && e.Error != "" || tc.wantErr != "" && !strings.Contains(e.Error, tc.wantErr) {
				t.Errorf("error = %q, want %q", e.Error, tc.wantErr)
			}
			if e.Source != tc.wantSrc {
				t.Errorf("source = %q, want %q", e.Source, tc.wantSrc)
			}
		})
	}
	if e := find(certbot.fingerprint); e != nil && strings.Join(e.Names, ",") != "app.example.com,www.example.com" {
		t.Errorf("names = %v", e.Names)
	}
}

func TestScan_excludesAgentOwnCerts(t *testing.T) {
	root := t.TempDir()
	c := mintCert(t, time.Now().Add(60*24*time.Hour), "*.example.com")
	dataDir := filepath.Join(root, "agent")
	own := filepath.Join(dataDir, "certs", "app.example.com.crt")
	ownKey := filepath.Join(dataDir, "certs", "app.example.com.key.plain")
	write(t, own, c.certPEM, 0o644)
	write(t, ownKey, c.keyPEM, 0o600)
	// A symlink outside the data dir pointing into it is excluded as well.
	link := filepath.Join(root, "link.crt")
	if err := os.Symlink(own, link); err != nil {
		t.Fatal(err)
	}
	refs := []Pair{{CertPath: own, KeyPath: ownKey, Source: SourceNginx}, {CertPath: link, KeyPath: ownKey, Source: SourceNginx}}

	if got := (Scanner{Refs: refs, Exclude: []string{dataDir}}).Scan(); len(got) != 0 {
		t.Errorf("agent's own certificates reported: %+v", got)
	}
	if got := (Scanner{Refs: refs, Exclude: []string{dataDir + "-other"}}).Scan(); len(got) != 1 {
		t.Errorf("a sibling directory with a shared prefix must not exclude: %+v", got)
	}
}

func TestScan_unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	root := t.TempDir()
	c := mintCert(t, time.Now().Add(60*24*time.Hour), "app.example.com")
	live := filepath.Join(root, "live")
	write(t, filepath.Join(live, "app", "fullchain.pem"), c.certPEM, 0o644)
	write(t, filepath.Join(live, "app", "privkey.pem"), c.keyPEM, 0o000)
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	got := Scanner{CertbotLive: []string{live, locked}}.Scan()
	var sawKey, sawDir bool
	for _, dc := range got {
		if dc.Fingerprint == c.fingerprint && strings.Contains(dc.Error, "permission denied") {
			sawKey = true
		}
		if dc.CertPath == locked && strings.Contains(dc.Error, "permission denied") {
			sawDir = true
		}
	}
	if !sawKey || !sawDir {
		t.Errorf("got %+v, want an unreadable-key entry and an unreadable-dir entry", got)
	}
	if _, err := (Scanner{CertbotLive: []string{live}}).Load(c.fingerprint); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("Load of unreadable key err = %v", err)
	}
}

func TestLoad(t *testing.T) {
	root := t.TempDir()
	c := mintCert(t, time.Now().Add(60*24*time.Hour), "app.example.com")
	issuer := mintCert(t, time.Now().Add(365*24*time.Hour), "Test Intermediate")
	live := filepath.Join(root, "live")
	// Key file first in a combined layout plus a chain cert, to check the
	// bundle is re-encoded as certificates only, leaf first.
	write(t, filepath.Join(live, "app", "fullchain.pem"), append(append([]byte{}, c.certPEM...), issuer.certPEM...), 0o644)
	write(t, filepath.Join(live, "app", "privkey.pem"), append([]byte("junk\n"), c.keyPEM...), 0o600)
	s := Scanner{CertbotLive: []string{live}}

	b, err := s.Load(strings.ToUpper(c.fingerprint))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(string(b.CertPEM), string(c.certPEM)) || strings.Contains(string(b.CertPEM), "PRIVATE KEY") {
		t.Errorf("cert PEM not leaf-first certificates only")
	}
	if strings.Count(string(b.CertPEM), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain dropped")
	}
	if string(b.KeyPEM) != string(c.keyPEM) {
		t.Errorf("key not re-encoded to the single key block")
	}
	if _, err := s.Load(issuer.fingerprint); err != ErrNotFound {
		t.Errorf("Load of a chain cert err = %v, want ErrNotFound", err)
	}
	if _, err := s.Load(""); err != ErrNotFound {
		t.Errorf("Load of empty fingerprint err = %v", err)
	}
}

func TestReadRegular_refusesNonRegular(t *testing.T) {
	if _, err := readRegular(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	big := filepath.Join(t.TempDir(), "big.pem")
	write(t, big, make([]byte, 2<<20), 0o644)
	if _, err := readRegular(big); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestApacheRefs(t *testing.T) {
	conf := `
SSLCertificateFile /etc/ssl/default.pem
SSLCertificateKeyFile /etc/ssl/default.key
<VirtualHost *:443>
    ServerName a.example.com
    SSLCertificateFile "/etc/letsencrypt/live/a/cert.pem"
    SSLCertificateKeyFile /etc/letsencrypt/live/a/privkey.pem
    SSLCertificateChainFile /etc/letsencrypt/live/a/chain.pem
</VirtualHost>
<VirtualHost *:443>
    # combined file, key inside
    SSLCertificateFile conf/combined.pem
</VirtualHost>
<VirtualHost *:443>
    SSLCertificateFile ${APACHE_CERT}
</VirtualHost>
<VirtualHost *:443>
    ServerName inherits.example.com
</VirtualHost>
`
	got := ApacheRefs(conf, "/etc/httpd")
	want := []Pair{
		{CertPath: "/etc/letsencrypt/live/a/cert.pem", KeyPath: "/etc/letsencrypt/live/a/privkey.pem", ChainPath: "/etc/letsencrypt/live/a/chain.pem", Source: SourceApache},
		{CertPath: "/etc/httpd/conf/combined.pem", KeyPath: "/etc/httpd/conf/combined.pem", Source: SourceApache},
		{CertPath: "/etc/ssl/default.pem", KeyPath: "/etc/ssl/default.key", Source: SourceApache},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pair %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestWriteSimulated(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	live, err := WriteSimulated(root, []string{" legacy.sandbox.test ", ""}, now)
	if err != nil {
		t.Fatal(err)
	}
	s := Scanner{CertbotLive: []string{live}, LiveSource: SourceDryRun}
	first := s.Scan()
	if len(first) != 1 || first[0].Error != "" || first[0].Source != SourceDryRun || first[0].Names[0] != "legacy.sandbox.test" {
		t.Fatalf("scan = %+v", first)
	}
	if _, err := WriteSimulated(root, []string{"legacy.sandbox.test"}, now); err != nil {
		t.Fatal(err)
	}
	if again := s.Scan(); again[0].Fingerprint != first[0].Fingerprint {
		t.Error("rewriting the simulation changed the fingerprint")
	}
	if _, err := s.Load(first[0].Fingerprint); err != nil {
		t.Errorf("Load simulated: %v", err)
	}
	if _, err := WriteSimulated(root, nil, now); err == nil {
		t.Error("no names accepted")
	}
}
