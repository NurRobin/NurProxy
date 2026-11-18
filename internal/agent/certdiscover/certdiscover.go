// Package certdiscover finds TLS certificate bundles that already sit on the
// agent host, so an operator migrating a host can adopt them instead of having
// NurProxy order fresh certificates (#80). It looks in certbot's live
// directory, in acme.sh homes, and at the files the host proxy's vhosts serve.
//
// Scanning reports metadata only. A private key is read to prove it matches
// its certificate and is then dropped; it is returned (by Load) only for the
// one fingerprint the operator chose to adopt.
package certdiscover

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/certmodel"
	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// MaxResults bounds how many bundles one scan reports. It matches the cap the
// orchestrator enforces on each detection list.
const MaxResults = 256

// Sources a bundle can be reported from.
const (
	SourceCertbot = "certbot"
	SourceAcmeSh  = "acme.sh"
	SourceNginx   = "nginx"
	SourceApache  = "apache"
	SourceDryRun  = "dryrun"
)

// Pair is one certificate file plus the key that belongs to it. ChainPath is
// set when the issuer chain lives in a separate file (Apache's
// SSLCertificateChainFile); KeyPath may equal CertPath for combined PEM files.
type Pair struct {
	CertPath  string
	KeyPath   string
	ChainPath string
	Source    string
}

// Scanner describes where to look. The zero value finds nothing; Default
// returns the well-known host locations.
type Scanner struct {
	// CertbotLive are certbot "live" directories: one subdirectory per
	// certificate holding fullchain.pem and privkey.pem.
	CertbotLive []string
	// AcmeShHomes are acme.sh home directories: one subdirectory per
	// certificate (suffixed _ecc for ECDSA) holding fullchain.cer and <name>.key.
	AcmeShHomes []string
	// Refs are pairs the host proxy's configuration references.
	Refs []Pair
	// Exclude lists directories whose files are never reported as Refs: the
	// agent's own data dir, where the vhosts NurProxy renders point at the
	// certificates it installed itself.
	Exclude []string
	// LiveSource overrides the source reported for CertbotLive entries; the
	// dry-run agent uses it to label its simulated bundles.
	LiveSource string
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Default returns a Scanner over the usual certbot and acme.sh locations.
func Default() Scanner {
	homes := []string{"/root/.acme.sh", "/etc/acme.sh"}
	if h, err := os.UserHomeDir(); err == nil && h != "" && h != "/root" {
		homes = append(homes, filepath.Join(h, ".acme.sh"))
	}
	return Scanner{CertbotLive: []string{"/etc/letsencrypt/live"}, AcmeShHomes: homes}
}

// Bundle is a loaded certificate bundle ready for upload. CertPEM holds only
// CERTIFICATE blocks (leaf first), KeyPEM exactly one private key block.
type Bundle struct {
	Pair    Pair
	CertPEM []byte
	KeyPEM  []byte
}

// Scan reports every bundle found, deduplicated by leaf fingerprint and sorted
// by certificate path. Bundles that cannot be adopted as found (unreadable
// key, key mismatch) are still reported with Error set, so the operator learns
// what is there and why it is not usable.
func (s Scanner) Scan() []models.DiscoveredCert {
	pairs, dirErrs := s.pairs()
	out := append([]models.DiscoveredCert(nil), dirErrs...)
	byFP := map[string]int{}
	for _, p := range pairs {
		dc, _ := s.read(p, false)
		if dc.Fingerprint != "" {
			if i, ok := byFP[dc.Fingerprint]; ok {
				// The same certificate is often both in certbot's directory and
				// referenced by a vhost. Keep the usable entry.
				if out[i].Error != "" && dc.Error == "" {
					out[i] = dc
				}
				continue
			}
			byFP[dc.Fingerprint] = len(out)
		}
		out = append(out, dc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CertPath < out[j].CertPath })
	if len(out) > MaxResults {
		out = out[:MaxResults]
	}
	return out
}

// ErrNotFound is returned by Load when no usable bundle has the fingerprint.
var ErrNotFound = errors.New("no usable certificate with that fingerprint on this host")

// Load re-scans and returns the bundle whose leaf has the given fingerprint.
// Only bundles the scanner itself discovers can be loaded, so a caller cannot
// steer it to an arbitrary file.
func (s Scanner) Load(fingerprint string) (*Bundle, error) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		return nil, ErrNotFound
	}
	pairs, _ := s.pairs()
	var lastErr error
	for _, p := range pairs {
		dc, b := s.read(p, true)
		if dc.Fingerprint != fingerprint {
			continue
		}
		if dc.Error != "" {
			lastErr = errors.New(dc.Error)
			continue
		}
		return b, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNotFound
}

func (s Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// pairs lists the candidate pairs. A directory that exists but cannot be
// listed is reported as an entry with Error set, which is the usual sign of an
// agent running without the rights to read certbot's 0700 directories.
func (s Scanner) pairs() ([]Pair, []models.DiscoveredCert) {
	var pairs []Pair
	var dirErrs []models.DiscoveredCert
	listDir := func(dir, source string) []fs.DirEntry {
		if _, err := os.Stat(dir); err != nil {
			return nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			dirErrs = append(dirErrs, models.DiscoveredCert{
				Source:   source,
				CertPath: dir,
				Error:    "cannot list directory: " + describeErr(err),
			})
			return nil
		}
		return entries
	}

	for _, live := range s.CertbotLive {
		source := SourceCertbot
		if s.LiveSource != "" {
			source = s.LiveSource
		}
		for _, e := range listDir(live, source) {
			if !isDirEntry(live, e) {
				continue
			}
			d := filepath.Join(live, e.Name())
			pairs = append(pairs, Pair{
				CertPath: filepath.Join(d, "fullchain.pem"),
				KeyPath:  filepath.Join(d, "privkey.pem"),
				Source:   source,
			})
		}
	}
	for _, home := range s.AcmeShHomes {
		for _, e := range listDir(home, SourceAcmeSh) {
			if !isDirEntry(home, e) {
				continue
			}
			d := filepath.Join(home, e.Name())
			cert := filepath.Join(d, "fullchain.cer")
			if _, err := os.Stat(cert); err != nil {
				continue // acme.sh keeps its own non-certificate directories here
			}
			name := strings.TrimSuffix(e.Name(), "_ecc")
			pairs = append(pairs, Pair{CertPath: cert, KeyPath: filepath.Join(d, name+".key"), Source: SourceAcmeSh})
		}
	}
	for _, r := range s.Refs {
		if r.CertPath == "" || s.excluded(r.CertPath) {
			continue
		}
		if r.KeyPath == "" {
			r.KeyPath = r.CertPath
		}
		r.Source = sourceForPath(r.CertPath, r.Source)
		pairs = append(pairs, r)
	}
	return pairs, dirErrs
}

// excluded reports whether path lies in one of the Exclude directories,
// comparing both the literal and the symlink-resolved forms.
func (s Scanner) excluded(path string) bool {
	forms := []string{filepath.Clean(path)}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		forms = append(forms, real)
	}
	for _, dir := range s.Exclude {
		if dir == "" {
			continue
		}
		dirs := []string{filepath.Clean(dir)}
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			dirs = append(dirs, real)
		}
		for _, p := range forms {
			for _, d := range dirs {
				if rel, err := filepath.Rel(d, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return true
				}
			}
		}
	}
	return false
}

func isDirEntry(parent string, e fs.DirEntry) bool {
	if e.IsDir() {
		return true
	}
	if e.Type()&fs.ModeSymlink != 0 {
		st, err := os.Stat(filepath.Join(parent, e.Name()))
		return err == nil && st.IsDir()
	}
	return false
}

// sourceForPath names the tool that manages a referenced file when its path
// says so, so a vhost pointing into /etc/letsencrypt reads as certbot.
func sourceForPath(path, fallback string) string {
	switch {
	case strings.Contains(path, "/letsencrypt/"):
		return SourceCertbot
	case strings.Contains(path, "/.acme.sh/") || strings.Contains(path, "/acme.sh/"):
		return SourceAcmeSh
	}
	return fallback
}

// read inspects one pair. With wantBundle it also returns the re-encoded PEM
// bundle; otherwise the key is parsed for the match check and dropped.
func (s Scanner) read(p Pair, wantBundle bool) (models.DiscoveredCert, *Bundle) {
	dc := models.DiscoveredCert{Source: p.Source, CertPath: p.CertPath, KeyPath: p.KeyPath}
	certData, err := readRegular(p.CertPath)
	if err != nil {
		dc.Error = "cannot read certificate: " + describeErr(err)
		return dc, nil
	}
	if p.ChainPath != "" {
		chain, err := readRegular(p.ChainPath)
		if err != nil {
			dc.Error = "cannot read chain file " + p.ChainPath + ": " + describeErr(err)
			return dc, nil
		}
		certData = append(append(certData, '\n'), chain...)
	}
	leaf, certPEM, err := certificates(certData)
	if err != nil {
		dc.Error = err.Error()
		return dc, nil
	}
	sum := sha256.Sum256(leaf.Raw)
	dc.Fingerprint = hex.EncodeToString(sum[:])
	dc.Names = leafNames(leaf)
	dc.Issuer = leaf.Issuer.CommonName
	if dc.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		dc.Issuer = leaf.Issuer.Organization[0]
	}
	dc.NotBefore = leaf.NotBefore.UTC()
	dc.NotAfter = leaf.NotAfter.UTC()

	keyData, err := readRegular(p.KeyPath)
	if err != nil {
		dc.Error = "private key not readable by the agent: " + describeErr(err)
		return dc, nil
	}
	keyPEM, err := privateKey(keyData)
	if err != nil {
		dc.Error = err.Error()
		return dc, nil
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		dc.Error = "private key does not match the certificate"
		return dc, nil
	}
	if !s.now().Before(leaf.NotAfter) {
		dc.Error = "certificate expired"
		return dc, nil
	}
	if !wantBundle {
		return dc, nil
	}
	return dc, &Bundle{Pair: p, CertPEM: certPEM, KeyPEM: keyPEM}
}

// readRegular reads a regular file of at most certmodel.MaxPEMBytes. Devices,
// FIFOs and directories are refused so a stray path cannot block the scan.
func readRegular(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > certmodel.MaxPEMBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, certmodel.MaxPEMBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, certmodel.MaxPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > certmodel.MaxPEMBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, certmodel.MaxPEMBytes)
	}
	return data, nil
}

// certificates returns the leaf and every CERTIFICATE block re-encoded, leaf
// first. Other blocks, including a private key in a combined file, are dropped.
func certificates(data []byte) (*x509.Certificate, []byte, error) {
	var leaf *x509.Certificate
	var out bytes.Buffer
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
		if leaf == nil {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("certificate cannot be parsed: %w", err)
			}
			leaf = c
		}
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	}
	if leaf == nil {
		return nil, nil, errors.New("no PEM certificate in file")
	}
	return leaf, out.Bytes(), nil
}

// privateKey returns the single private key block, re-encoded.
func privateKey(data []byte) ([]byte, error) {
	var found *pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
			return nil, errors.New("private key is encrypted")
		}
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		if found != nil {
			return nil, errors.New("key file holds more than one private key")
		}
		found = block
	}
	if found == nil {
		return nil, errors.New("no PEM private key in key file")
	}
	return pem.EncodeToMemory(&pem.Block{Type: found.Type, Bytes: found.Bytes}), nil
}

func leafNames(leaf *x509.Certificate) []string {
	names := append([]string(nil), leaf.DNSNames...)
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	return names
}

// describeErr shortens filesystem errors to their cause; the path is already
// part of the report.
func describeErr(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, fs.ErrNotExist):
		return "file not found"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
