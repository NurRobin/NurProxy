// Package selfupdate replaces the agent binary with a newer signed NurProxy
// release on operator request from the orchestrator.
//
// Trust model: a release is accepted only if
//
//  1. checksums.txt carries a cosign keyless signature whose Fulcio certificate
//     chains to the Sigstore Fulcio CA embedded in this binary,
//  2. that certificate was issued to the release workflow of the pinned
//     repository for exactly the requested tag (the SAN URI
//     https://github.com/<repo>/.github/workflows/release.yml@refs/tags/v<version>)
//     by the GitHub Actions OIDC issuer, and
//  3. the downloaded archive's SHA-256 matches its line in that checksums.txt.
//
// The download location is therefore not trusted: a mirror can serve the files.
// The Rekor transparency log is not consulted (that needs network access and a
// much larger dependency), so the certificate chain is checked at the
// certificate's own issuance time instead of "now". The residual risk is a
// Fulcio certificate obtained for this workflow and tag by someone else than
// the release job, which requires control of the repository's workflow.
package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// fulcioPEM is the Sigstore public-good Fulcio root and intermediate
// (O=sigstore.dev, CN=sigstore / sigstore-intermediate), valid until 2031.
//
//go:embed fulcio_v1.pem
var fulcioPEM []byte

const (
	// DefaultRepository is the GitHub repository whose release workflow signs
	// NurProxy releases.
	DefaultRepository = "NurRobin/NurProxy"
	// DefaultReleaseBaseURL serves release assets as <base>/v<version>/<file>.
	DefaultReleaseBaseURL = "https://github.com/" + DefaultRepository + "/releases/download"
	// GitHubActionsIssuer is the OIDC issuer Fulcio records for workflow tokens.
	GitHubActionsIssuer = "https://token.actions.githubusercontent.com"
	releaseWorkflow     = ".github/workflows/release.yml"

	// BinaryName is the executable inside a release archive.
	BinaryName = "nurproxy-agent"
	// ChecksumsFile and its signature files are release assets.
	ChecksumsFile   = "checksums.txt"
	SignatureFile   = "checksums.txt.sig"
	CertificateFile = "checksums.txt.pem"

	maxBinaryBytes = 256 << 20
)

var (
	// Fulcio certificate extensions carrying the OIDC issuer: the original raw
	// string form and the DER UTF8String form that replaced it.
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// Trust pins what a release signature must chain to and who must have signed.
type Trust struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// Repository is "owner/name" of the repository whose release workflow
	// signs releases.
	Repository string
	// Issuer is the OIDC issuer recorded in the signing certificate.
	Issuer string
}

// DefaultTrust trusts the embedded Fulcio CA for the NurProxy release workflow.
func DefaultTrust() (Trust, error) {
	return TrustFromPEM(fulcioPEM, DefaultRepository, GitHubActionsIssuer)
}

// TrustFromPEM builds a Trust from concatenated PEM certificates: self-signed
// ones become roots, the rest intermediates.
func TrustFromPEM(bundle []byte, repository, issuer string) (Trust, error) {
	t := Trust{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool(), Repository: repository, Issuer: issuer}
	roots := 0
	for rest := bundle; ; {
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
			return Trust{}, fmt.Errorf("parsing trust certificate: %w", err)
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil {
			t.Roots.AddCert(cert)
			roots++
		} else {
			t.Intermediates.AddCert(cert)
		}
	}
	if roots == 0 {
		return Trust{}, fmt.Errorf("trust bundle contains no root certificate")
	}
	if repository == "" || issuer == "" {
		return Trust{}, fmt.Errorf("trust needs a repository and an issuer")
	}
	return t, nil
}

// ExpectedIdentity is the certificate SAN the release workflow run for version
// gets from Fulcio.
func (t Trust) ExpectedIdentity(version string) string {
	return "https://github.com/" + t.Repository + "/" + releaseWorkflow + "@refs/tags/v" + version
}

// VerifyChecksums checks the cosign keyless signature over checksums.txt for
// the given release version. signature is the base64 ECDSA signature cosign
// writes; certificate is the Fulcio certificate as PEM, optionally base64
// wrapped (cosign's --output-certificate writes it wrapped).
func (t Trust) VerifyChecksums(version string, checksums, signature, certificate []byte) error {
	if !models.ValidReleaseVersion(version) {
		return fmt.Errorf("invalid release version %q", version)
	}
	leaf, err := decodeCertificate(certificate)
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         t.Roots,
		Intermediates: t.Intermediates,
		// Fulcio certificates live for ten minutes. Without a transparency-log
		// timestamp the only defensible reference time is the issuance time.
		CurrentTime: leaf.NotBefore,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return fmt.Errorf("signing certificate is not issued by the trusted Sigstore CA: %w", err)
	}
	want := t.ExpectedIdentity(version)
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != want {
		got := make([]string, 0, len(leaf.URIs))
		for _, u := range leaf.URIs {
			got = append(got, u.String())
		}
		return fmt.Errorf("signing identity %q does not match the release workflow for v%s (%s)", strings.Join(got, ","), version, want)
	}
	if err := t.checkIssuer(leaf); err != nil {
		return err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("signing certificate has an unsupported key type %T", leaf.PublicKey)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("signature is not valid base64")
	}
	digest := sha256.Sum256(checksums)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature over %s does not verify", ChecksumsFile)
	}
	return nil
}

func (t Trust) checkIssuer(leaf *x509.Certificate) error {
	found := false
	for _, ext := range leaf.Extensions {
		var issuer string
		switch {
		case ext.Id.Equal(oidIssuerV2):
			if rest, err := asn1.UnmarshalWithParams(ext.Value, &issuer, "utf8"); err != nil || len(rest) != 0 {
				return fmt.Errorf("signing certificate has a malformed issuer extension")
			}
		case ext.Id.Equal(oidIssuerV1):
			issuer = string(ext.Value)
		default:
			continue
		}
		if issuer != t.Issuer {
			return fmt.Errorf("signing certificate was issued for OIDC issuer %q, want %q", issuer, t.Issuer)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("signing certificate names no OIDC issuer")
	}
	return nil
}

func decodeCertificate(raw []byte) (*x509.Certificate, error) {
	data := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(data, []byte("-----BEGIN")) {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("signing certificate is neither PEM nor base64-wrapped PEM")
		}
		data = decoded
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("signing certificate is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing signing certificate: %w", err)
	}
	return cert, nil
}

// ParseChecksums reads a GoReleaser checksums.txt ("<sha256>  <name>" lines).
func ParseChecksums(data []byte) (map[string]string, error) {
	sums := make(map[string]string)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s line %d is malformed", ChecksumsFile, i+1)
		}
		sum, name := strings.ToLower(fields[0]), strings.TrimPrefix(fields[1], "*")
		if len(sum) != sha256.Size*2 {
			return nil, fmt.Errorf("%s line %d is not a SHA-256 checksum", ChecksumsFile, i+1)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("%s line %d is not a SHA-256 checksum", ChecksumsFile, i+1)
		}
		if _, dup := sums[name]; dup {
			return nil, fmt.Errorf("%s lists %s twice", ChecksumsFile, name)
		}
		sums[name] = sum
	}
	return sums, nil
}

// AssetName is the release archive for the agent on goos/goarch, following the
// archive name_template in .goreleaser.yml. 32-bit ARM is published as armv7
// only.
func AssetName(version, goos, goarch string) (string, error) {
	switch goos {
	case "linux", "darwin", "freebsd":
	default:
		return "", fmt.Errorf("no agent release is published for %s", goos)
	}
	arch := goarch
	switch goarch {
	case "amd64", "arm64":
	case "arm":
		if goos != "linux" {
			return "", fmt.Errorf("no agent release is published for %s/%s", goos, goarch)
		}
		arch = "armv7"
	default:
		return "", fmt.Errorf("no agent release is published for %s/%s", goos, goarch)
	}
	return fmt.Sprintf("%s_%s_%s_%s.tar.gz", BinaryName, version, goos, arch), nil
}

// Release is the set of downloaded files for one version and platform.
type Release struct {
	Version     string
	Asset       string
	Checksums   []byte
	Signature   []byte
	Certificate []byte
	Archive     []byte
}

// Verify runs the full trust check and returns the agent binary from the
// archive. Nothing is written anywhere.
func (t Trust) Verify(r Release) ([]byte, error) {
	if err := t.VerifyChecksums(r.Version, r.Checksums, r.Signature, r.Certificate); err != nil {
		return nil, err
	}
	sums, err := ParseChecksums(r.Checksums)
	if err != nil {
		return nil, err
	}
	want, ok := sums[r.Asset]
	if !ok {
		return nil, fmt.Errorf("%s has no entry for %s (no release for this platform?)", ChecksumsFile, r.Asset)
	}
	got := sha256.Sum256(r.Archive)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("checksum mismatch for %s: the download is corrupt or was tampered with", r.Asset)
	}
	return ExtractBinary(r.Archive)
}

// ExtractBinary returns the agent executable from a release tar.gz. Only a
// regular file named nurproxy-agent at the archive root is accepted.
func ExtractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("release archive is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("release archive does not contain %s", BinaryName)
		}
		if err != nil {
			return nil, fmt.Errorf("reading release archive: %w", err)
		}
		if strings.TrimPrefix(hdr.Name, "./") != BinaryName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s in the release archive is not a regular file", BinaryName)
		}
		if hdr.Size <= 0 || hdr.Size > maxBinaryBytes {
			return nil, fmt.Errorf("%s in the release archive has an implausible size %d", BinaryName, hdr.Size)
		}
		bin := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, bin); err != nil {
			return nil, fmt.Errorf("reading %s from the release archive: %w", BinaryName, err)
		}
		return bin, nil
	}
}
