package selfupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestVerifyRealReleaseSignature checks the embedded Fulcio CA and the identity
// pinning against the signature files GoReleaser published for v0.5.1.
func TestVerifyRealReleaseSignature(t *testing.T) {
	trust, err := DefaultTrust()
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/v0.5.1-" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sums, sig, cert := read(ChecksumsFile), read(SignatureFile), read(CertificateFile)
	if err := trust.VerifyChecksums("0.5.1", sums, sig, cert); err != nil {
		t.Fatalf("real v0.5.1 signature rejected: %v", err)
	}
	if err := trust.VerifyChecksums("0.5.0", sums, sig, cert); err == nil || !strings.Contains(err.Error(), "signing identity") {
		t.Fatalf("v0.5.1 signature accepted for v0.5.0: %v", err)
	}
	tampered := bytes.Replace(sums, []byte("linux_amd64.tar.gz"), []byte("linux_amd64.tar.gx"), 1)
	if err := trust.VerifyChecksums("0.5.1", tampered, sig, cert); err == nil {
		t.Fatal("tampered checksums.txt accepted")
	}
	other, err := TrustFromPEM(fulcioPEM, "someone/fork", GitHubActionsIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.VerifyChecksums("0.5.1", sums, sig, cert); err == nil {
		t.Fatal("signature accepted for a different repository")
	}
	parsed, err := ParseChecksums(sums)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "arm"}, {"darwin", "arm64"}, {"freebsd", "amd64"}} {
		asset, err := AssetName("0.5.1", platform[0], platform[1])
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := parsed[asset]; !ok {
			t.Errorf("asset %s missing from the real checksums.txt", asset)
		}
	}
}

func TestVerifyRelease(t *testing.T) {
	pki := newTestPKI(t)
	binary := []byte("#!new-agent-binary")

	t.Run("good", func(t *testing.T) {
		rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
		got, err := pki.trust.Verify(rel)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, binary) {
			t.Fatalf("extracted %q", got)
		}
	})

	cases := []struct {
		name    string
		mutate  func(*Release)
		wantErr string
	}{
		{"tampered archive", func(r *Release) { r.Archive = append(append([]byte{}, r.Archive...), 0) }, "checksum mismatch"},
		{"tampered checksums", func(r *Release) {
			r.Checksums = bytes.Replace(r.Checksums, []byte("nurproxy_"), []byte("nurproxx_"), 1)
		}, "does not verify"},
		{"wrong arch", func(r *Release) { r.Asset = strings.Replace(r.Asset, "amd64", "arm64", 1) }, "no entry"},
		{"wrong version", func(r *Release) { r.Version = "1.2.4" }, "signing identity"},
		{"garbage signature", func(r *Release) { r.Signature = []byte("not base64!") }, "base64"},
		{"empty signature", func(r *Release) { r.Signature = nil }, "base64"},
		{"missing certificate", func(r *Release) { r.Certificate = nil }, "certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
			tc.mutate(&rel)
			_, err := pki.trust.Verify(rel)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	t.Run("signed by another key", func(t *testing.T) {
		rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
		rel.Signature, _ = pki.sign(t, rel.Checksums, leafOpts{identity: pki.trust.ExpectedIdentity("1.2.3"), issuer: GitHubActionsIssuer})
		if _, err := pki.trust.Verify(rel); err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("signature from a different key accepted: %v", err)
		}
	})
	t.Run("untrusted CA", func(t *testing.T) {
		rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
		rel.Signature, rel.Certificate = pki.sign(t, rel.Checksums, leafOpts{identity: pki.trust.ExpectedIdentity("1.2.3"), issuer: GitHubActionsIssuer, selfCA: true})
		if _, err := pki.trust.Verify(rel); err == nil || !strings.Contains(err.Error(), "trusted Sigstore CA") {
			t.Fatalf("certificate from an untrusted CA accepted: %v", err)
		}
	})
	t.Run("other workflow", func(t *testing.T) {
		rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
		identity := strings.Replace(pki.trust.ExpectedIdentity("1.2.3"), "release.yml", "ci.yml", 1)
		rel.Signature, rel.Certificate = pki.sign(t, rel.Checksums, leafOpts{identity: identity, issuer: GitHubActionsIssuer})
		if _, err := pki.trust.Verify(rel); err == nil || !strings.Contains(err.Error(), "signing identity") {
			t.Fatalf("certificate for another workflow accepted: %v", err)
		}
	})
	t.Run("other issuer", func(t *testing.T) {
		rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
		rel.Signature, rel.Certificate = pki.sign(t, rel.Checksums, leafOpts{identity: pki.trust.ExpectedIdentity("1.2.3"), issuer: "https://accounts.google.com"})
		if _, err := pki.trust.Verify(rel); err == nil || !strings.Contains(err.Error(), "OIDC issuer") {
			t.Fatalf("certificate from another issuer accepted: %v", err)
		}
	})
	t.Run("archive without binary", func(t *testing.T) {
		rel := pki.release(t, "1.2.3", "linux", "amd64", binary)
		rel.Archive = tarGz(t, map[string][]byte{"README": []byte("x")})
		resign(t, pki, &rel)
		if _, err := pki.trust.Verify(rel); err == nil || !strings.Contains(err.Error(), "does not contain") {
			t.Fatalf("archive without the agent accepted: %v", err)
		}
	})
}

// resign rewrites the checksum line for the (changed) archive and signs again.
func resign(t *testing.T, pki *testPKI, rel *Release) {
	t.Helper()
	sum := sha256.Sum256(rel.Archive)
	rel.Checksums = []byte(hex.EncodeToString(sum[:]) + "  " + rel.Asset + "\n")
	rel.Signature, rel.Certificate = pki.sign(t, rel.Checksums, leafOpts{identity: pki.trust.ExpectedIdentity(rel.Version), issuer: GitHubActionsIssuer})
}

func TestParseChecksums(t *testing.T) {
	good := strings.Repeat("a", 64)
	if _, err := ParseChecksums([]byte(good + "  x.tar.gz\n" + good + " *y.tar.gz\n\n")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"abc  x.tar.gz",
		good + "  x.tar.gz extra",
		strings.Repeat("z", 64) + "  x.tar.gz",
		good + "  x.tar.gz\n" + good + "  x.tar.gz",
	} {
		if _, err := ParseChecksums([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := map[[2]string]string{
		{"linux", "amd64"}:   "nurproxy-agent_1.0.0_linux_amd64.tar.gz",
		{"linux", "arm"}:     "nurproxy-agent_1.0.0_linux_armv7.tar.gz",
		{"darwin", "arm64"}:  "nurproxy-agent_1.0.0_darwin_arm64.tar.gz",
		{"freebsd", "amd64"}: "nurproxy-agent_1.0.0_freebsd_amd64.tar.gz",
	}
	for in, want := range cases {
		got, err := AssetName("1.0.0", in[0], in[1])
		if err != nil || got != want {
			t.Errorf("%v: got %q, %v", in, got, err)
		}
	}
	for _, in := range [][2]string{{"windows", "amd64"}, {"darwin", "arm"}, {"linux", "386"}} {
		if _, err := AssetName("1.0.0", in[0], in[1]); err == nil {
			t.Errorf("%v accepted", in)
		}
	}
}
