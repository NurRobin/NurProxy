package selfupdate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Download size caps. The agent archive is around 15 MB today.
const (
	maxChecksumsBytes   = 1 << 20
	maxSignatureBytes   = 16 << 10
	maxCertificateBytes = 64 << 10
	maxArchiveBytes     = 200 << 20
)

// Fetcher downloads release files from <BaseURL>/v<version>/<file>. The base
// defaults to GitHub releases of the pinned repository and may point at a
// mirror: what is fetched is verified against the signature, not the source.
type Fetcher struct {
	BaseURL string
	Client  *http.Client
}

// ValidateBaseURL accepts only absolute https URLs without query or fragment.
func ValidateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("release base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("release base URL must be a plain https:// URL, got %q", raw)
	}
	return nil
}

// Fetch downloads the checksums, its signature and certificate, and the
// archive for asset.
func (f Fetcher) Fetch(ctx context.Context, version, asset string) (Release, error) {
	base := f.BaseURL
	if base == "" {
		base = DefaultReleaseBaseURL
	}
	if err := ValidateBaseURL(base); err != nil {
		return Release{}, err
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	prefix := strings.TrimRight(base, "/") + "/v" + url.PathEscape(version) + "/"
	r := Release{Version: version, Asset: asset}
	files := []struct {
		name string
		max  int64
		dst  *[]byte
	}{
		{ChecksumsFile, maxChecksumsBytes, &r.Checksums},
		{SignatureFile, maxSignatureBytes, &r.Signature},
		{CertificateFile, maxCertificateBytes, &r.Certificate},
		{asset, maxArchiveBytes, &r.Archive},
	}
	for _, file := range files {
		data, err := download(ctx, client, prefix+url.PathEscape(file.name), file.max)
		if err != nil {
			return Release{}, fmt.Errorf("downloading %s: %w", file.name, err)
		}
		*file.dst = data
	}
	return r, nil
}

func download(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL.Scheme != "https" {
		return nil, fmt.Errorf("redirected to a non-https URL")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	return data, nil
}
