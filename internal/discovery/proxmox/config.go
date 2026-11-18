// Package proxmox discovers QEMU VMs and LXC containers through the Proxmox VE
// API (api2/json) with an API token.
package proxmox

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config is the stored configuration of a Proxmox source.
type Config struct {
	// URL is the API endpoint, e.g. "https://pve.lan:8006". A bare host gets
	// https and port 8006.
	URL string `json:"url"`
	// TokenID is "user@realm!tokenname".
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
	// VerifyTLS checks the certificate chain against the system roots (plus
	// CAPEM). Pinning a Fingerprint replaces the chain check.
	VerifyTLS bool `json:"verify_tls"`
	// CAPEM is an extra trusted CA, e.g. the cluster's pve-root-ca.pem.
	CAPEM string `json:"ca_pem,omitempty"`
	// Fingerprint is the SHA-256 fingerprint of the API certificate, as shown
	// in the PVE UI ("AB:CD:..."). When set, only that certificate is
	// accepted.
	Fingerprint string `json:"fingerprint,omitempty"`
}

func parseConfig(raw json.RawMessage) (*Config, error) {
	var c Config
	if len(raw) == 0 {
		return nil, errors.New("config is empty")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("url is required")
	}
	if _, err := c.baseURL(); err != nil {
		return err
	}
	user, name, ok := strings.Cut(c.TokenID, "!")
	if !ok || !strings.Contains(user, "@") || name == "" {
		return errors.New(`token_id must look like "user@realm!tokenname"`)
	}
	if strings.TrimSpace(c.TokenSecret) == "" {
		return errors.New("token_secret is required")
	}
	// Both end up in one Authorization header value.
	if strings.ContainsAny(c.TokenID, " \t\r\n=") || strings.ContainsAny(c.TokenSecret, " \t\r\n") {
		return errors.New("token_id and token_secret must not contain whitespace")
	}
	if c.Fingerprint != "" {
		if _, err := c.fingerprintBytes(); err != nil {
			return err
		}
	}
	if c.CAPEM != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
			return errors.New("ca_pem holds no PEM certificate")
		}
	}
	return nil
}

// baseURL returns the normalized endpoint without a trailing slash and
// without the /api2/json suffix.
func (c *Config) baseURL() (*url.URL, error) {
	raw := strings.TrimSpace(c.URL)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("url %q is not a valid URL", c.URL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("url scheme must be https, got %q", u.Scheme)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "8006")
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api2/json")
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u, nil
}

func (c *Config) fingerprintBytes() ([]byte, error) {
	clean := strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(c.Fingerprint))
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("fingerprint must be a SHA-256 fingerprint (32 hex bytes, colons optional)")
	}
	return b, nil
}

// httpClient builds the client for c's TLS settings.
func (c *Config) httpClient(timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.Fingerprint != "":
		want, err := c.fingerprintBytes()
		if err != nil {
			return nil, err
		}
		// The pin replaces chain validation: PVE nodes ship a self-signed
		// certificate, and the fingerprint is what the operator can verify.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("proxmox: server sent no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if !equalBytes(got[:], want) {
				return fmt.Errorf("proxmox: certificate fingerprint %s does not match the pinned fingerprint", formatFingerprint(got[:]))
			}
			return nil
		}
	case !c.VerifyTLS:
		tlsCfg.InsecureSkipVerify = true
	case c.CAPEM != "":
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(c.CAPEM))
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: maxParallel,
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{x}))
	}
	return strings.Join(parts, ":")
}
