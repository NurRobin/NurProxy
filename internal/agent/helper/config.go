package helper

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

const MaxRootConfigBytes = 64 << 10

type RootConfig struct {
	AgentID                   string                    `json:"agent_id"`
	HelperInstanceID          string                    `json:"helper_instance_id"`
	ExpectedBuildID           string                    `json:"expected_build_id"`
	AgentUser                 string                    `json:"agent_user"`
	AgentUID                  uint32                    `json:"agent_uid"`
	OrchestratorKeyID         string                    `json:"orchestrator_key_id"`
	OrchestratorPublicKeyText string                    `json:"orchestrator_public_key"`
	AttestationKeyID          string                    `json:"attestation_key_id"`
	AttestationPrivateKeyFile string                    `json:"attestation_private_key_file"`
	StoreDir                  string                    `json:"store_dir"`
	ProxyTarget               ProxyTargetConfig         `json:"proxy_target"`
	PackageTarget             PackageTargetConfig       `json:"package_target"`
	FirewallTarget            *FirewallTargetConfig     `json:"firewall_target"`
	ManagedApply              *ManagedApplyTargetConfig `json:"managed_apply"`
}

type FirewallTargetConfig struct {
	Backend string `json:"backend"`
	Binary  string `json:"binary"`
}

func (c FirewallTargetConfig) Validate() error {
	if c.Backend != "ufw" || c.Binary != "/usr/sbin/ufw" || !trustedExecutableLocation(c.Binary) {
		return fmt.Errorf("firewall backend is not a compiled provenanced mapping")
	}
	return nil
}

type ManagedApplyTargetConfig struct {
	StagingDir          string `json:"staging_dir"`
	AvailableDir        string `json:"available_dir"`
	EnabledDir          string `json:"enabled_dir"`
	CertificateDir      string `json:"certificate_dir"`
	CustomPolicyVersion string `json:"custom_policy_version"`
	ProxyVersion        string `json:"proxy_version"`
}

type PackageTargetConfig struct {
	Manager string `json:"manager"`
	Package string `json:"package"`
}

type ProxyTargetConfig struct {
	Kind            string   `json:"kind"`
	Binary          string   `json:"binary"`
	Unit            string   `json:"unit"`
	SystemctlBinary string   `json:"systemctl_binary"`
	ConfigRoots     []string `json:"config_roots"`
}

func (c RootConfig) Validate() error {
	if !validConfigID(c.AgentID) || !validConfigID(c.HelperInstanceID) || !validConfigID(c.ExpectedBuildID) ||
		!validConfigID(c.AgentUser) || c.AgentUID == 0 ||
		!validConfigID(c.OrchestratorKeyID) || !validConfigID(c.AttestationKeyID) {
		return fmt.Errorf("invalid root configuration identity")
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(c.OrchestratorPublicKeyText)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid orchestrator verification key")
	}
	if err := validatePrivatePath(c.AttestationPrivateKeyFile); err != nil {
		return fmt.Errorf("invalid attestation key path: %w", err)
	}
	if err := validatePrivatePath(c.StoreDir); err != nil {
		return fmt.Errorf("invalid helper store path: %w", err)
	}
	if err := c.ProxyTarget.Validate(); err != nil {
		return fmt.Errorf("invalid proxy target: %w", err)
	}
	if err := c.PackageTarget.Validate(c.ProxyTarget.Kind); err != nil {
		return fmt.Errorf("invalid package target: %w", err)
	}
	if c.FirewallTarget != nil {
		if err := c.FirewallTarget.Validate(); err != nil {
			return fmt.Errorf("invalid firewall target: %w", err)
		}
	}
	if c.ManagedApply != nil {
		if err := c.ManagedApply.Validate(c.ProxyTarget.Kind); err != nil {
			return fmt.Errorf("invalid managed apply target: %w", err)
		}
	}
	return nil
}

func (c ManagedApplyTargetConfig) Validate(proxyKind string) error {
	if !validConfigID(c.CustomPolicyVersion) || validatePrivatePath(c.StagingDir) != nil || validatePrivatePath(c.CertificateDir) != nil ||
		c.StagingDir != "/var/lib/nurproxy-agent/helper-staging" || c.CertificateDir != "/var/lib/nurproxy-agent/certs" {
		return fmt.Errorf("managed staging, certificate, or policy mapping is invalid")
	}
	switch proxyKind {
	case "nginx":
		if !validConfigID(c.ProxyVersion) {
			return fmt.Errorf("nginx version mapping is invalid")
		}
		validPair := (c.AvailableDir == "/etc/nginx/sites-available" && c.EnabledDir == "/etc/nginx/sites-enabled") ||
			(c.AvailableDir == "/etc/nginx/conf.d" && c.EnabledDir == "")
		if !validPair {
			return fmt.Errorf("nginx managed directories are not a compiled layout")
		}
	case "apache":
		validPair := (c.AvailableDir == "/etc/apache2/sites-available" && c.EnabledDir == "/etc/apache2/sites-enabled") ||
			(c.AvailableDir == "/etc/httpd/conf.d" && c.EnabledDir == "")
		if !validPair || (c.ProxyVersion != "" && !validConfigID(c.ProxyVersion)) {
			return fmt.Errorf("apache managed directories are not a compiled layout")
		}
	default:
		return fmt.Errorf("ordinary privileged apply is unsupported for this proxy kind")
	}
	return nil
}

func (c PackageTargetConfig) Validate(proxyKind string) error {
	if !trustedExecutableLocation(c.Manager) {
		return fmt.Errorf("package manager path is not allowed")
	}
	allowed := map[string]map[string]string{
		"/usr/bin/apt-get": {"nginx": "nginx", "apache": "apache2", "caddy": "caddy"},
	}
	packages, ok := allowed[c.Manager]
	if !ok || packages[proxyKind] != c.Package {
		return fmt.Errorf("package manager, backend, and package are not a compiled mapping")
	}
	return nil
}

func (c ProxyTargetConfig) Validate() error {
	allowed := map[string]struct {
		binaries map[string]bool
		units    map[string]bool
		roots    []string
	}{
		"nginx": {
			binaries: map[string]bool{"nginx": true},
			units:    map[string]bool{"nginx.service": true},
			roots:    []string{"/etc/nginx"},
		},
		"apache": {
			binaries: map[string]bool{"apachectl": true, "apache2ctl": true, "httpd": true, "apache2": true},
			units:    map[string]bool{"apache2.service": true, "httpd.service": true},
			roots:    []string{"/etc/apache2", "/etc/httpd"},
		},
		"caddy": {
			binaries: map[string]bool{"caddy": true},
			units:    map[string]bool{"caddy.service": true},
			roots:    []string{"/etc/caddy"},
		},
	}
	mapping, ok := allowed[c.Kind]
	if !ok || !mapping.binaries[filepath.Base(c.Binary)] || !mapping.units[c.Unit] {
		return fmt.Errorf("proxy kind, binary, or unit is not a compiled mapping")
	}
	if !trustedExecutableLocation(c.Binary) || (c.SystemctlBinary != "/usr/bin/systemctl" && c.SystemctlBinary != "/bin/systemctl") {
		return fmt.Errorf("proxy or systemctl binary path is not allowed")
	}
	if len(c.ConfigRoots) == 0 || len(c.ConfigRoots) > 8 {
		return fmt.Errorf("proxy config roots are not bounded")
	}
	seen := make(map[string]struct{}, len(c.ConfigRoots))
	for _, root := range c.ConfigRoots {
		if err := validatePrivatePath(root); err != nil || !pathWithinAny(root, mapping.roots) {
			return fmt.Errorf("proxy config root is outside the compiled backend layout")
		}
		if _, exists := seen[root]; exists {
			return fmt.Errorf("duplicate proxy config root")
		}
		seen[root] = struct{}{}
	}
	return nil
}

func trustedExecutableLocation(path string) bool {
	if err := validatePrivatePath(path); err != nil {
		return false
	}
	switch filepath.Dir(path) {
	case "/usr/bin", "/usr/sbin", "/bin", "/sbin":
		return true
	default:
		return false
	}
}

func pathWithinAny(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (c RootConfig) OrchestratorPublicKey() ed25519.PublicKey {
	decoded, _ := base64.RawURLEncoding.Strict().DecodeString(c.OrchestratorPublicKeyText)
	return ed25519.PublicKey(append([]byte(nil), decoded...))
}

func LoadRootConfig(path string) (RootConfig, error) {
	return loadRootConfig(path, 0, user.Lookup)
}

func WriteRootConfig(path string, config RootConfig) error {
	return writeRootConfig(path, config, 0)
}

func writeRootConfig(path string, config RootConfig, expectedOwnerUID uint32) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := validatePrivatePath(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := validateTrustedDirectory(parent, expectedOwnerUID); err != nil {
		return fmt.Errorf("root configuration parent is not trusted: %w", err)
	}
	payload, err := helperprotocol.CanonicalBytes(config)
	if err != nil || len(payload) > MaxRootConfigBytes {
		return fmt.Errorf("encode bounded root configuration")
	}
	temporary, err := os.CreateTemp(parent, ".root-helper-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func RefreshRootConfigBuildID(path, buildID string) (bool, error) {
	return refreshRootConfigBuildID(path, buildID, 0, user.Lookup)
}

func refreshRootConfigBuildID(path, buildID string, expectedOwnerUID uint32, lookup func(string) (*user.User, error)) (bool, error) {
	if !validConfigID(buildID) {
		return false, fmt.Errorf("invalid helper build identity")
	}
	config, err := loadRootConfig(path, expectedOwnerUID, lookup)
	if err != nil {
		if os.IsNotExist(rootCause(err)) {
			return false, nil
		}
		return false, err
	}
	if config.ExpectedBuildID == buildID {
		return false, nil
	}
	config.ExpectedBuildID = buildID
	if err := writeRootConfig(path, config, expectedOwnerUID); err != nil {
		return false, err
	}
	return true, nil
}

func loadRootConfig(path string, expectedOwnerUID uint32, lookup func(string) (*user.User, error)) (RootConfig, error) {
	var zero RootConfig
	payload, err := readTrustedFile(path, expectedOwnerUID, MaxRootConfigBytes, false)
	if err != nil {
		return zero, fmt.Errorf("root configuration is not trusted: %w", err)
	}
	cfg, err := helperprotocol.Decode[RootConfig](payload)
	if err != nil {
		return zero, fmt.Errorf("decode root configuration: %w", err)
	}
	account, err := lookup(cfg.AgentUser)
	if err != nil {
		return zero, fmt.Errorf("resolve configured agent user: %w", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uint32(uid) != cfg.AgentUID {
		return zero, fmt.Errorf("configured agent user and uid do not match")
	}
	return cfg, nil
}

func LoadOrCreateAttestationKey(path string) (ed25519.PrivateKey, error) {
	return loadOrCreateAttestationKey(path, 0)
}

func loadOrCreateAttestationKey(path string, expectedOwnerUID uint32) (ed25519.PrivateKey, error) {
	if payload, err := readTrustedFile(path, expectedOwnerUID, ed25519.PrivateKeySize, true); err == nil {
		if len(payload) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("attestation private key has invalid size")
		}
		return ed25519.PrivateKey(append([]byte(nil), payload...)), nil
	} else if !os.IsNotExist(rootCause(err)) {
		return nil, err
	}
	if err := validatePrivatePath(path); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if err := validateTrustedDirectory(parent, expectedOwnerUID); err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate attestation key: %w", err)
	}
	tmp, err := os.CreateTemp(parent, ".attestation-key-*")
	if err != nil {
		return nil, fmt.Errorf("create attestation key temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	linked := false
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return nil, err
	}
	if _, err := tmp.Write(privateKey); err != nil {
		return nil, fmt.Errorf("write attestation key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("sync attestation key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close attestation key: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("install attestation key: %w", err)
		}
	} else {
		linked = true
	}
	if linked {
		if err := syncDirectory(parent); err != nil {
			return nil, err
		}
	}
	payload, err := readTrustedFile(path, expectedOwnerUID, ed25519.PrivateKeySize, true)
	if err != nil {
		return nil, err
	}
	if len(payload) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attestation private key has invalid size")
	}
	return ed25519.PrivateKey(append([]byte(nil), payload...)), nil
}

func validConfigID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func validatePrivatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("path must be canonical, absolute, and non-root")
	}
	for _, blocked := range []string{"/proc", "/sys", "/dev", "/run/user"} {
		if path == blocked || strings.HasPrefix(path, blocked+"/") {
			return fmt.Errorf("path is under a prohibited virtual filesystem")
		}
	}
	return nil
}

func rootCause(err error) error {
	for {
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok || unwrapped.Unwrap() == nil {
			return err
		}
		err = unwrapped.Unwrap()
	}
}
