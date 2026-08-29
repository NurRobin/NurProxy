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
	HelperInstanceID          string `json:"helper_instance_id"`
	ExpectedBuildID           string `json:"expected_build_id"`
	AgentUser                 string `json:"agent_user"`
	AgentUID                  uint32 `json:"agent_uid"`
	OrchestratorKeyID         string `json:"orchestrator_key_id"`
	OrchestratorPublicKeyText string `json:"orchestrator_public_key"`
	AttestationKeyID          string `json:"attestation_key_id"`
	AttestationPrivateKeyFile string `json:"attestation_private_key_file"`
	StoreDir                  string `json:"store_dir"`
}

func (c RootConfig) Validate() error {
	if !validConfigID(c.HelperInstanceID) || !validConfigID(c.ExpectedBuildID) ||
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
	return nil
}

func (c RootConfig) OrchestratorPublicKey() ed25519.PublicKey {
	decoded, _ := base64.RawURLEncoding.Strict().DecodeString(c.OrchestratorPublicKeyText)
	return ed25519.PublicKey(append([]byte(nil), decoded...))
}

func LoadRootConfig(path string) (RootConfig, error) {
	return loadRootConfig(path, 0, user.Lookup)
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
