package helper

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLoadRootConfigAcceptsOnlyTrustedStrictFile(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid64, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	ownerUID := uint32(uid64)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "helper.conf")
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	body := fmt.Sprintf(`{"agent_id":"agent-1","helper_instance_id":"helper-1","expected_build_id":"dev-010e5a7","agent_user":%q,"agent_uid":%d,"orchestrator_key_id":"orchestrator-1","orchestrator_public_key":%q,"attestation_key_id":"attestation-1","attestation_private_key_file":%q,"store_dir":%q}`,
		current.Username, ownerUID, publicKey, filepath.Join(dir, "attestation.key"), filepath.Join(dir, "store"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadRootConfig(path, ownerUID, user.Lookup)
	if err != nil {
		t.Fatalf("valid root config rejected: %v", err)
	}
	if cfg.HelperInstanceID != "helper-1" || len(cfg.OrchestratorPublicKey()) != 32 {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	for name, mutate := range map[string]func(t *testing.T, file string){
		"group writable file": func(t *testing.T, file string) {
			if err := os.Chmod(file, 0o620); err != nil {
				t.Fatal(err)
			}
		},
		"wrong owner": func(t *testing.T, _ string) { ownerUID++ },
		"writable parent": func(t *testing.T, _ string) {
			if err := os.Chmod(dir, 0o720); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			originalOwner := ownerUID
			originalDirMode := os.FileMode(0o700)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, originalDirMode); err != nil {
				t.Fatal(err)
			}
			mutate(t, path)
			if _, err := loadRootConfig(path, ownerUID, user.Lookup); err == nil {
				t.Fatal("untrusted root config accepted")
			}
			ownerUID = originalOwner
		})
	}
}

func TestLoadRootConfigRejectsSymlinkUnknownAndAmbiguousJSON(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid64, _ := strconv.ParseUint(current.Uid, 10, 32)
	ownerUID := uint32(uid64)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	valid := fmt.Sprintf(`{"agent_id":"agent-1","helper_instance_id":"helper-1","expected_build_id":"dev-1","agent_user":%q,"agent_uid":%d,"orchestrator_key_id":"key-1","orchestrator_public_key":%q,"attestation_key_id":"attest-1","attestation_private_key_file":%q,"store_dir":%q}`,
		current.Username, ownerUID, key, filepath.Join(dir, "attest.key"), filepath.Join(dir, "store"))
	for name, body := range map[string]string{
		"unknown":   strings.Replace(valid, `"store_dir":`, `"path":"/etc/passwd","store_dir":`, 1),
		"duplicate": strings.Replace(valid, `"helper_instance_id":"helper-1"`, `"helper_instance_id":"helper-1","helper_instance_id":"helper-2"`, 1),
		"raw path":  strings.Replace(valid, filepath.Join(dir, "store"), "/", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".conf")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRootConfig(path, ownerUID, user.Lookup); err == nil {
				t.Fatal("invalid root config accepted")
			}
		})
	}

	realPath := filepath.Join(dir, "real.conf")
	if err := os.WriteFile(realPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(dir, "linked.conf")
	if err := os.Symlink(realPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRootConfig(symlinkPath, ownerUID, user.Lookup); err == nil {
		t.Fatal("symlinked root config accepted")
	}
}

func TestLoadOrCreateAttestationKeyPersistsSecureEd25519Key(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "attestation.key")
	first, err := loadOrCreateAttestationKey(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateAttestationKey(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("attestation key changed across reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
	if len(first) != ed25519.PrivateKeySize || len(first.Public().(ed25519.PublicKey)) != ed25519.PublicKeySize {
		t.Fatal("unexpected Ed25519 key sizes")
	}
}
