package recoveryauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

func openAuthorityFile(t *testing.T, path string) (*os.File, bool) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return file, true
	}
	if !os.IsExist(err) {
		t.Fatal(err)
	}
	file, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file, false
}

func TestLoadOrGenerateAuthorityPersistsSeedAndIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery-authority.key")
	firstFile, created := openAuthorityFile(t, path)
	first, err := LoadOrGenerate(firstFile, created)
	if err != nil {
		t.Fatal(err)
	}
	_ = firstFile.Close()
	secondFile, created := openAuthorityFile(t, path)
	if created {
		t.Fatal("existing authority key was treated as new")
	}
	second, err := LoadOrGenerate(secondFile, created)
	if err != nil {
		t.Fatal(err)
	}
	_ = secondFile.Close()
	if first.KeyID() != second.KeyID() || first.PublicKeyText() != second.PublicKeyText() {
		t.Fatalf("authority identity changed: %q/%q", first.KeyID(), second.KeyID())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != ed25519.SeedSize || info.Mode().Perm() != 0o600 {
		t.Fatalf("authority key metadata = size %d mode %o", info.Size(), info.Mode().Perm())
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(first.PublicKeyText())
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key text is invalid: len=%d err=%v", len(publicKey), err)
	}
}

func TestLoadOrGenerateAuthorityRejectsMalformedExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery-authority.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, created := openAuthorityFile(t, path)
	defer file.Close()
	if created {
		t.Fatal("malformed existing key was treated as new")
	}
	if _, err := LoadOrGenerate(file, false); err == nil {
		t.Fatal("malformed authority key was accepted")
	}
}

func TestAuthoritySignsBoundExecutionGrant(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := New(private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	grant := helperprotocol.ExecutionGrant{
		GrantID: "grant-1", AgentID: "agent-1", HelperInstanceID: "helper-1",
		DiagnosticID: "diag-1", OperationID: "op-1", Action: helperprotocol.ActionRestartProxy,
		HelperPlanID: "plan-1", DisplayPlanHash: digest("display"), ExecutionPlanHash: digest("execute"),
		ResourceFingerprint: digest("resource"), ConfirmationEventIDs: []string{"confirm-1", "confirm-2"},
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signed, err := authority.SignExecutionGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := helperprotocol.Verify(authority.PublicKey(), signed, helperprotocol.MessageExecutionGrant); err != nil {
		t.Fatal(err)
	}
	signed.Envelope.Payload.OperationID = "op-2"
	if err := helperprotocol.Verify(authority.PublicKey(), signed, helperprotocol.MessageExecutionGrant); err == nil {
		t.Fatal("mutated signed grant verified")
	}
}

func digest(seed string) string {
	const hex = "0123456789abcdef"
	result := make([]byte, 64)
	for i := range result {
		result[i] = hex[(i+len(seed))%len(hex)]
	}
	return string(result)
}
