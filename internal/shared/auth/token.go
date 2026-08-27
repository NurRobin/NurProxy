package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateAgentToken returns a token prefixed with "np_ag_" followed by 32 random hex bytes.
func GenerateAgentToken() (string, error) {
	return generatePrefixedToken("np_ag_")
}

// GenerateAPIKey returns a token prefixed with "np_ak_" followed by 32 random hex bytes.
func GenerateAPIKey() (string, error) {
	return generatePrefixedToken("np_ak_")
}

// GenerateSessionToken returns 32 random hex bytes (no prefix).
func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func generatePrefixedToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a token for storage comparison.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// MatchesStoredAPIKey reports whether a presented bearer token matches the
// stored admin API key. The stored value is normally the key's SHA-256 hex
// digest (never the plaintext, so a leaked DB cannot mint admin access) —
// compare hash-to-hash; pre-hashing installs stored the plaintext, which is
// accepted too so existing keys keep working (callers may upgrade the row on a
// legacy match). Constant-time in both comparisons. Every endpoint gating on
// the admin API key (REST middleware, MCP, /metrics) must use this ONE helper —
// a plaintext-only comparison silently locks the endpoint out the moment the
// stored key is hashed.
func MatchesStoredAPIKey(stored, token string) (ok, legacy bool) {
	if stored == "" || token == "" {
		return false, false
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(HashToken(token))) == 1 {
		return true, false
	}
	// Legacy plaintext rows only ever held generated "np_ak_…" keys. Gating the
	// plaintext comparison on that prefix closes pass-the-hash: a SHA-256 hex
	// digest (64 hex chars, no prefix) presented as the token can never take
	// this branch, so a leaked stored digest is not a usable credential.
	if strings.HasPrefix(token, "np_ak_") &&
		subtle.ConstantTimeCompare([]byte(stored), []byte(token)) == 1 {
		return true, true
	}
	return false, false
}
