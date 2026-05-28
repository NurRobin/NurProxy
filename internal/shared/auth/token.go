package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
