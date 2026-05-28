package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// SessionManager provides HMAC-based session token signing and verification.
type SessionManager struct {
	key []byte
}

// NewSessionManager creates a SessionManager with the given HMAC key.
func NewSessionManager(key []byte) *SessionManager {
	return &SessionManager{key: key}
}

// Sign produces a signed token in the format "token.signature" where
// the signature is the base64url-encoded HMAC-SHA256 of the token.
func (sm *SessionManager) Sign(token string) string {
	sig := sm.computeMAC(token)
	encoded := base64.RawURLEncoding.EncodeToString(sig)
	return token + "." + encoded
}

// Verify checks the signed token and returns the original token if valid.
// Returns an error if the format is invalid or the signature does not match.
func (sm *SessionManager) Verify(signedToken string) (string, error) {
	idx := strings.LastIndex(signedToken, ".")
	if idx < 0 {
		return "", errors.New("invalid signed token format: missing separator")
	}

	token := signedToken[:idx]
	sigEncoded := signedToken[idx+1:]

	sig, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return "", errors.New("invalid signed token format: bad signature encoding")
	}

	expected := sm.computeMAC(token)
	if !hmac.Equal(sig, expected) {
		return "", errors.New("invalid signature")
	}

	return token, nil
}

func (sm *SessionManager) computeMAC(message string) []byte {
	mac := hmac.New(sha256.New, sm.key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}
