package db

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// confirmationCodeAlphabet is Crockford base32 with the ambiguous characters
// I, L, O and U removed, leaving a human-typable set that is hard to mistranscribe.
const confirmationCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// confirmationCodeGroups and confirmationCodeGroupLen describe the rendered
// shape: two dash-separated groups of four characters, e.g. "K7QF-2M9X".
const (
	confirmationCodeGroups   = 2
	confirmationCodeGroupLen = 4
)

// GenerateConfirmationCode mints a short, human-typable confirmation code using
// cryptographically secure randomness (§19). The plaintext is shown once and
// never persisted; only its hash (see HashConfirmationCode) is stored. The code
// uses a Crockford base32 alphabet with the ambiguous characters I/L/O/U removed
// and is rendered as two dash-separated groups of four, e.g. "K7QF-2M9X".
func GenerateConfirmationCode() (string, error) {
	total := confirmationCodeGroups * confirmationCodeGroupLen
	// Rejection sampling against a power-of-two-sized alphabet (32) makes each
	// byte's low 5 bits uniform, so no modulo bias and no rejection needed.
	buf := make([]byte, total)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.Grow(total + confirmationCodeGroups - 1)
	for i := 0; i < total; i++ {
		if i > 0 && i%confirmationCodeGroupLen == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(confirmationCodeAlphabet[buf[i]&0x1f])
	}
	return sb.String(), nil
}

// HashConfirmationCode returns the sha256 hex digest of a confirmation code. The
// store only ever persists this hash; claims are matched by hashing the
// presented plaintext and comparing. Normalizing case/whitespace here keeps the
// match tolerant of how a human re-types the code.
func HashConfirmationCode(plain string) string {
	normalized := strings.ToUpper(strings.TrimSpace(plain))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
