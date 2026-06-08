package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// defaultSessionTTL is the fallback session lifetime used when a SessionManager
// is created without an explicit TTL (e.g. in tests). Production wires the
// configured session_expiry_hours value via WithTTL.
const defaultSessionTTL = 7 * 24 * time.Hour

// ErrSessionExpired is returned by Verify when a token's embedded expiry has
// passed. ErrSessionRevoked is returned when the token's session version is
// older than the current server-side version (logout / password change bump it).
var (
	ErrSessionExpired = errors.New("session expired")
	ErrSessionRevoked = errors.New("session revoked")
)

// SessionManager provides HMAC-based session token signing and verification.
//
// A signed token embeds a tamper-proof expiry and a server-side session version
// inside the HMAC-protected payload, so Verify can reject sessions that have
// outlived their lifetime or that were invalidated server-side (logout or
// password change bump the version). This makes the previously client-only
// cookie expiry actually enforced and gives logout real teeth.
type SessionManager struct {
	key []byte
	ttl time.Duration
	// ttlFn, when set, supplies the TTL dynamically at Sign time (so a runtime
	// change to session_expiry_hours takes effect without a restart). Wired once
	// at construction, it is only ever read — never reassigned — so it does not
	// race with concurrent Verify/Sign calls. nil falls back to the static ttl.
	ttlFn func() time.Duration
	// now returns the current time; overridable in tests.
	now func() time.Time
	// version returns the current server-side session version. Tokens carrying a
	// lower version are rejected. nil means "no revocation tracking" (version 0).
	version func() int
}

// NewSessionManager creates a SessionManager with the given HMAC key and the
// default session TTL.
func NewSessionManager(key []byte) *SessionManager {
	return &SessionManager{key: key, ttl: defaultSessionTTL, now: time.Now}
}

// WithTTL sets the lifetime embedded into freshly signed tokens. A non-positive
// TTL falls back to the default. Returns the receiver for chaining.
func (sm *SessionManager) WithTTL(ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	sm.ttl = ttl
	return sm
}

// WithTTLFunc wires a provider that supplies the session lifetime dynamically at
// Sign time. Set it once at construction; it is read without locking on every
// Sign, so the configured session_expiry_hours is honored live without the
// shared-state writes a per-request WithTTL would incur. Returns the receiver.
func (sm *SessionManager) WithTTLFunc(fn func() time.Duration) *SessionManager {
	sm.ttlFn = fn
	return sm
}

// WithVersion wires a provider for the current server-side session version.
// Verify rejects any token whose embedded version is lower than the value this
// returns, so bumping it (on logout or password change) invalidates every
// outstanding cookie. Returns the receiver for chaining.
func (sm *SessionManager) WithVersion(fn func() int) *SessionManager {
	sm.version = fn
	return sm
}

// currentVersion returns the live server-side session version (0 if untracked).
func (sm *SessionManager) currentVersion() int {
	if sm.version == nil {
		return 0
	}
	return sm.version()
}

// Sign produces a signed token in the format "token.meta.signature" where meta
// encodes the session version and expiry (version:expiryUnix, base64url) and the
// signature is the base64url-encoded HMAC-SHA256 of "token.meta". The original
// token is recoverable from Verify, so existing callers keep their semantics.
func (sm *SessionManager) Sign(token string) string {
	ttl := sm.ttl
	if sm.ttlFn != nil {
		if d := sm.ttlFn(); d > 0 {
			ttl = d
		}
	}
	exp := sm.now().Add(ttl).Unix()
	meta := strconv.Itoa(sm.currentVersion()) + ":" + strconv.FormatInt(exp, 10)
	metaEnc := base64.RawURLEncoding.EncodeToString([]byte(meta))
	payload := token + "." + metaEnc
	sig := base64.RawURLEncoding.EncodeToString(sm.computeMAC(payload))
	return payload + "." + sig
}

// Verify checks the signed token and returns the original token if valid. It
// rejects tokens with a bad format or signature, tokens past their embedded
// expiry (ErrSessionExpired), and tokens whose version is older than the current
// server-side version (ErrSessionRevoked). The HMAC comparison is constant-time.
func (sm *SessionManager) Verify(signedToken string) (string, error) {
	sigIdx := strings.LastIndex(signedToken, ".")
	if sigIdx < 0 {
		return "", errors.New("invalid signed token format: missing separator")
	}
	payload := signedToken[:sigIdx]
	sigEncoded := signedToken[sigIdx+1:]

	sig, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return "", errors.New("invalid signed token format: bad signature encoding")
	}

	expected := sm.computeMAC(payload)
	if !hmac.Equal(sig, expected) {
		return "", errors.New("invalid signature")
	}

	metaIdx := strings.LastIndex(payload, ".")
	if metaIdx < 0 {
		return "", errors.New("invalid signed token format: missing metadata")
	}
	token := payload[:metaIdx]
	metaEnc := payload[metaIdx+1:]

	metaBytes, err := base64.RawURLEncoding.DecodeString(metaEnc)
	if err != nil {
		return "", errors.New("invalid signed token format: bad metadata encoding")
	}
	ver, exp, err := parseMeta(string(metaBytes))
	if err != nil {
		return "", err
	}

	if ver < sm.currentVersion() {
		return "", ErrSessionRevoked
	}
	if sm.now().Unix() >= exp {
		return "", ErrSessionExpired
	}

	return token, nil
}

// parseMeta splits the "version:expiryUnix" payload metadata.
func parseMeta(meta string) (version int, expiry int64, err error) {
	sep := strings.IndexByte(meta, ':')
	if sep < 0 {
		return 0, 0, errors.New("invalid signed token format: malformed metadata")
	}
	version, err = strconv.Atoi(meta[:sep])
	if err != nil {
		return 0, 0, errors.New("invalid signed token format: malformed version")
	}
	expiry, err = strconv.ParseInt(meta[sep+1:], 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid signed token format: malformed expiry")
	}
	return version, expiry, nil
}

func (sm *SessionManager) computeMAC(message string) []byte {
	mac := hmac.New(sha256.New, sm.key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}
